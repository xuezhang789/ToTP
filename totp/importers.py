"""批量导入相关的解析辅助函数。"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from typing import List

from .utils import normalize_google_secret, parse_otpauth


@dataclass(slots=True)
class ParsedEntry:
    """标准化后的条目数据，方便写入数据库。"""

    name: str
    secret: str
    group: str
    source: str


@dataclass(slots=True)
class ParseResult:
    """解析操作的产出，包括条目、警告与错误。"""

    entries: List[ParsedEntry]
    warnings: List[str]
    errors: List[str]


MAX_NAME_LEN = 64
MAX_GROUP_LEN = 40


def parse_manual_text(text: str) -> ParseResult:
    entries: list[ParsedEntry] = []
    warnings: list[str] = []
    errors: list[str] = []

    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    seen_names: set[str] = set()
    for idx, raw in enumerate(lines, 1):
        name = ""
        secret = ""
        group = ""
        if raw.lower().startswith("otpauth://"):
            # 支持直接粘贴 otpauth URI，将标签用作名称
            label, parsed_secret = parse_otpauth(raw)
            name = (label or "").strip()
            secret = parsed_secret or ""
        else:
            parts = raw.split("|")
            if len(parts) < 2:
                warnings.append(f"第 {idx} 行格式无效，已忽略该行")
                continue
            secret = parts[0].strip()
            name = parts[1].strip()
            if len(parts) >= 3:
                group = parts[2].strip()

        _append_entry(entries, warnings, errors, name, secret, group, "手动粘贴", seen_names, idx)

    return ParseResult(entries=entries, warnings=warnings, errors=errors)


def parse_import_payload(*, manual_text: str | None = None, uploaded_file=None) -> ParseResult:
    """根据输入类型自动选择解析流程。"""

    if manual_text:
        return parse_manual_text(manual_text)

    if not uploaded_file:
        return ParseResult(entries=[], warnings=[], errors=["未提供可解析的内容"])

    raw_bytes = uploaded_file.read()
    if not raw_bytes:
        return ParseResult(entries=[], warnings=[], errors=["上传文件为空"])

    # 默认尝试 UTF-8 并移除 BOM
    text = raw_bytes.decode("utf-8-sig", errors="ignore")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return parse_authy_json(text)

    return parse_csv_data(text)


def parse_csv_data(data: str) -> ParseResult:
    try:
        reader = csv.DictReader(io.StringIO(data))
    except csv.Error as exc:
        return ParseResult(entries=[], warnings=[], errors=[f"无法解析 CSV：{exc}"])

    if not reader.fieldnames:
        return ParseResult(entries=[], warnings=[], errors=["CSV 文件缺少表头"])

    header = [h.lower().strip() for h in reader.fieldnames]
    if any("otpauth" in h for h in header):
        return parse_1password_csv(reader)
    if "login_totp" in header:
        return parse_bitwarden_csv(reader)

    return ParseResult(entries=[], warnings=[], errors=["无法识别的 CSV 格式，仅支持 1Password 与 Bitwarden 导出"])


def parse_1password_csv(reader: csv.DictReader) -> ParseResult:
    entries: list[ParsedEntry] = []
    warnings: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    for idx, row in enumerate(reader, 2):  # 计数包含表头
        otpuri = row.get("OTPAuth") or row.get("otpAuth") or row.get("otp auth") or row.get("otpauth")
        if not otpuri:
            otpuri = row.get("one-time password") or row.get("one-time password url")
        if not otpuri:
            continue
        label, secret = parse_otpauth(otpuri)
        name = (label or row.get("title") or row.get("Title") or "").strip()
        group = (row.get("category") or row.get("vault") or "").strip()
        if not name:
            name = row.get("Account") or row.get("account") or ""

        _append_entry(entries, warnings, errors, name, secret or "", group, "1Password CSV", seen, idx)

    if not entries and not errors:
        warnings.append("在 1Password CSV 中未发现可用的 TOTP 数据")

    return ParseResult(entries=entries, warnings=warnings, errors=errors)


def parse_bitwarden_csv(reader: csv.DictReader) -> ParseResult:
    entries: list[ParsedEntry] = []
    warnings: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    for idx, row in enumerate(reader, 2):
        secret = row.get("login_totp") or row.get("login_TOTP")
        if not secret:
            continue
        name = (row.get("name") or "").strip()
        group = (row.get("folder") or "").strip()
        _append_entry(entries, warnings, errors, name, secret, group, "Bitwarden CSV", seen, idx)

    if not entries and not errors:
        warnings.append("在 Bitwarden CSV 中未发现可用的 TOTP 数据")

    return ParseResult(entries=entries, warnings=warnings, errors=errors)


def parse_authy_json(data: str) -> ParseResult:
    entries: list[ParsedEntry] = []
    warnings: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        return ParseResult(entries=[], warnings=[], errors=[f"JSON 解析失败：{exc}"])

    if isinstance(payload, dict):
        candidates = payload.get("tokens") or payload.get("accounts") or []
    elif isinstance(payload, list):
        candidates = payload
    else:
        return ParseResult(entries=[], warnings=[], errors=["无法识别的 Authy JSON 结构"])

    if not isinstance(candidates, list):
        return ParseResult(entries=[], warnings=[], errors=["Authy JSON 结构无效"])

    for idx, item in enumerate(candidates, 1):
        if not isinstance(item, dict):
            continue
        secret = item.get("secret") or item.get("secretSeed") or item.get("secret_seed") or ""
        name = (item.get("name") or item.get("label") or item.get("accountName") or "").strip()
        issuer = (item.get("issuer") or item.get("organization") or "").strip()
        group = issuer
        _append_entry(entries, warnings, errors, name, secret, group, "Authy JSON", seen, idx)

    if not entries and not errors:
        warnings.append("在 Authy JSON 中未发现可用的 TOTP 数据")

    return ParseResult(entries=entries, warnings=warnings, errors=errors)


def _append_entry(
    entries: list[ParsedEntry],
    warnings: list[str],
    errors: list[str],
    name: str,
    secret: str,
    group: str,
    source: str,
    seen_names: set[str],
    position: int,
) -> None:
    name = (name or "").strip()
    group = (group or "").strip()

    if not secret:
        warnings.append(f"第 {position} 项缺少密钥，已忽略")
        return

    normalized = normalize_google_secret(secret)
    if not normalized:
        warnings.append(f"第 {position} 项密钥无效，已忽略")
        return

    if not name:
        name = "未命名条目"
        warnings.append(f"第 {position} 项缺少名称，已使用占位名称")

    name = name[:MAX_NAME_LEN]
    group = group[:MAX_GROUP_LEN]

    if name in seen_names:
        warnings.append(f"名称“{name}”出现多次，仅保留首次出现")
        return

    seen_names.add(name)
    entries.append(ParsedEntry(name=name, secret=normalized, group=group, source=source))
