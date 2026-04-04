import base64
import hashlib
import hmac
import struct
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.fernet import Fernet
from django.conf import settings
from django.utils.module_loading import import_string

_B32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_FERNETS = None


def _derive_fernet_key(material: str) -> bytes:
    digest = hashlib.sha256(material.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def reset_encryption_cache():
    """清空已缓存的加密实例，便于测试或轮换后重新加载配置。"""

    global _FERNETS
    _FERNETS = None


def _normalize_materials(values) -> list[str]:
    materials: list[str] = []
    seen: set[str] = set()

    def collect(raw):
        if raw is None:
            return
        if isinstance(raw, str):
            value = raw.strip()
            if value and value not in seen:
                seen.add(value)
                materials.append(value)
            return
        if isinstance(raw, dict):
            collect(raw.get("primary"))
            collect(raw.get("fallbacks"))
            return
        if isinstance(raw, (list, tuple, set)):
            for item in raw:
                collect(item)
            return
        collect(str(raw))

    collect(values)
    return materials


def _load_materials_from_file(path: str) -> list[str]:
    if not path:
        return []
    content = Path(path).read_text(encoding="utf-8")
    return _normalize_materials(content.splitlines())


def _load_materials_from_loader() -> list[str]:
    loader_path = (getattr(settings, "TOTP_DATA_KEY_LOADER", "") or "").strip()
    if not loader_path:
        return []
    loader = import_string(loader_path)
    return _normalize_materials(loader())


def get_encryption_materials() -> list[str]:
    """返回当前配置的主密钥列表，按优先级从高到低。"""

    materials = []
    materials.extend(_load_materials_from_loader())
    materials.extend(_normalize_materials(getattr(settings, "TOTP_DATA_KEYS", None) or []))
    materials.extend(_load_materials_from_file(getattr(settings, "TOTP_DATA_KEY_FILE", "") or ""))
    if getattr(settings, "TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK", True):
        materials.extend(_normalize_materials(getattr(settings, "TOTP_ENC_KEYS", None) or []))
    if getattr(settings, "TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK", False):
        materials.extend(_normalize_materials([settings.SECRET_KEY]))
    return _normalize_materials(materials)


def _fernets():
    """返回缓存的 Fernet 实例列表，按优先级从高到低。"""

    global _FERNETS
    if _FERNETS is None:
        materials = get_encryption_materials()
        if not materials:
            raise RuntimeError("未配置可用的 TOTP 数据加密主密钥")
        _FERNETS = [Fernet(_derive_fernet_key(m)) for m in materials]
    return _FERNETS


def is_encrypted_with_primary(token: str) -> bool:
    """判断密文是否已由当前主密钥加密。"""

    fernet = _fernets()[0]
    try:
        fernet.decrypt(token.encode())
    except Exception:
        return False
    return True


def encrypt_str(s: str) -> str:
    """对字符串进行对称加密。"""
    return _fernets()[0].encrypt(s.encode()).decode()


def decrypt_str(token: str) -> str:
    """解密 ``encrypt_str`` 生成的密文。"""
    last_exc = None
    for f in _fernets():
        try:
            return f.decrypt(token.encode()).decode()
        except Exception as exc:
            last_exc = exc
    if last_exc:
        raise last_exc
    raise ValueError("invalid token")


def rewrap_encrypted_str(token: str) -> tuple[str, bool]:
    """使用当前主密钥重新包裹密文，返回 (新密文, 是否发生了重加密)。"""

    if is_encrypted_with_primary(token):
        return token, False
    plaintext = decrypt_str(token)
    return encrypt_str(plaintext), True


def parse_otpauth(uri: str):
    """解析 ``otpauth://`` 格式的 URI，返回标签和密钥。"""
    if not uri.lower().startswith("otpauth://totp/"):
        return "", ""
    u = urlparse(uri)
    label = unquote((u.path or "").lstrip("/"))
    secret = parse_qs(u.query).get("secret", [""])[0]
    return label, secret


def _b32_clean(s: str) -> str:
    """去除 Base32 字符串中无效字符。"""
    return "".join(c for c in s if c.isalnum()).upper()


def normalize_google_secret(secret: str) -> str:
    """清理并校验 Google 身份验证器使用的 Base32 密钥。

    返回清理后的密钥；若密钥无效则返回空字符串。
    """
    s = _b32_clean(secret)
    if len(s) < 16 or any(c not in _B32_ALPHABET for c in s):
        return ""
    try:
        # Base32 要求长度为 8 的倍数，不足时补齐填充后检测其合法性
        base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8), casefold=True)
    except Exception:
        return ""
    return s


def totp_code_base32(
    secret_b32: str,
    digits: int = 6,
    period: int = 30,
    timestamp: int | float | None = None,
):
    """根据 Base32 密钥计算当前 TOTP 码及剩余时间。

    可选的 ``timestamp`` 参数允许复用同一时间点，用于批量计算时减少重复的
    ``time.time()`` 调用并保持返回值在一个周期内一致。
    """
    s = _b32_clean(secret_b32)
    key = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8), casefold=True)
    if timestamp is None:
        t = int(time.time())
    else:
        t = int(timestamp)
    counter = t // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % (10 ** digits)
    code = str(code_int).zfill(digits)
    remaining = period - (t % period)
    return code, remaining
