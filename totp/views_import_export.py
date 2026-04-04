import base64
import io
import json
import os
from urllib.parse import quote

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from . import importers
from .models import Group, TeamAsset, TOTPEntry, TOTPEntryAudit
from .utils import decrypt_str, encrypt_str, normalize_google_secret
from .views import (
    _has_recent_reauth,
    _reauth_json,
    _reauth_redirect,
    _resolve_import_target,
    _secret_preview,
)


@login_required
@require_POST
def batch_import_preview(request):
    """上传文件或文本后，返回解析结果供前端预览。"""

    try:
        space, target_team, target_label = _resolve_import_target(
            request.user,
            request.POST.get("space"),
            require_manage=True,
        )
    except ValueError as exc:
        return JsonResponse({"ok": False, "errors": [str(exc)]}, status=400)

    raw_asset_id = (request.POST.get("asset_id") or "").strip()
    target_asset = None
    if target_team is not None and raw_asset_id:
        try:
            target_asset = TeamAsset.objects.get(pk=int(raw_asset_id), team=target_team)
        except (TeamAsset.DoesNotExist, TypeError, ValueError):
            return JsonResponse({"ok": False, "errors": ["资产不存在或不可用"]}, status=400)

    mode = (request.POST.get("mode") or "manual").strip()
    manual_text = (request.POST.get("manual_text") or "").strip() if mode == "manual" else ""
    uploaded = request.FILES.get("file") if mode == "file" else None

    result = importers.parse_import_payload(
        manual_text=manual_text,
        uploaded_file=uploaded,
    )

    if result.errors:
        return JsonResponse({"ok": False, "errors": result.errors}, status=400)
    if not result.entries:
        return JsonResponse({"ok": False, "errors": ["没有可导入的条目"]}, status=400)

    names = [entry.name for entry in result.entries]
    if target_team is None:
        existing_names = set(
            TOTPEntry.objects.filter(
                user=request.user,
                team__isnull=True,
                name__in=names,
                is_deleted=False,
            ).values_list("name", flat=True)
        )
    else:
        existing_names = set(
            TOTPEntry.objects.filter(
                team=target_team,
                name__in=names,
                is_deleted=False,
            ).values_list("name", flat=True)
        )

    entries_payload = []
    duplicates = 0
    ignored_groups = False
    for entry in result.entries:
        exists = entry.name in existing_names
        if exists:
            duplicates += 1
        group_value = entry.group
        if target_team is not None:
            if entry.group:
                ignored_groups = True
            group_value = ""
        entries_payload.append(
            {
                "name": entry.name,
                "group": group_value,
                "secret": entry.secret,
                "source": entry.source,
                "exists": exists,
                "secret_preview": _secret_preview(entry.secret),
            }
        )

    warnings = list(result.warnings)
    if duplicates:
        warnings.append(f"发现 {duplicates} 条与现有名称重复的条目，导入时将跳过")
    if ignored_groups:
        warnings.append("团队空间不支持分组，已忽略导入数据中的分组信息")

    return JsonResponse(
        {
            "ok": True,
            "space": space,
            "target_label": target_label,
            "asset_id": str(target_asset.id) if target_asset else "",
            "entries": entries_payload,
            "warnings": warnings,
            "summary": {
                "total": len(entries_payload),
                "new": len(entries_payload) - duplicates,
                "existing": duplicates,
            },
        }
    )


@login_required
@require_POST
def batch_import_apply(request):
    """在预览确认后批量写入条目。"""

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (TypeError, ValueError):
        return JsonResponse({"ok": False, "error": "请求格式无效"}, status=400)

    if not _has_recent_reauth(request):
        return _reauth_json(request)

    try:
        space, target_team, _target_label = _resolve_import_target(
            request.user,
            payload.get("space"),
            require_manage=True,
        )
    except ValueError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    raw_asset_id = (payload.get("asset_id") or "").strip()
    target_asset = None
    if target_team is not None and raw_asset_id:
        try:
            target_asset = TeamAsset.objects.get(pk=int(raw_asset_id), team=target_team)
        except (TeamAsset.DoesNotExist, TypeError, ValueError):
            return JsonResponse({"ok": False, "error": "invalid_asset"}, status=400)

    raw_entries = payload.get("entries") or []
    if not isinstance(raw_entries, list) or not raw_entries:
        return JsonResponse({"ok": False, "error": "缺少有效的导入数据"}, status=400)

    entries: list[importers.ParsedEntry] = []
    errors: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(raw_entries, 1):
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or "").strip()
        secret = (item.get("secret") or "").strip()
        group = (item.get("group") or "").strip()
        if target_team is not None:
            group = ""
        if not name or name in seen:
            continue
        normalized = normalize_google_secret(secret)
        if not normalized:
            errors.append(f"第 {idx} 条数据无效，已跳过")
            continue
        entries.append(
            importers.ParsedEntry(
                name=name[:importers.MAX_NAME_LEN],
                secret=normalized,
                group=group[:importers.MAX_GROUP_LEN],
                source=item.get("source") or "预览导入",
            )
        )
        seen.add(name)

    if not entries:
        if errors:
            return JsonResponse({"ok": False, "error": errors[0]}, status=400)
        return JsonResponse({"ok": False, "error": "没有可导入的条目"}, status=400)

    created, skipped = _apply_import_entries(
        request.user,
        entries,
        team=target_team,
        asset=target_asset,
    )

    if created:
        message = f"成功导入 {created} 条"
        if target_team is not None:
            message += f"到 {target_team.name} 团队空间"
        if skipped:
            message += f"，跳过 {skipped} 条重复"
        if errors:
            message += f"（{len(errors)} 条无效密钥已忽略）"
        messages.success(request, message)
    else:
        message = "没有新的条目导入"
        if errors:
            message += f"（{len(errors)} 条无效密钥已忽略）"
        messages.info(request, message)

    for err in errors:
        messages.warning(request, err)

    redirect_url = reverse("totp:list")
    if target_team is not None:
        redirect_url = f"{redirect_url}?space=team:{target_team.id}"

    return JsonResponse({"ok": True, "redirect": redirect_url, "space": space})


def _apply_import_entries(user, entries, *, team=None, asset=None):
    """将解析后的条目写入数据库，返回 (新增数量, 跳过数量)。"""

    created = 0
    skipped = 0
    if not entries:
        return created, skipped

    if team is not None:
        existing_names = set(
            TOTPEntry.objects.filter(
                team=team,
                name__in=[entry.name for entry in entries],
                is_deleted=False,
            ).values_list("name", flat=True)
        )

        to_create = []
        for entry in entries:
            if entry.name in existing_names:
                skipped += 1
                continue
            to_create.append(
                TOTPEntry(
                    user=user,
                    team=team,
                    asset=asset,
                    name=entry.name,
                    secret_encrypted=encrypt_str(entry.secret),
                )
            )
            existing_names.add(entry.name)

        if to_create:
            created_entries = TOTPEntry.objects.bulk_create(to_create)
            created = len(created_entries)
            if created_entries:
                actor_obj = user if getattr(user, "is_authenticated", False) else None
                TOTPEntryAudit.objects.bulk_create(
                    [
                        TOTPEntryAudit(
                            entry=created_entry,
                            actor=actor_obj,
                            action=TOTPEntryAudit.Action.CREATED,
                            new_value=created_entry.name,
                            metadata={
                                "space": "team",
                                "import": True,
                                "asset": asset.name if asset else "",
                            },
                        )
                        for created_entry in created_entries
                    ]
                )

        return created, skipped

    group_names = sorted({entry.group for entry in entries if entry.group})
    groups = {g.name: g for g in Group.objects.filter(user=user, name__in=group_names)}
    missing = [Group(user=user, name=name) for name in group_names if name not in groups]
    if missing:
        Group.objects.bulk_create(missing)
        groups.update(
            {g.name: g for g in Group.objects.filter(user=user, name__in=group_names)}
        )

    existing_names = set(
        TOTPEntry.objects.filter(
            user=user,
            team__isnull=True,
            name__in=[entry.name for entry in entries],
            is_deleted=False,
        ).values_list("name", flat=True)
    )

    to_create = []
    for entry in entries:
        if entry.name in existing_names:
            skipped += 1
            continue
        group = groups.get(entry.group) if entry.group else None
        to_create.append(
            TOTPEntry(
                user=user,
                name=entry.name,
                group=group,
                secret_encrypted=encrypt_str(entry.secret),
            )
        )
        existing_names.add(entry.name)

    if to_create:
        created_entries = TOTPEntry.objects.bulk_create(to_create)
        created = len(created_entries)
        if created_entries:
            actor_obj = user if getattr(user, "is_authenticated", False) else None
            TOTPEntryAudit.objects.bulk_create(
                [
                    TOTPEntryAudit(
                        entry=created_entry,
                        actor=actor_obj,
                        action=TOTPEntryAudit.Action.CREATED,
                        new_value=created_entry.name,
                        metadata={"space": "personal", "import": True},
                    )
                    for created_entry in created_entries
                ]
            )

    return created, skipped


@never_cache
@login_required
@require_GET
def export_download(request):
    kind = (request.GET.get("kind") or "").strip()
    return_url = (request.GET.get("return") or "").strip()
    if not url_has_allowed_host_and_scheme(
        url=return_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return_url = reverse("totp:list")

    if kind == "plain":
        download_url = reverse("totp:export")
        title = "导出密钥"
    elif kind == "offline":
        download_url = reverse("totp:export_offline")
        title = "离线导出"
    else:
        raise Http404("Not found")

    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再继续")
        return _reauth_redirect(request)

    return render(
        request,
        "totp/export_download.html",
        {
            "title": title,
            "download_url": download_url,
            "return_url": return_url,
        },
    )


@never_cache
@login_required
def export_entries(request):
    """导出当前用户的全部密钥，以文本形式下载。"""

    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再导出")
        return _reauth_redirect(request)

    queryset = TOTPEntry.objects.filter(
        user=request.user,
        team__isnull=True,
        is_deleted=False,
    ).select_related("group").only(
        "id",
        "name",
        "secret_encrypted",
        "group_id",
        "group__name",
    ).order_by("name")

    if not queryset.exists():
        messages.info(request, "当前没有可以导出的密钥")
        return redirect("totp:list")

    filename = timezone.now().strftime("totp-export-%Y%m%d-%H%M%S.txt")
    quoted = quote(filename)

    def row_stream():
        audit_rows = []
        for entry in queryset.iterator(chunk_size=200):
            secret = decrypt_str(entry.secret_encrypted)
            parts = [secret, entry.name]
            if entry.group_id:
                parts.append(entry.group.name)
            audit_rows.append(
                TOTPEntryAudit(
                    entry=entry,
                    actor=request.user,
                    action=TOTPEntryAudit.Action.EXPORTED,
                    old_value=entry.name,
                    metadata={"space": "personal"},
                )
            )
            if len(audit_rows) >= 500:
                TOTPEntryAudit.objects.bulk_create(audit_rows)
                audit_rows.clear()
            yield ("|".join(parts) + "\n").encode("utf-8")
        if audit_rows:
            TOTPEntryAudit.objects.bulk_create(audit_rows)

    response = StreamingHttpResponse(
        row_stream(),
        content_type="text/plain; charset=utf-8",
    )
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


@never_cache
@login_required
@require_POST
def export_encrypted_package(request):
    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再导出")
        next_url = f"{reverse('totp:list')}?modal=export_encrypted"
        return redirect(f"{reverse('accounts:reauth')}?next={quote(next_url)}")

    passphrase = (request.POST.get("passphrase") or "").strip()
    passphrase2 = (request.POST.get("passphrase2") or "").strip()
    if not passphrase or len(passphrase) < 8:
        messages.error(request, "口令长度至少 8 位")
        return redirect(f"{reverse('totp:list')}?modal=export_encrypted")
    if passphrase != passphrase2:
        messages.error(request, "两次输入的口令不一致")
        return redirect(f"{reverse('totp:list')}?modal=export_encrypted")

    queryset = TOTPEntry.objects.filter(
        user=request.user,
        team__isnull=True,
        is_deleted=False,
    ).select_related("group").order_by("name")
    if not queryset.exists():
        messages.info(request, "当前没有可以导出的密钥")
        return redirect("totp:list")

    limit = int(getattr(settings, "EXPORT_ENCRYPTED_MAX_ENTRIES", 2000) or 2000)
    total = queryset.count()
    if total > limit:
        messages.error(
            request,
            (
                f"密钥数量过多（{total} 条），为避免导出时占用过多资源，"
                f"单次最多导出 {limit} 条。请减少条目数量或分批处理后再试。"
            ),
        )
        return redirect(f"{reverse('totp:list')}?modal=export_encrypted")

    buffer = io.StringIO()
    audit_rows = []
    entry_count = 0
    for entry in queryset.iterator(chunk_size=200):
        secret = decrypt_str(entry.secret_encrypted)
        parts = [secret, entry.name]
        if entry.group:
            parts.append(entry.group.name)
        buffer.write("|".join(parts))
        buffer.write("\n")
        entry_count += 1
        audit_rows.append(
            TOTPEntryAudit(
                entry=entry,
                actor=request.user,
                action=TOTPEntryAudit.Action.ENCRYPTED_EXPORTED,
                old_value=entry.name,
                metadata={"space": "personal"},
            )
        )
        if len(audit_rows) >= 500:
            TOTPEntryAudit.objects.bulk_create(audit_rows)
            audit_rows.clear()

    plaintext = buffer.getvalue().encode("utf-8")
    iterations = 200000
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    token = Fernet(key).encrypt(plaintext).decode("utf-8")
    payload = {
        "version": 1,
        "kdf": {
            "name": "pbkdf2-sha256",
            "iterations": iterations,
            "salt": base64.urlsafe_b64encode(salt).decode("utf-8"),
        },
        "cipher": {
            "name": "fernet",
            "token": token,
        },
        "meta": {
            "generated_at": timezone.now().isoformat(),
            "count": entry_count,
        },
    }

    filename = timezone.now().strftime("totp-export-encrypted-%Y%m%d-%H%M%S.json")
    quoted = quote(filename)
    response = HttpResponse(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        content_type="application/json; charset=utf-8",
    )
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    if audit_rows:
        TOTPEntryAudit.objects.bulk_create(audit_rows)
    return response


@never_cache
@login_required
@require_GET
def export_offline_package(request):
    """生成离线只读 HTML，便于无网络环境查看验证码。"""

    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再导出")
        return _reauth_redirect(request)

    queryset = (
        TOTPEntry.objects.filter(
            user=request.user,
            team__isnull=True,
            is_deleted=False,
        )
        .select_related("group")
        .order_by("name")
    )

    if not queryset.exists():
        messages.info(request, "当前没有可用的密钥，无法生成离线包")
        return redirect("totp:list")

    limit = int(getattr(settings, "EXPORT_OFFLINE_MAX_ENTRIES", 1000) or 1000)
    total = queryset.count()
    if total > limit:
        messages.error(
            request,
            (
                f"密钥数量过多（{total} 条），离线包会包含所有密钥并占用较大内存，"
                f"单次最多导出 {limit} 条。请减少条目数量或分批处理后再试。"
            ),
        )
        return redirect("totp:list")

    entries_payload = []
    audit_rows = []
    for entry in queryset.iterator(chunk_size=200):
        secret = decrypt_str(entry.secret_encrypted)
        issuer = entry.group.name if entry.group else request.user.username
        entries_payload.append(
            {
                "name": entry.name,
                "secret": secret,
                "group": entry.group.name if entry.group else "",
                "period": 30,
                "digits": 6,
                "issuer": issuer,
            }
        )
        audit_rows.append(
            TOTPEntryAudit(
                entry=entry,
                actor=request.user,
                action=TOTPEntryAudit.Action.OFFLINE_EXPORTED,
                old_value=entry.name,
                metadata={"space": "personal"},
            )
        )
        if len(audit_rows) >= 500:
            TOTPEntryAudit.objects.bulk_create(audit_rows)
            audit_rows.clear()

    generated_at = timezone.now()
    filename = generated_at.strftime("totp-offline-%Y%m%d-%H%M%S.html")
    quoted = quote(filename)

    response = render(
        request,
        "totp/offline_package.html",
        {
            "generated_at": generated_at,
            "owner": request.user,
            "entries_payload": entries_payload,
            "entry_count": len(entries_payload),
            "site_url": request.build_absolute_uri(reverse("dashboard")),
            "site_host": request.get_host(),
        },
    )
    response["Content-Type"] = "text/html; charset=utf-8"
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    if audit_rows:
        TOTPEntryAudit.objects.bulk_create(audit_rows)
    return response
