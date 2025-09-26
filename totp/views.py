import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, F, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from . import importers
from .models import Group, OneTimeLink, TOTPEntry
from .utils import (
    decrypt_str,
    encrypt_str,
    normalize_google_secret,
    parse_otpauth,
    totp_code_base32,
)


def dashboard(request):
    """展示仪表盘，可匿名访问。"""

    stats = {}
    recent_entries = []
    if request.user.is_authenticated:
        # 登录用户访问仪表盘时也清理一次回收站，保证数据实时。
        TOTPEntry.purge_expired_trash(user=request.user)
        entries = TOTPEntry.objects.filter(user=request.user)
        # 尽量减少查询次数地聚合统计信息
        agg = entries.aggregate(
            total_entries=Count("id"),
            today_added=Count("id", filter=Q(created_at__date=timezone.localdate())),
        )
        stats = {
            "total_entries": agg["total_entries"],
            "group_count": Group.objects.filter(user=request.user).count(),
            "today_added": agg["today_added"],
        }

        cycle_total = 30
        now = timezone.now()
        stats["current_cycle_total"] = cycle_total
        stats["current_cycle_remaining"] = cycle_total - (int(now.timestamp()) % cycle_total)

        recent_entries = list(
            entries.order_by("-created_at").values(
                "name",
                "created_at",
                group_name=F("group__name"),
            )[:5]
        )

    return render(
        request,
        "totp/dashboard.html",
        {"stats": stats, "recent_entries": recent_entries},
    )



@login_required
def list_view(request):
    """列出用户的所有 TOTP 条目。"""
    # 在展示列表前先顺带清理一下过期的回收站数据，保证统计准确。
    TOTPEntry.purge_expired_trash(user=request.user)
    q = (request.GET.get("q") or "").strip()
    group_id = (request.GET.get("group") or "").strip()
    entry_qs = (
        TOTPEntry.objects.filter(user=request.user)
        .select_related("group")
        .order_by("-created_at")
    )
    if q:
        entry_qs = entry_qs.filter(Q(name__icontains=q))
    if group_id == "0":
        entry_qs = entry_qs.filter(group__isnull=True)
    elif group_id:
        entry_qs = entry_qs.filter(group_id=group_id)

    paginator = Paginator(entry_qs, 5)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    groups = (
        Group.objects.filter(user=request.user)
        .annotate(entry_count=Count("entries", filter=Q(entries__is_deleted=False)))
        .order_by("name")
    )
    return render(
        request,
        "totp/list.html",
        {
            "entries": page_obj,
            "page_obj": page_obj,
            "q": q,
            "groups": groups,
            "group_id": group_id,
        },
    )


@login_required
def add_entry(request):
    """添加单个 TOTP 条目。"""
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        group_id = request.POST.get("group_id") or ""
        secret = (request.POST.get("secret") or "").strip()

        if secret.lower().startswith("otpauth://"):
            label, s = parse_otpauth(secret)
            if not name and label:
                name = label
            secret = s
        secret = normalize_google_secret(secret)
        if not name or not secret:
            messages.error(request, "名称和密钥必填且需符合要求")
            return redirect("totp:list")

        group = None
        if group_id:
            try:
                group = Group.objects.get(pk=int(group_id), user=request.user)
            except (Group.DoesNotExist, ValueError, TypeError):
                group = None

        if TOTPEntry.objects.filter(user=request.user, name=name).exists():
            messages.error(request, "同一用户下名称需唯一")
            return redirect("totp:list")

        enc = encrypt_str(secret)
        TOTPEntry.objects.create(user=request.user, name=name, group=group, secret_encrypted=enc)
        messages.success(request, "已添加")
        return redirect("totp:list")
    return redirect("totp:list")


@login_required
def add_group(request):
    """添加一个新的分组。"""
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        if not name:
            messages.error(request, "分组名称必填")
            return redirect("totp:list")
        if Group.objects.filter(user=request.user, name=name).exists():
            messages.error(request, "分组名称已存在")
            return redirect("totp:list")
        Group.objects.create(user=request.user, name=name)
        messages.success(request, "分组已添加")
    return redirect("totp:list")


@login_required
@require_POST
def rename_group(request, pk: int):
    """更新分组名称。"""

    group = get_object_or_404(Group, pk=pk, user=request.user)
    new_name = (request.POST.get("name") or "").strip()
    if not new_name:
        return JsonResponse(
            {
                "ok": False,
                "error": "empty_name",
                "message": "分组名称不能为空",
            },
            status=400,
        )

    exists = (
        Group.objects.filter(user=request.user, name=new_name)
        .exclude(pk=group.pk)
        .exists()
    )
    if exists:
        return JsonResponse(
            {
                "ok": False,
                "error": "duplicate_name",
                "message": "分组名称已存在",
            },
            status=400,
        )

    group.name = new_name
    group.save(update_fields=["name", "updated_at"])

    return JsonResponse({"ok": True, "id": group.pk, "name": group.name})


@login_required
@require_POST
def delete_group(request, pk: int):
    """删除指定分组并将关联条目标记为未分组。"""

    group = get_object_or_404(Group, pk=pk, user=request.user)
    entry_count = (
        TOTPEntry.objects.filter(user=request.user, group=group, is_deleted=False)
        .count()
    )
    group.delete()

    return JsonResponse({
        "ok": True,
        "id": pk,
        "released_entries": entry_count,
    })


@login_required
def delete_entry(request, pk: int):
    """删除指定的 TOTP 条目。"""
    e = get_object_or_404(TOTPEntry, pk=pk, user=request.user)
    # 改为软删除：仅做标记并记录删除时间，数据进入回收站。
    e.is_deleted = True
    e.deleted_at = timezone.now()
    e.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
    messages.success(request, "已移入回收站，可在 30 天内恢复")
    return redirect("totp:list")


@login_required
def trash_view(request):
    """展示当前用户的回收站列表。"""

    # 每次打开回收站时清理超过 30 天的条目，确保自动过期策略生效。
    TOTPEntry.purge_expired_trash(user=request.user)

    entry_qs = (
        TOTPEntry.all_objects.filter(user=request.user, is_deleted=True)
        .select_related("group")
        .order_by("-deleted_at")
    )
    paginator = Paginator(entry_qs, 15)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(
        request,
        "totp/trash.html",
        {"entries": page_obj, "page_obj": page_obj},
    )


@login_required
def restore_entry(request, pk: int):
    """从回收站恢复指定的 TOTP 条目。"""

    if request.method != "POST":
        messages.error(request, "请求方式不正确")
        return redirect("totp:trash")

    entry = get_object_or_404(
        TOTPEntry.all_objects, pk=pk, user=request.user, is_deleted=True
    )

    # 如果已有同名有效密钥，恢复会因唯一性约束失败，这里提前做校验并给出提示。
    if TOTPEntry.objects.filter(user=request.user, name=entry.name).exists():
        messages.error(request, "已存在同名密钥，无法恢复，请先修改现有密钥的名称")
        return redirect("totp:trash")

    entry.is_deleted = False
    entry.deleted_at = None
    entry.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
    messages.success(request, "密钥已成功恢复")
    return redirect("totp:list")



@login_required
@require_POST
def batch_import_preview(request):
    """上传文件或文本后，返回解析结果供前端预览。"""

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
    # 预先查询名称，避免在循环中重复命中数据库
    existing_names = set(
        TOTPEntry.objects.filter(user=request.user, name__in=names)
        .values_list("name", flat=True)
    )

    entries_payload = []
    duplicates = 0
    for entry in result.entries:
        exists = entry.name in existing_names
        if exists:
            duplicates += 1
        entries_payload.append(
            {
                "name": entry.name,
                "group": entry.group,
                "secret": entry.secret,
                "source": entry.source,
                "exists": exists,
                "secret_preview": _secret_preview(entry.secret),
            }
        )

    warnings = list(result.warnings)
    if duplicates:
        warnings.append(f"发现 {duplicates} 条与现有名称重复的条目，导入时将跳过")

    return JsonResponse(
        {
            "ok": True,
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

    created, skipped = _apply_import_entries(request.user, entries)

    if created:
        message = f"成功导入 {created} 条"
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

    return JsonResponse({"ok": True, "redirect": reverse("totp:list")})


def _apply_import_entries(user, entries):
    """将解析后的条目写入数据库，返回 (新增数量, 跳过数量)。"""

    created = 0
    skipped = 0
    if not entries:
        return created, skipped

    # 一次性查出需要的分组，缺失的分组批量创建
    group_names = sorted({entry.group for entry in entries if entry.group})
    groups = {
        g.name: g
        for g in Group.objects.filter(user=user, name__in=group_names)
    }
    missing = [
        Group(user=user, name=name) for name in group_names if name not in groups
    ]
    if missing:
        Group.objects.bulk_create(missing)
        groups.update(
            {
                g.name: g
                for g in Group.objects.filter(user=user, name__in=group_names)
            }
        )

    existing_names = set(
        TOTPEntry.objects.filter(user=user, name__in=[entry.name for entry in entries])
        .values_list("name", flat=True)
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
        existing_names.add(entry.name)  # 防止本次导入中出现重复名称

    if to_create:
        TOTPEntry.objects.bulk_create(to_create)
        created = len(to_create)

    return created, skipped


def _secret_preview(secret: str) -> str:
    """隐藏中间字符，仅展示密钥的头尾片段。"""

    if not secret:
        return ""
    if len(secret) <= 8:
        return secret
    return f"{secret[:4]}...{secret[-4:]}"



@login_required
def export_entries(request):
    """导出当前用户的全部密钥，以文本形式下载。"""

    queryset = (
        TOTPEntry.objects.filter(user=request.user)
        .select_related("group")
        .order_by("name")
    )

    if not queryset.exists():
        messages.info(request, "当前没有可以导出的密钥")
        return redirect("totp:list")

    lines = []
    for entry in queryset:
        secret = decrypt_str(entry.secret_encrypted)
        parts = [secret, entry.name]
        if entry.group:
            parts.append(entry.group.name)
        lines.append("|".join(parts))

    content = "\n".join(lines)
    filename = timezone.now().strftime("totp-export-%Y%m%d-%H%M%S.txt")
    quoted = quote(filename)

    response = HttpResponse(content, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    return response


@login_required
def export_offline_package(request):
    """生成离线只读 HTML，便于无网络环境查看验证码。"""

    queryset = (
        TOTPEntry.objects.filter(user=request.user, is_deleted=False)
        .select_related("group")
        .order_by("name")
    )

    if not queryset.exists():
        messages.info(request, "当前没有可用的密钥，无法生成离线包")
        return redirect("totp:list")

    entries = []
    for entry in queryset:
        secret = decrypt_str(entry.secret_encrypted)
        entries.append(
            {
                "name": entry.name,
                "secret": secret,
                "group": entry.group.name if entry.group else "",
                "period": 30,
                "digits": 6,
            }
        )

    generated_at = timezone.now()
    filename = generated_at.strftime("totp-offline-%Y%m%d-%H%M%S.html")
    quoted = quote(filename)

    context = {
        "generated_at": generated_at,
        "owner": request.user,
        "entries_json": json.dumps(entries, ensure_ascii=False),
        "entry_count": len(entries),
    }

    response = render(request, "totp/offline_package.html", context)
    response["Content-Type"] = "text/html; charset=utf-8"
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    return response


@login_required
def update_entry_group(request, pk: int):
    """更新指定条目的分组。"""

    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)

    entry = get_object_or_404(TOTPEntry, pk=pk, user=request.user)
    group_id = (request.POST.get("group_id") or "").strip()
    group = None
    if group_id:
        try:
            group = Group.objects.get(pk=int(group_id), user=request.user)
        except (Group.DoesNotExist, ValueError, TypeError):
            return JsonResponse({"error": "invalid_group"}, status=400)

    entry.group = group
    entry.save(update_fields=["group", "updated_at"])

    return JsonResponse(
        {
            "success": True,
            "group_name": group.name if group else "未分组",
        }
    )


@login_required
@require_POST
def create_one_time_link(request, pk: int):
    """为指定密钥生成一次性只读访问链接。"""

    entry = get_object_or_404(TOTPEntry, pk=pk, user=request.user, is_deleted=False)

    try:
        duration_minutes = int(request.POST.get("duration") or 10)
    except (TypeError, ValueError):
        duration_minutes = 10
    duration_minutes = max(1, min(duration_minutes, 60))

    try:
        max_views = int(request.POST.get("max_views") or 3)
    except (TypeError, ValueError):
        max_views = 3
    max_views = max(1, min(max_views, 5))

    now = timezone.now()
    active_links = OneTimeLink.active.filter(entry=entry).count()
    if active_links >= 5:
        return JsonResponse(
            {
                "ok": False,
                "error": "link_limit_reached",
                "message": "已有较多有效链接，请先失效旧链接后再试。",
            },
            status=400,
        )

    expires_at = now + timedelta(minutes=duration_minutes)

    token = None
    token_hash = None
    for _ in range(6):
        candidate = secrets.token_urlsafe(32)
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        if not OneTimeLink.objects.filter(token_hash=candidate_hash).exists():
            token = candidate
            token_hash = candidate_hash
            break
    if not token:
        return JsonResponse(
            {"ok": False, "error": "token_generation_failed"}, status=500
        )

    link = OneTimeLink.objects.create(
        entry=entry,
        created_by=request.user,
        token_hash=token_hash,
        expires_at=expires_at,
        max_views=max_views,
    )

    url = request.build_absolute_uri(reverse("totp:one_time_view", args=[token]))
    return JsonResponse(
        {
            "ok": True,
            "id": link.id,
            "url": url,
            "expires_at": expires_at.isoformat(),
            "expires_at_timestamp": int(expires_at.timestamp()),
            "max_views": link.max_views,
            "remaining_views": link.max_views - link.view_count,
        }
    )


@login_required
@require_POST
def invalidate_one_time_link(request, pk: int):
    """立即失效指定的一次性访问链接。"""

    link = get_object_or_404(OneTimeLink, pk=pk, created_by=request.user)
    link.invalidate()
    return JsonResponse({"ok": True})


def one_time_view(request, token: str):
    """展示一次性访问链接的验证码。"""

    token = (token or "").strip()
    if not token:
        return _render_one_time_invalid(request, reason="not_found")

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    try:
        with transaction.atomic():
            link = (
                OneTimeLink.objects.select_for_update()
                .select_related("entry", "entry__user", "entry__group")
                .get(token_hash=token_hash)
            )

            if not link.is_active:
                reason = _resolve_link_inactive_reason(link)
                return _render_one_time_invalid(request, reason=reason)

            try:
                link.mark_view(request)
            except ValueError:
                reason = _resolve_link_inactive_reason(link)
                return _render_one_time_invalid(request, reason=reason)

    except OneTimeLink.DoesNotExist:
        return _render_one_time_invalid(request, reason="not_found")

    entry = link.entry
    secret = decrypt_str(entry.secret_encrypted)
    code, remaining = totp_code_base32(secret, digits=6, period=30)

    context = {
        "link": link,
        "entry": entry,
        "code": code,
        "remaining": remaining,
        "owner": link.created_by,
        "remaining_views": max(0, link.max_views - link.view_count),
        "expires_at": link.expires_at,
    }
    return render(request, "totp/one_time_link.html", context)


def _render_one_time_invalid(request, reason: str, status: int | None = None):
    status_map = {
        "not_found": 404,
        "deleted": 410,
        "expired": 410,
        "used": 410,
        "revoked": 410,
    }
    ctx = {"reason": reason}
    return render(
        request,
        "totp/one_time_link.html",
        ctx,
        status=status or status_map.get(reason, 404),
    )


def _resolve_link_inactive_reason(link: OneTimeLink) -> str:
    now = timezone.now()
    if link.entry.is_deleted:
        return "deleted"
    if link.revoked_at is not None:
        return "revoked"
    if link.expires_at <= now:
        return "expired"
    if link.view_count >= link.max_views:
        return "used"
    return "revoked"
