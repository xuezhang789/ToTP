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
from django.views.decorators.http import require_POST

from .models import (
    Group,
    OneTimeLink,
    TOTPEntry,
)
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
    groups = Group.objects.filter(user=request.user).order_by("name")
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
def batch_import(request):
    """批量导入多个 TOTP 条目。"""
    if request.method != "POST":
        return redirect("totp:list")
    text = (request.POST.get("bulk_text") or "").strip()
    if not text:
        messages.error(request, "内容为空")
        return redirect("totp:list")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    parsed = []
    group_names = set()
    invalid_count = 0
    for s in lines:
        name = secret = ""
        group_name = ""
        if s.lower().startswith("otpauth://"):
            label, secret = parse_otpauth(s)
            name = (label or "").strip()
        else:
            parts = s.split("|")
            if len(parts) < 2:
                invalid_count += 1
                continue
            secret = parts[0].strip()
            name = parts[1].strip()
            if len(parts) >= 3:
                group_name = parts[2].strip()

        secret = normalize_google_secret(secret)
        if not name or not secret:
            invalid_count += 1
            continue

        if group_name:
            group_names.add(group_name)
        parsed.append((name, secret, group_name))

    if not parsed:
        msg = "没有新的条目导入"
        if invalid_count:
            msg += f"（{invalid_count} 条无效密钥已忽略）"
        messages.info(request, msg)
        return redirect("totp:list")

    # 预取已存在的分组并一次性创建缺失的分组
    groups = {
        g.name: g
        for g in Group.objects.filter(user=request.user, name__in=group_names)
    }
    missing = [
        Group(user=request.user, name=n) for n in group_names if n not in groups
    ]
    if missing:
        Group.objects.bulk_create(missing)
        groups.update(
            {
                g.name: g
                for g in Group.objects.filter(
                user=request.user, name__in=group_names
            )
            }
        )

    # 一次性查询现有条目名称，避免重复
    names = [name for name, _, _ in parsed]
    existing_names = set(
        TOTPEntry.objects.filter(user=request.user, name__in=names).values_list(
            "name", flat=True
        )
    )
    to_create = []
    for name, secret, group_name in parsed:
        if name in existing_names:
            continue
        group = groups.get(group_name) if group_name else None
        to_create.append(
            TOTPEntry(
                user=request.user,
                name=name,
                group=group,
                secret_encrypted=encrypt_str(secret),
            )
        )

    if to_create:
        TOTPEntry.objects.bulk_create(to_create)
        msg = f"成功导入 {len(to_create)} 条"
        if invalid_count:
            msg += f"（{invalid_count} 条无效密钥已忽略）"
        messages.success(request, msg)
    else:
        msg = "没有新的条目导入"
        if invalid_count:
            msg += f"（{invalid_count} 条无效密钥已忽略）"
        messages.info(request, msg)
    return redirect("totp:list")


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
