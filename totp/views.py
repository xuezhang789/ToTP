from urllib.parse import quote
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, F, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from .models import Group, TOTPEntry
from .utils import decrypt_str, encrypt_str, normalize_google_secret, parse_otpauth


def dashboard(request):
    """展示仪表盘，可匿名访问。"""

    stats = {}
    recent_entries = []
    if request.user.is_authenticated:
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

    paginator = Paginator(entry_qs, 15)
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
    e.delete()
    messages.success(request, "已删除")
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
