from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q, F, Count
from django.utils import timezone
from django.core.paginator import Paginator
from .models import TOTPEntry, Group
from .utils import encrypt_str, parse_otpauth


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
    entry_qs = TOTPEntry.objects.filter(user=request.user).select_related("group").order_by("-created_at")
    if q:
        entry_qs = entry_qs.filter(Q(name__icontains=q))

    paginator = Paginator(entry_qs, 15)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    groups = Group.objects.filter(user=request.user).order_by("name")
    return render(
        request,
        "totp/list.html",
        {"entries": page_obj, "page_obj": page_obj, "q": q, "groups": groups},
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

        if not name or not secret:
            messages.error(request, "名称和密钥必填")
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
    for s in lines:
        name = secret = ""
        group_name = ""
        if s.lower().startswith("otpauth://"):
            label, secret = parse_otpauth(s)
            name = label or ""
        else:
            parts = s.split("|")
            if len(parts) >= 2:
                secret = parts[0].strip()
                name = parts[1].strip()
                if len(parts) >= 3:
                    group_name = parts[2].strip()
                    if name and secret:
                        if group_name:
                            group_names.add(group_name)
                        parsed.append((name, secret, group_name))

                if not parsed:
                    messages.info(request, "没有新的条目导入")
                    return redirect("totp:list")

                # 预取已存在的分组并一次性创建缺失的分组
                groups = {g.name: g for g in Group.objects.filter(user=request.user, name__in=group_names)}
                missing = [Group(user=request.user, name=n) for n in group_names if n not in groups]
                if missing:
                    Group.objects.bulk_create(missing)
                    groups.update({g.name: g for g in Group.objects.filter(user=request.user, name__in=group_names)})

                # 一次性查询现有条目名称，避免重复
                names = [name for name, _, _ in parsed]
                existing_names = set(
                    TOTPEntry.objects.filter(user=request.user, name__in=names).values_list("name", flat=True)
                )

                to_create = []
                for name, secret, group_name in parsed:
                    if name in existing_names:
                        continue
        group = groups.get(group_name)
        to_create.append(
            TOTPEntry(
                user=request.user,
                name=name,
                group=group,
                secret_encrypted=encrypt_str(secret),
            )
        )
        existing_names.add(name)
        if to_create:
            TOTPEntry.objects.bulk_create(to_create)
            messages.success(request, f"成功导入 {len(to_create)} 条")
    else:
        messages.info(request, "没有新的条目导入")
    return redirect("totp:list")
