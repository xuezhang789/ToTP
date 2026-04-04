from datetime import datetime, time, timedelta
from importlib import import_module
from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Max, Prefetch, Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .models import (
    Group,
    OneTimeLink,
    Team,
    TeamAsset,
    TeamAudit,
    TeamInvitation,
    TeamMembership,
    TOTPEntry,
    TOTPEntryAudit,
    log_entry_audit,
)
from .querysets import entries_queryset_for_list
from .utils import (
    encrypt_str,
    normalize_google_secret,
    parse_otpauth,
)

EXPORT_REAUTH_MAX_AGE_SECONDS = 5 * 60
TEAM_ONE_TIME_LINK_ACTIVE_LIMIT = 50
TEAM_ONE_TIME_LINK_MAX_DURATION_MINUTES = 12 * 60

TEAM_MANAGER_ROLES = (
    TeamMembership.Role.OWNER,
    TeamMembership.Role.ADMIN,
)

PURGE_TRASH_THROTTLE_SECONDS = 60 * 60  # 每位用户至多每小时触发一次回收站清理
ENTRY_NAME_MAX_LENGTH = TOTPEntry._meta.get_field("name").max_length
GROUP_NAME_MAX_LENGTH = Group._meta.get_field("name").max_length
TEAM_NAME_MAX_LENGTH = Team._meta.get_field("name").max_length
TEAM_ASSET_NAME_MAX_LENGTH = TeamAsset._meta.get_field("name").max_length


def _purge_trash_throttled(user):
    """控制调用频率的回收站清理，避免高频页面引发重复删除查询。"""

    if not user or not getattr(user, "is_authenticated", False):
        return
    cache_key = f"totp:purge_trash:v1:{user.pk}"
    if cache.get(cache_key):
        return
    TOTPEntry.purge_expired_trash(user=user)
    cache.set(cache_key, True, PURGE_TRASH_THROTTLE_SECONDS)


def _team_memberships_for_user(user):
    return list(
        TeamMembership.objects.filter(user=user)
        .select_related("team")
        .order_by("team__name")
    )


def _has_recent_reauth(request) -> bool:
    ts = request.session.get("reauth_at")
    if not ts:
        return False
    try:
        value = int(ts)
    except (TypeError, ValueError):
        return False
    now_ts = int(timezone.now().timestamp())
    return now_ts - value <= EXPORT_REAUTH_MAX_AGE_SECONDS


def _reauth_redirect(request, *, next_url: str | None = None, fallback: str | None = None):
    if fallback is None:
        fallback = reverse("totp:list")
    candidate = next_url
    if not candidate:
        if request.method == "GET":
            candidate = request.get_full_path()
        else:
            candidate = request.META.get("HTTP_REFERER") or fallback
    if not url_has_allowed_host_and_scheme(
        candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        candidate = fallback
    return redirect(f"{reverse('accounts:reauth')}?next={quote(candidate)}")


def _reauth_json(request):
    next_url = request.META.get("HTTP_REFERER") or reverse("totp:list")
    if not url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = reverse("totp:list")
    return JsonResponse(
        {
            "ok": False,
            "error": "reauth_required",
            "redirect": f"{reverse('accounts:reauth')}?next={quote(next_url)}",
        },
        status=403,
    )


def _get_team_membership(user, team_id, *, require_manage=False):
    membership = (
        TeamMembership.objects.select_related("team")
        .filter(team_id=team_id, user=user)
        .first()
    )
    if membership is None:
        raise Http404("Team not found")
    if require_manage and membership.role not in TEAM_MANAGER_ROLES:
        raise Http404("Team not found")
    return membership


def _resolve_import_target(user, space_value, *, require_manage=False):
    """解析批量导入目标空间，返回 (normalized_space, team, label)。"""

    space_raw = (space_value or "personal").strip()
    if space_raw.startswith("team:"):
        try:
            team_id = int(space_raw.split(":", 1)[1])
        except (ValueError, IndexError):
            raise ValueError("无效的团队空间")
        try:
            membership = _get_team_membership(
                user, team_id, require_manage=require_manage
            )
        except Http404 as exc:
            raise ValueError("无法访问指定团队或缺少权限") from exc
        if require_manage and not membership.can_manage_entries:
            raise ValueError("只有团队管理员可以导入到该空间")
        return (
            f"team:{membership.team_id}",
            membership.team,
            f"{membership.team.name} 团队",
        )
    return "personal", None, "个人空间"


def _get_entry_for_user(user, pk, *, include_deleted=False, require_manage=False):
    """获取当前用户可访问的条目，必要时校验管理权限。"""

    manager = TOTPEntry.all_objects if include_deleted else TOTPEntry.objects
    try:
        entry = manager.select_related("team", "user").get(pk=pk)
    except TOTPEntry.DoesNotExist as exc:
        raise Http404("Entry not found") from exc

    if not entry.user_can_view(user):
        raise Http404("Entry not found")
    if require_manage and not entry.user_can_manage(user):
        raise Http404("Entry not found")
    return entry


def _creator_accessible_one_time_links(user):
    return (
        OneTimeLink.objects.filter(created_by=user)
        .filter(
            Q(entry__team__isnull=True, entry__user=user)
            | Q(entry__team__isnull=False, entry__team__memberships__user=user)
        )
        .distinct()
    )


def _active_one_time_links_queryset(queryset, *, now=None):
    if now is None:
        now = timezone.now()
    return queryset.filter(
        expires_at__gt=now,
        view_count__lt=F("max_views"),
        entry__is_deleted=False,
        revoked_at__isnull=True,
    )


def dashboard(request):
    """展示仪表盘，可匿名访问。"""

    stats = {}
    recent_entries = []
    recent_audits = []
    memberships = []
    groups = []
    if request.user.is_authenticated:
        memberships = _team_memberships_for_user(request.user)
        team_ids = {m.team_id for m in memberships}
        # 登录用户访问仪表盘时也清理一次回收站，保证数据实时。
        _purge_trash_throttled(request.user)
        accessible_entries = (
            TOTPEntry.objects.for_user(request.user)
            .select_related("team", "group")
            .distinct()
        )
        today = timezone.localdate()
        today_start = timezone.make_aware(
            datetime.combine(today, time.min),
            timezone.get_current_timezone(),
        )
        tomorrow_start = today_start + timedelta(days=1)
        group_list = list(Group.objects.filter(user=request.user).order_by("name"))
        agg = accessible_entries.aggregate(
            total_entries=Count("id", distinct=True),
            personal_entries=Count(
                "id",
                filter=Q(team__isnull=True),
                distinct=True,
            ),
            shared_entries=Count(
                "id",
                filter=Q(team__isnull=False),
                distinct=True,
            ),
            today_added_total=Count(
                "id",
                filter=Q(created_at__gte=today_start, created_at__lt=tomorrow_start),
                distinct=True,
            ),
        )
        stats = {
            "total_entries": agg["total_entries"] or 0,
            "personal_entries": agg["personal_entries"] or 0,
            "shared_entries": agg["shared_entries"] or 0,
            "group_count": len(group_list),
            "team_count": len(team_ids),
            "today_added": agg["today_added_total"] or 0,
        }

        cycle_total = 30
        now = timezone.now()
        stats["current_cycle_total"] = cycle_total
        stats["current_cycle_remaining"] = cycle_total - (int(now.timestamp()) % cycle_total)
        groups = group_list

        recent_entries = list(
            accessible_entries.order_by("-created_at")
            .values(
                "name",
                "created_at",
                group_name=F("group__name"),
                team_name=F("team__name"),
            )[:5]
        )

        audit_qs = (
            TOTPEntryAudit.objects.filter(entry__in=accessible_entries.values("pk"))
            .select_related("entry", "entry__team", "actor")
            .order_by("-created_at")[:10]
        )
        recent_audits = list(audit_qs)

    return render(
        request,
        "totp/dashboard.html",
        {
            "stats": stats,
            "recent_entries": recent_entries,
            "team_memberships": memberships,
            "recent_audits": recent_audits,
            "groups": groups,
        },
    )



@login_required
def list_view(request):
    """列出用户的所有 TOTP 条目。"""
    # 在展示列表前先顺带清理一下过期的回收站数据，保证统计准确。
    _purge_trash_throttled(request.user)

    memberships = _team_memberships_for_user(request.user)

    q = (request.GET.get("q") or "").strip()
    group_id = (request.GET.get("group") or "").strip()
    asset_id = (request.GET.get("asset") or "").strip()
    space = (request.GET.get("space") or "personal").strip()
    selected_team = None
    selected_membership = None

    if space.startswith("team:"):
        try:
            team_id = int(space.split(":", 1)[1])
        except (ValueError, IndexError):
            raise Http404("Team not found")
        selected_membership = _get_team_membership(
            request.user, team_id, require_manage=False
        )
        selected_team = selected_membership.team
    else:
        space = "personal"
    entry_qs, groups = entries_queryset_for_list(
        user=request.user,
        selected_team=selected_team,
        q=q,
        group_id=group_id,
        asset_id=asset_id,
    )
    available_team_assets = []
    if selected_team is not None:
        available_team_assets = list(
            TeamAsset.objects.filter(team=selected_team).order_by("name")
        )

    paginator = Paginator(entry_qs, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    for entry in page_obj.object_list:
        entry.can_manage = entry.user_can_manage(request.user)
        entry.current_membership = entry.membership_for(request.user)

    return render(
        request,
        "totp/list.html",
        {
            "entries": page_obj,
            "page_obj": page_obj,
            "q": q,
            "groups": groups,
            "group_id": group_id,
            "asset_id": asset_id,
            "team_assets": available_team_assets,
            "team_memberships": memberships,
            "selected_space": space,
            "selected_team": selected_team,
            "selected_membership": selected_membership,
            "has_password": request.user.has_usable_password(),
        },
    )
def _build_team_member_row(*, row: TeamMembership, viewer: TeamMembership, current_user):
    is_self = row.user_id == current_user.id
    can_leave = is_self and row.role != TeamMembership.Role.OWNER
    can_remove = False
    if viewer.role == TeamMembership.Role.OWNER:
        can_remove = row.role != TeamMembership.Role.OWNER and not is_self
    elif viewer.role == TeamMembership.Role.ADMIN:
        can_remove = row.role == TeamMembership.Role.MEMBER
    can_set_admin = (
        viewer.role == TeamMembership.Role.OWNER
        and row.role != TeamMembership.Role.OWNER
        and row.role != TeamMembership.Role.ADMIN
    )
    can_set_member = (
        viewer.role == TeamMembership.Role.OWNER
        and row.role != TeamMembership.Role.OWNER
        and row.role != TeamMembership.Role.MEMBER
    )
    can_show_actions = can_leave or can_remove or can_set_admin or can_set_member
    return {
        "member": row,
        "can_leave": can_leave,
        "can_remove": can_remove,
        "can_set_admin": can_set_admin,
        "can_set_member": can_set_member,
        "can_show_actions": can_show_actions,
    }


def _team_overview_counts(*, team: Team, can_manage: bool):
    """汇总团队首页与标签页常用计数，减少重复查询。"""

    entry_stats = TOTPEntry.objects.filter(team=team, is_deleted=False).aggregate(
        entry_count=Count("id"),
        unassigned_entries_count=Count("id", filter=Q(asset__isnull=True)),
    )
    counts = {
        "member_count": TeamMembership.objects.filter(team=team).count(),
        "entry_count": entry_stats.get("entry_count") or 0,
        "unassigned_entries_count": entry_stats.get("unassigned_entries_count") or 0,
        "asset_total": TeamAsset.objects.filter(team=team).count(),
        "active_share_links": 0,
        "pending_invites_count": 0,
    }
    if can_manage:
        counts["active_share_links"] = OneTimeLink.active.filter(entry__team=team).count()
        counts["pending_invites_count"] = TeamInvitation.objects.filter(
            team=team,
            status=TeamInvitation.Status.PENDING,
        ).count()
    counts["assigned_entries_count"] = max(
        counts["entry_count"] - counts["unassigned_entries_count"],
        0,
    )
    return counts


def _team_active_link_panel_stats(*, team: Team):
    """聚合风险面板所需的分享链接统计，避免对同一 queryset 多次往返。"""

    stats = OneTimeLink.active.filter(entry__team=team).aggregate(
        active_share_links=Count("id"),
        latest_link_created_at=Max("created_at"),
        latest_link_viewed_at=Max("last_viewed_at"),
        viewed_links=Count("id", filter=Q(last_viewed_at__isnull=False)),
    )
    return {
        "active_share_links": stats.get("active_share_links") or 0,
        "latest_link_created_at": stats.get("latest_link_created_at"),
        "latest_link_viewed_at": stats.get("latest_link_viewed_at"),
        "has_link_views": bool(stats.get("viewed_links")),
    }


def _cleanup_team_asset_user_roles(*, team: Team, user_id: int):
    """成员离队后同步移除其在团队资产上的负责人/关注人标记。"""

    TeamAsset.owners.through.objects.filter(teamasset__team=team, user_id=user_id).delete()
    TeamAsset.watchers.through.objects.filter(teamasset__team=team, user_id=user_id).delete()


def _team_audit_ui_meta(action: str):
    if action in {
        TeamAudit.Action.LINKS_REVOKED_ALL,
        TeamAudit.Action.LINKS_REVOKE_REMINDER_SENT,
    }:
        return {"group": "链接", "variant": "danger", "priority": "high", "icon": "bi-link-45deg"}
    if action in {
        TeamAudit.Action.MEMBER_ROLE_CHANGED,
        TeamAudit.Action.MEMBER_REMOVED,
        TeamAudit.Action.MEMBER_LEFT,
    }:
        return {"group": "成员", "variant": "warning", "priority": "high", "icon": "bi-people"}
    if action in {
        TeamAudit.Action.INVITE_SENT,
        TeamAudit.Action.INVITE_UPDATED,
        TeamAudit.Action.INVITE_CANCELLED,
        TeamAudit.Action.INVITE_ACCEPTED,
        TeamAudit.Action.INVITE_DECLINED,
    }:
        return {"group": "邀请", "variant": "info", "priority": "normal", "icon": "bi-envelope"}
    if action in {TeamAudit.Action.TEAM_CREATED, TeamAudit.Action.TEAM_RENAMED}:
        return {"group": "团队", "variant": "secondary", "priority": "normal", "icon": "bi-building"}
    return {"group": "其他", "variant": "secondary", "priority": "normal", "icon": "bi-info-circle"}
@login_required
def add_entry(request):
    """添加单个 TOTP 条目。"""
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        group_id = request.POST.get("group_id") or ""
        team_id = (request.POST.get("team_id") or "").strip()
        asset_id = (request.POST.get("asset_id") or "").strip()
        secret = (request.POST.get("secret") or "").strip()

        if secret.lower().startswith("otpauth://"):
            # 兼容扫描二维码导出的 otpauth URL，自动解析名称与密钥
            label, s = parse_otpauth(secret)
            if not name and label:
                name = label
            secret = s
        secret = normalize_google_secret(secret)
        if not name or not secret:
            messages.error(request, "名称和密钥必填且需符合要求")
            return redirect("totp:list")
        if len(name) > ENTRY_NAME_MAX_LENGTH:
            messages.error(request, "名称过长")
            return redirect("totp:list")

        team = None
        group = None
        asset = None
        if team_id:
            membership = _get_team_membership(
                request.user, team_id, require_manage=True
            )
            team = membership.team
            if asset_id:
                try:
                    asset = TeamAsset.objects.get(pk=int(asset_id), team=team)
                except (TeamAsset.DoesNotExist, ValueError, TypeError):
                    asset = None
        if group_id:
            try:
                group = Group.objects.get(pk=int(group_id), user=request.user)
            except (Group.DoesNotExist, ValueError, TypeError):
                group = None
        if team is not None:
            group = None  # 团队空间下不复用个人分组
            if asset is None:
                asset = None

        if team is None:
            duplicate_qs = TOTPEntry.objects.filter(
                user=request.user, team__isnull=True, name=name
            )
        else:
            duplicate_qs = TOTPEntry.objects.filter(team=team, name=name)
        if duplicate_qs.exists():
            # 针对同一用户维持名称唯一，避免后续展示或分享时产生混淆
            messages.error(request, "相同空间内名称需唯一")
            return redirect("totp:list")

        enc = encrypt_str(secret)
        try:
            with transaction.atomic():
                entry = TOTPEntry.objects.create(
                    user=request.user,
                    team=team,
                    name=name,
                    group=group,
                    asset=asset,
                    secret_encrypted=enc,
                )
        except IntegrityError:
            messages.error(request, "相同空间内名称需唯一")
            return redirect("totp:list")
        log_entry_audit(
            entry,
            request.user,
            TOTPEntryAudit.Action.CREATED,
            new_value=name,
            metadata={
                "space": "team" if entry.team_id else "personal",
                "group": group.name if group else "",
                "asset": asset.name if asset else "",
            },
        )
        messages.success(request, "已添加")
        if entry.team_id:
            return redirect(f"{reverse('totp:list')}?space=team:{entry.team_id}")
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
        if len(name) > GROUP_NAME_MAX_LENGTH:
            messages.error(request, "分组名称过长")
            return redirect("totp:list")
        if Group.objects.filter(user=request.user, name=name).exists():
            messages.error(request, "分组名称已存在")
            return redirect("totp:list")
        try:
            with transaction.atomic():
                Group.objects.create(user=request.user, name=name)
        except IntegrityError:
            messages.error(request, "分组名称已存在")
            return redirect("totp:list")
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
    if len(new_name) > GROUP_NAME_MAX_LENGTH:
        return JsonResponse(
            {
                "ok": False,
                "error": "name_too_long",
                "message": "分组名称过长",
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
    try:
        with transaction.atomic():
            group.save(update_fields=["name", "updated_at"])
    except IntegrityError:
        return JsonResponse(
            {
                "ok": False,
                "error": "duplicate_name",
                "message": "分组名称已存在",
            },
            status=400,
        )

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
@require_POST
def delete_entry(request, pk: int):
    """删除指定的 TOTP 条目。"""
    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再删除")
        return _reauth_redirect(request)
    e = _get_entry_for_user(request.user, pk, require_manage=True)
    # 改为软删除：仅做标记并记录删除时间，数据进入回收站。
    e.is_deleted = True
    e.deleted_at = timezone.now()
    e.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
    log_entry_audit(
        e,
        request.user,
        TOTPEntryAudit.Action.TRASHED,
        old_value=e.name,
        metadata={
            "space": "team" if e.team_id else "personal",
        },
    )
    messages.success(request, "已移入回收站，可在 30 天内恢复")
    if e.team_id:
        return redirect(f"{reverse('totp:list')}?space=team:{e.team_id}")
    return redirect("totp:list")


@login_required
def trash_view(request):
    """展示当前用户的回收站列表。"""

    # 每次打开回收站时清理超过 30 天的条目，确保自动过期策略生效。
    TOTPEntry.purge_expired_trash(user=request.user)

    entry_qs = (
        TOTPEntry.all_objects.filter(is_deleted=True)
        .filter(
            Q(user=request.user, team__isnull=True)
            | Q(
                team__memberships__user=request.user,
                team__memberships__role__in=TEAM_MANAGER_ROLES,
            )
        )
        .select_related("group", "team")
        .prefetch_related(
            Prefetch(
                "team__memberships",
                queryset=TeamMembership.objects.filter(user=request.user),
            )
        )
        .order_by("-deleted_at")
        .distinct()
    )
    paginator = Paginator(entry_qs, 15)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    for entry in page_obj.object_list:
        entry.can_manage = entry.user_can_manage(request.user)
    return render(
        request,
        "totp/trash.html",
        {"entries": page_obj, "page_obj": page_obj},
    )


@login_required
@require_POST
def trash_bulk_action(request):
    """针对回收站条目执行批量操作。"""

    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再执行此操作")
        return _reauth_redirect(request)

    action = (request.POST.get("action") or "").strip()
    raw_ids = request.POST.getlist("selected")
    try:
        selected_ids = [int(pk) for pk in raw_ids if pk]
    except (TypeError, ValueError):
        selected_ids = []

    if not selected_ids:
        messages.info(request, "请先选择至少一条记录")
        return redirect("totp:trash")

    entries = list(
        TOTPEntry.all_objects.filter(is_deleted=True, pk__in=selected_ids)
        .filter(
            Q(user=request.user, team__isnull=True)
            | Q(
                team__memberships__user=request.user,
                team__memberships__role__in=TEAM_MANAGER_ROLES,
            )
        )
        .select_related("team")
        .distinct()
    )

    if not entries:
        messages.info(request, "所选记录不存在或已处理")
        return redirect("totp:trash")

    if action == "restore":
        conflicts = []
        now = timezone.now()
        personal_names = {e.name for e in entries if not e.team_id}
        team_names: set[str] = {e.name for e in entries if e.team_id}
        team_ids: set[int] = {e.team_id for e in entries if e.team_id}

        personal_conflicts: set[str] = set()
        if personal_names:
            personal_conflicts = set(
                TOTPEntry.objects.filter(
                    user=request.user,
                    team__isnull=True,
                    is_deleted=False,
                    name__in=personal_names,
                ).values_list("name", flat=True)
            )

        team_conflicts: set[tuple[int, str]] = set()
        if team_ids and team_names:
            team_conflicts = set(
                TOTPEntry.objects.filter(
                    team_id__in=team_ids,
                    is_deleted=False,
                    name__in=team_names,
                ).values_list("team_id", "name")
            )

        ids_to_restore: list[int] = []
        audit_rows = []
        for entry in entries:
            if entry.team_id:
                duplicate_exists = (entry.team_id, entry.name) in team_conflicts
            else:
                duplicate_exists = entry.name in personal_conflicts
            if duplicate_exists:
                conflicts.append(entry.name)
                continue
            ids_to_restore.append(entry.pk)
            audit_rows.append(
                TOTPEntryAudit(
                    entry_id=entry.pk,
                    actor=request.user,
                    action=TOTPEntryAudit.Action.RESTORED,
                    new_value=entry.name,
                    metadata={
                        "space": "team" if entry.team_id else "personal",
                        "bulk": True,
                    },
                )
            )

        restored = 0
        if ids_to_restore:
            with transaction.atomic():
                restored = (
                    TOTPEntry.all_objects.filter(pk__in=ids_to_restore, is_deleted=True)
                    .update(is_deleted=False, deleted_at=None, updated_at=now)
                )
                if audit_rows:
                    TOTPEntryAudit.objects.bulk_create(audit_rows)

        if restored:
            messages.success(request, f"已恢复 {restored} 条密钥")
        if conflicts:
            displayed = ", ".join(conflicts[:5])
            suffix = "" if len(conflicts) <= 5 else " 等"
            messages.warning(
                request,
                f"{len(conflicts)} 条因名称冲突未恢复：{displayed}{suffix}",
            )
        return redirect("totp:trash")

    if action == "delete":
        ids = [entry.pk for entry in entries]
        count = len(ids)
        audit_rows = [
            TOTPEntryAudit(
                entry_id=entry.pk,
                actor=request.user,
                action=TOTPEntryAudit.Action.DELETED,
                old_value=entry.name,
                metadata={
                    "space": "team" if entry.team_id else "personal",
                    "bulk": True,
                },
            )
            for entry in entries
        ]
        with transaction.atomic():
            if audit_rows:
                TOTPEntryAudit.objects.bulk_create(audit_rows)
            TOTPEntry.all_objects.filter(pk__in=ids).delete()
        messages.success(request, f"已永久删除 {count} 条密钥")
        return redirect("totp:trash")

    messages.error(request, "未知操作")
    return redirect("totp:trash")


@login_required
@require_POST
def restore_entry(request, pk: int):
    """从回收站恢复指定的 TOTP 条目。"""

    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再恢复")
        return _reauth_redirect(request)

    entry = _get_entry_for_user(
        request.user, pk, include_deleted=True, require_manage=True
    )
    if not entry.is_deleted:
        messages.info(request, "该条目已在列表中")
        if entry.team_id:
            return redirect(f"{reverse('totp:list')}?space=team:{entry.team_id}")
        return redirect("totp:list")

    # 如果已有同名有效密钥，恢复会因唯一性约束失败，这里提前做校验并给出提示。
    if entry.is_team_entry:
        duplicate_exists = TOTPEntry.objects.filter(
            team=entry.team, name=entry.name, is_deleted=False
        ).exclude(pk=entry.pk).exists()
    else:
        duplicate_exists = TOTPEntry.objects.filter(
            user=request.user,
            team__isnull=True,
            name=entry.name,
            is_deleted=False,
        ).exclude(pk=entry.pk).exists()
    if duplicate_exists:
        messages.error(request, "已存在同名密钥，无法恢复，请先修改现有密钥的名称")
        return redirect("totp:trash")

    entry.is_deleted = False
    entry.deleted_at = None
    entry.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
    log_entry_audit(
        entry,
        request.user,
        TOTPEntryAudit.Action.RESTORED,
        new_value=entry.name,
        metadata={
            "space": "team" if entry.team_id else "personal",
        },
    )
    messages.success(request, "密钥已成功恢复")
    if entry.team_id:
        return redirect(f"{reverse('totp:list')}?space=team:{entry.team_id}")
    return redirect("totp:list")
def _secret_preview(secret: str) -> str:
    """隐藏中间字符，仅展示密钥的头尾片段。"""

    if not secret:
        return ""
    if len(secret) <= 8:
        return secret
    return f"{secret[:4]}...{secret[-4:]}"
@login_required
def update_entry_group(request, pk: int):
    """更新指定条目的分组。"""

    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)

    entry = _get_entry_for_user(request.user, pk, require_manage=True)
    if entry.is_team_entry:
        return JsonResponse(
            {"error": "team_entry_not_supported", "message": "团队条目不支持个人分组"},
            status=400,
        )
    group_id = (request.POST.get("group_id") or "").strip()
    group = None
    if group_id:
        try:
            group = Group.objects.get(pk=int(group_id), user=request.user)
        except (Group.DoesNotExist, ValueError, TypeError):
            return JsonResponse({"error": "invalid_group"}, status=400)

    old_group = entry.group.name if entry.group else ""
    entry.group = group
    entry.save(update_fields=["group", "updated_at"])
    log_entry_audit(
        entry,
        request.user,
        TOTPEntryAudit.Action.GROUP_CHANGED,
        old_value=old_group,
        new_value=group.name if group else "",
        metadata={"space": "personal"},
    )

    return JsonResponse(
        {
            "success": True,
            "group_name": group.name if group else "未分组",
        }
    )


@login_required
def update_entry_asset(request, pk: int):
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)

    entry = _get_entry_for_user(request.user, pk, require_manage=True)
    if not entry.is_team_entry:
        return JsonResponse(
            {"error": "personal_entry_not_supported", "message": "个人条目不支持资产归属"},
            status=400,
        )
    asset_id = (request.POST.get("asset_id") or "").strip()
    asset = None
    if asset_id:
        try:
            asset = TeamAsset.objects.get(pk=int(asset_id), team=entry.team)
        except (TeamAsset.DoesNotExist, ValueError, TypeError):
            return JsonResponse({"error": "invalid_asset"}, status=400)

    old_asset = entry.asset.name if entry.asset else ""
    entry.asset = asset
    entry.save(update_fields=["asset", "updated_at"])
    log_entry_audit(
        entry,
        request.user,
        TOTPEntryAudit.Action.ASSET_CHANGED,
        old_value=old_asset,
        new_value=asset.name if asset else "",
        metadata={"space": "team", "team_id": entry.team_id},
    )
    return JsonResponse(
        {
            "success": True,
            "asset_name": asset.name if asset else "未归属",
        }
    )


@login_required
@require_POST
def rename_entry(request, pk: int):
    """修改指定 TOTP 条目的名称。"""

    entry = _get_entry_for_user(request.user, pk, require_manage=True)
    if entry.is_deleted:
        return JsonResponse(
            {"ok": False, "error": "deleted", "message": "条目已被删除"},
            status=400,
        )
    new_name = (request.POST.get("name") or "").strip()
    if not new_name:
        return JsonResponse(
            {
                "ok": False,
                "error": "empty_name",
                "message": "名称不能为空",
            },
            status=400,
        )
    if len(new_name) > ENTRY_NAME_MAX_LENGTH:
        return JsonResponse(
            {
                "ok": False,
                "error": "name_too_long",
                "message": "名称过长",
            },
            status=400,
        )

    if entry.is_team_entry:
        exists = (
            TOTPEntry.objects.filter(
                team=entry.team,
                name=new_name,
                is_deleted=False,
            )
            .exclude(pk=entry.pk)
            .exists()
        )
    else:
        exists = (
            TOTPEntry.objects.filter(
                user=request.user,
                team__isnull=True,
                name=new_name,
                is_deleted=False,
            )
            .exclude(pk=entry.pk)
            .exists()
        )
    if exists:
        return JsonResponse(
            {
                "ok": False,
                "error": "duplicate_name",
                "message": "名称已存在，请使用其他名称",
            },
            status=400,
        )

    old_name = entry.name
    entry.name = new_name
    try:
        with transaction.atomic():
            entry.save(update_fields=["name", "updated_at"])
    except IntegrityError:
        return JsonResponse(
            {
                "ok": False,
                "error": "duplicate_name",
                "message": "名称已存在，请使用其他名称",
            },
            status=400,
        )
    log_entry_audit(
        entry,
        request.user,
        TOTPEntryAudit.Action.RENAMED,
        old_value=old_name,
        new_value=new_name,
        metadata={
            "space": "team" if entry.team_id else "personal",
        },
    )

    return JsonResponse({"ok": True, "name": entry.name})

_views_assets = import_module(".views_assets", __package__)
team_asset_assign_entries = _views_assets.team_asset_assign_entries
team_asset_create = _views_assets.team_asset_create
team_asset_delete = _views_assets.team_asset_delete
team_asset_detail = _views_assets.team_asset_detail
team_asset_edit = _views_assets.team_asset_edit
team_asset_options = _views_assets.team_asset_options
team_asset_remove_entries = _views_assets.team_asset_remove_entries
team_assets = _views_assets.team_assets

_views_import_export = import_module(".views_import_export", __package__)
batch_import_apply = _views_import_export.batch_import_apply
batch_import_preview = _views_import_export.batch_import_preview
export_download = _views_import_export.export_download
export_encrypted_package = _views_import_export.export_encrypted_package
export_entries = _views_import_export.export_entries
export_offline_package = _views_import_export.export_offline_package

_views_sharing = import_module(".views_sharing", __package__)
batch_invalidate_one_time_links = _views_sharing.batch_invalidate_one_time_links
batch_invalidate_one_time_links_team = _views_sharing.batch_invalidate_one_time_links_team
batch_remind_one_time_links_team = _views_sharing.batch_remind_one_time_links_team
create_one_time_link = _views_sharing.create_one_time_link
external_totp = _views_sharing.external_totp
external_totp_tool = _views_sharing.external_totp_tool
invalidate_one_time_link = _views_sharing.invalidate_one_time_link
one_time_link_audit = _views_sharing.one_time_link_audit
one_time_link_audit_export = _views_sharing.one_time_link_audit_export
one_time_link_team_audit = _views_sharing.one_time_link_team_audit
one_time_link_team_audit_export = _views_sharing.one_time_link_team_audit_export
one_time_view = _views_sharing.one_time_view

_views_team = import_module(".views_team", __package__)
team_actions_panel = _views_team.team_actions_panel
team_add_member = _views_team.team_add_member
team_audit = _views_team.team_audit
team_audit_export = _views_team.team_audit_export
team_create = _views_team.team_create
team_home = _views_team.team_home
team_invitation_accept = _views_team.team_invitation_accept
team_invitation_cancel = _views_team.team_invitation_cancel
team_invitation_decline = _views_team.team_invitation_decline
team_remove_member = _views_team.team_remove_member
team_rename = _views_team.team_rename
team_revoke_all_share_links = _views_team.team_revoke_all_share_links
team_tab_fragment = _views_team.team_tab_fragment
team_update_member_role = _views_team.team_update_member_role
teams_overview = _views_team.teams_overview

del _views_assets
del _views_import_export
del _views_sharing
del _views_team
