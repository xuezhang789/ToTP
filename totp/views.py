import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, F, Q, Prefetch
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from . import importers
from .models import Group, OneTimeLink, Team, TeamInvitation, TeamMembership, TOTPEntry

UserModel = get_user_model()
from .utils import (
    decrypt_str,
    encrypt_str,
    normalize_google_secret,
    parse_otpauth,
    totp_code_base32,
)


EXTERNAL_TOTP_RATE_LIMIT = 20
EXTERNAL_TOTP_RATE_WINDOW_SECONDS = 60

TEAM_MANAGER_ROLES = (
    TeamMembership.Role.OWNER,
    TeamMembership.Role.ADMIN,
)


def _team_memberships_for_user(user):
    return list(
        TeamMembership.objects.filter(user=user)
        .select_related("team")
        .order_by("team__name")
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


def dashboard(request):
    """展示仪表盘，可匿名访问。"""

    stats = {}
    recent_entries = []
    memberships = []
    if request.user.is_authenticated:
        memberships = _team_memberships_for_user(request.user)
        team_ids = {m.team_id for m in memberships}
        # 登录用户访问仪表盘时也清理一次回收站，保证数据实时。
        TOTPEntry.purge_expired_trash(user=request.user)
        accessible_entries = (
            TOTPEntry.objects.for_user(request.user)
            .select_related("team", "group")
            .distinct()
        )
        today = timezone.localdate()
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
                filter=Q(created_at__date=today),
                distinct=True,
            ),
        )
        stats = {
            "total_entries": agg["total_entries"] or 0,
            "personal_entries": agg["personal_entries"] or 0,
            "shared_entries": agg["shared_entries"] or 0,
            "group_count": Group.objects.filter(user=request.user).count(),
            "team_count": len(team_ids),
            "today_added": agg["today_added_total"] or 0,
        }

        cycle_total = 30
        now = timezone.now()
        stats["current_cycle_total"] = cycle_total
        stats["current_cycle_remaining"] = cycle_total - (int(now.timestamp()) % cycle_total)

        recent_entries = list(
            accessible_entries.order_by("-created_at")
            .values(
                "name",
                "created_at",
                group_name=F("group__name"),
                team_name=F("team__name"),
            )[:5]
        )

    return render(
        request,
        "totp/dashboard.html",
        {
            "stats": stats,
            "recent_entries": recent_entries,
            "team_memberships": memberships,
        },
    )



@login_required
def list_view(request):
    """列出用户的所有 TOTP 条目。"""
    # 在展示列表前先顺带清理一下过期的回收站数据，保证统计准确。
    TOTPEntry.purge_expired_trash(user=request.user)

    memberships = _team_memberships_for_user(request.user)

    q = (request.GET.get("q") or "").strip()
    group_id = (request.GET.get("group") or "").strip()
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
        entry_qs = (
            TOTPEntry.objects.filter(team=selected_team)
            .select_related("team")
            .order_by("-created_at")
        )
        groups = []
    else:
        space = "personal"
        entry_qs = (
            TOTPEntry.objects.filter(user=request.user, team__isnull=True)
            .select_related("group")
            .order_by("-created_at")
        )
        if group_id == "0":
            entry_qs = entry_qs.filter(group__isnull=True)
        elif group_id:
            entry_qs = entry_qs.filter(group_id=group_id)
        groups = (
            Group.objects.filter(user=request.user)
            .annotate(
                entry_count=Count(
                    "entries",
                    filter=Q(entries__is_deleted=False, entries__team__isnull=True),
                )
            )
            .order_by("name")
        )

    if q:
        entry_qs = entry_qs.filter(name__icontains=q)

    entry_qs = entry_qs.select_related("group", "team").prefetch_related(
        Prefetch(
            "team__memberships",
            queryset=TeamMembership.objects.filter(user=request.user),
        )
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
            "team_memberships": memberships,
            "selected_space": space,
            "selected_team": selected_team,
            "selected_membership": selected_membership,
        },
    )


@login_required
def teams_overview(request):
    """展示团队列表及成员信息。"""

    teams = (
        Team.objects.filter(memberships__user=request.user)
        .annotate(
            member_count=Count("memberships", distinct=True),
            entry_count=Count(
                "entries",
                filter=Q(entries__is_deleted=False),
                distinct=True,
            ),
        )
        .prefetch_related(
            Prefetch(
                "memberships",
                queryset=TeamMembership.objects.select_related("user").order_by(
                    "role", "user__username"
                ),
            )
        )
        .order_by("name")
    )
    membership_map = {team.id: team.get_membership(request.user) for team in teams}
    role_labels = dict(TeamMembership.Role.choices)
    available_roles = [
        (TeamMembership.Role.MEMBER, role_labels[TeamMembership.Role.MEMBER]),
        (TeamMembership.Role.ADMIN, role_labels[TeamMembership.Role.ADMIN]),
    ]
    pending_invites = (
        TeamInvitation.objects.filter(
            team__in=teams, status=TeamInvitation.Status.PENDING
        )
        .select_related("invitee")
        .order_by("-created_at")
    )
    invites_by_team: dict[int, list[TeamInvitation]] = {}
    for invite in pending_invites:
        invites_by_team.setdefault(invite.team_id, []).append(invite)

    team_blocks = [
        {
            "team": team,
            "membership": membership_map.get(team.id),
            "member_count": team.member_count,
            "entry_count": team.entry_count,
            "pending_invites": invites_by_team.get(team.id, []),
        }
        for team in teams
    ]
    summary = {
        "team_total": len(team_blocks),
        "member_total": sum(block["member_count"] or 0 for block in team_blocks),
        "entry_total": sum(block["entry_count"] or 0 for block in team_blocks),
        "manageable": sum(
            1
            for block in team_blocks
            if block["membership"] and block["membership"].can_manage_entries
        ),
    }

    inbound_invitations = list(
        TeamInvitation.objects.filter(
            invitee=request.user, status=TeamInvitation.Status.PENDING
        )
        .select_related("team", "inviter")
        .order_by("-created_at")
    )
    return render(
        request,
        "totp/teams.html",
        {
            "team_blocks": team_blocks,
            "teams": teams,
            "membership_map": membership_map,
            "role_labels": role_labels,
            "available_roles": available_roles,
            "team_summary": summary,
            "incoming_invitations": inbound_invitations,
        },
    )


@login_required
@require_POST
def team_create(request):
    """创建新的团队空间。"""

    name = (request.POST.get("name") or "").strip()
    if not name:
        messages.error(request, "团队名称不能为空")
        return redirect("totp:teams")

    if Team.objects.filter(owner=request.user, name=name).exists():
        messages.error(request, "已存在同名团队，请更换名称")
        return redirect("totp:teams")

    with transaction.atomic():
        team = Team.objects.create(owner=request.user, name=name)
        TeamMembership.objects.create(
            team=team,
            user=request.user,
            role=TeamMembership.Role.OWNER,
        )

    messages.success(request, "团队已创建")
    return redirect("totp:teams")


@login_required
@require_POST
def team_add_member(request, team_id: int):
    """向团队添加成员或更新成员角色。"""

    membership = _get_team_membership(request.user, team_id, require_manage=True)
    identifier = (request.POST.get("identifier") or "").strip()
    if not identifier:
        messages.error(request, "请输入要邀请的用户名或邮箱")
        return redirect("totp:teams")

    target_user = (
        UserModel.objects.filter(username__iexact=identifier).first()
        or UserModel.objects.filter(email__iexact=identifier).first()
    )
    if not target_user:
        messages.error(request, "未找到对应的用户")
        return redirect("totp:teams")

    desired_role = request.POST.get("role") or TeamMembership.Role.MEMBER
    if desired_role not in dict(TeamMembership.Role.choices):
        desired_role = TeamMembership.Role.MEMBER

    if membership.role != TeamMembership.Role.OWNER:
        # 管理员仅可邀请普通成员
        desired_role = TeamMembership.Role.MEMBER

    team = membership.team

    existing_member = TeamMembership.objects.filter(team=team, user=target_user).first()
    if existing_member:
        messages.info(request, f"{target_user} 已在团队中")
        return redirect("totp:teams")

    pending_invite = TeamInvitation.objects.filter(
        team=team,
        invitee=target_user,
        status=TeamInvitation.Status.PENDING,
    ).first()
    if pending_invite:
        if membership.role == TeamMembership.Role.OWNER and pending_invite.role != desired_role:
            pending_invite.role = desired_role
            pending_invite.inviter = request.user
            pending_invite.save(update_fields=["role", "inviter"])
            messages.success(request, f"已更新对 {target_user} 的邀请角色")
        else:
            messages.info(request, f"已存在发送给 {target_user} 的待确认邀请")
        return redirect("totp:teams")

    TeamInvitation.objects.create(
        team=team,
        inviter=request.user,
        invitee=target_user,
        role=desired_role,
    )
    messages.success(request, f"已向 {target_user} 发送团队邀请，等待对方确认")
    return redirect("totp:teams")


@login_required
@require_POST
def team_update_member_role(request, team_id: int, member_id: int):
    """更新团队成员角色（仅拥有者）。"""

    membership = _get_team_membership(request.user, team_id, require_manage=True)
    if membership.role != TeamMembership.Role.OWNER:
        messages.error(request, "只有团队拥有者可以调整角色")
        return redirect("totp:teams")

    target = get_object_or_404(
        TeamMembership.objects.select_related("user"),
        pk=member_id,
        team=membership.team,
    )
    if target.role == TeamMembership.Role.OWNER:
        messages.error(request, "无法修改拥有者的角色")
        return redirect("totp:teams")

    new_role = request.POST.get("role") or TeamMembership.Role.MEMBER
    if new_role not in dict(TeamMembership.Role.choices):
        new_role = TeamMembership.Role.MEMBER
    if new_role == TeamMembership.Role.OWNER:
        messages.error(request, "暂不支持直接委任新的拥有者")
        return redirect("totp:teams")

    if target.role == new_role:
        messages.info(request, "角色未发生变化")
        return redirect("totp:teams")

    target.role = new_role
    target.save(update_fields=["role"])
    messages.success(request, f"{target.user} 的角色已更新")
    return redirect("totp:teams")


@login_required
@require_POST
def team_remove_member(request, team_id: int, member_id: int):
    """移除团队成员或主动退出团队。"""

    membership = _get_team_membership(request.user, team_id, require_manage=False)
    target = get_object_or_404(
        TeamMembership.objects.select_related("user"),
        pk=member_id,
        team=membership.team,
    )

    if target.role == TeamMembership.Role.OWNER:
        messages.error(request, "无法移除团队拥有者")
        return redirect("totp:teams")

    if target.user_id == request.user.id:
        # 允许管理员或成员退出团队
        target.delete()
        messages.success(request, "已退出团队")
        return redirect("totp:teams")

    if membership.role not in TEAM_MANAGER_ROLES:
        messages.error(request, "只有团队管理员或拥有者可以移除其他成员")
        return redirect("totp:teams")

    if membership.role != TeamMembership.Role.OWNER and target.role != TeamMembership.Role.MEMBER:
        messages.error(request, "管理员只能移除普通成员")
        return redirect("totp:teams")

    target.delete()
    messages.success(request, f"{target.user} 已被移出团队")
    return redirect("totp:teams")


@login_required
@require_POST
def team_invitation_accept(request, invitation_id: int):
    invitation = get_object_or_404(
        TeamInvitation.objects.select_related("team"),
        pk=invitation_id,
        invitee=request.user,
        status=TeamInvitation.Status.PENDING,
    )

    with transaction.atomic():
        membership, created = TeamMembership.objects.get_or_create(
            team=invitation.team,
            user=request.user,
            defaults={"role": invitation.role},
        )
        if not created and membership.role != invitation.role and invitation.role != TeamMembership.Role.MEMBER:
            membership.role = invitation.role
            membership.save(update_fields=["role"])
        invitation.status = TeamInvitation.Status.ACCEPTED
        invitation.responded_at = timezone.now()
        invitation.save(update_fields=["status", "responded_at"])

    messages.success(request, f"已加入 {invitation.team.name}")
    return redirect("totp:teams")


@login_required
@require_POST
def team_invitation_decline(request, invitation_id: int):
    invitation = get_object_or_404(
        TeamInvitation.objects.select_related("team"),
        pk=invitation_id,
        invitee=request.user,
        status=TeamInvitation.Status.PENDING,
    )
    invitation.status = TeamInvitation.Status.DECLINED
    invitation.responded_at = timezone.now()
    invitation.save(update_fields=["status", "responded_at"])
    messages.info(request, f"已拒绝加入 {invitation.team.name}")
    return redirect("totp:teams")


@login_required
@require_POST
def team_invitation_cancel(request, invitation_id: int):
    invitation = get_object_or_404(
        TeamInvitation.objects.select_related("team"),
        pk=invitation_id,
    )
    membership = _get_team_membership(request.user, invitation.team_id, require_manage=True)
    if not invitation.is_pending:
        messages.info(request, "该邀请已处理")
        return redirect("totp:teams")
    invitation.status = TeamInvitation.Status.CANCELLED
    invitation.responded_at = timezone.now()
    invitation.save(update_fields=["status", "responded_at"])
    messages.success(request, "已取消邀请")
    return redirect("totp:teams")


@login_required
def add_entry(request):
    """添加单个 TOTP 条目。"""
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        group_id = request.POST.get("group_id") or ""
        team_id = (request.POST.get("team_id") or "").strip()
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

        team = None
        group = None
        if team_id:
            membership = _get_team_membership(
                request.user, team_id, require_manage=True
            )
            team = membership.team
        if group_id:
            try:
                group = Group.objects.get(pk=int(group_id), user=request.user)
            except (Group.DoesNotExist, ValueError, TypeError):
                group = None
        if team is not None:
            group = None  # 团队空间下不复用个人分组

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
        entry = TOTPEntry.objects.create(
            user=request.user,
            team=team,
            name=name,
            group=group,
            secret_encrypted=enc,
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
    e = _get_entry_for_user(request.user, pk, require_manage=True)
    # 改为软删除：仅做标记并记录删除时间，数据进入回收站。
    e.is_deleted = True
    e.deleted_at = timezone.now()
    e.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
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
            Q(user=request.user)
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

    action = (request.POST.get("action") or "").strip()
    raw_ids = request.POST.getlist("selected")
    try:
        selected_ids = [int(pk) for pk in raw_ids if pk]
    except (TypeError, ValueError):
        selected_ids = []

    if not selected_ids:
        messages.info(request, "请先选择至少一条记录")
        return redirect("totp:trash")

    entries = []
    for entry_id in selected_ids:
        try:
            entry = _get_entry_for_user(
                request.user,
                entry_id,
                include_deleted=True,
                require_manage=True,
            )
        except Http404:
            continue
        if entry.is_deleted:
            entries.append(entry)

    if not entries:
        messages.info(request, "所选记录不存在或已处理")
        return redirect("totp:trash")

    if action == "restore":
        restored = 0
        conflicts = []
        for entry in entries:
            if entry.is_team_entry:
                duplicate_exists = TOTPEntry.objects.filter(
                    team=entry.team,
                    name=entry.name,
                    is_deleted=False,
                ).exclude(pk=entry.pk).exists()
            else:
                duplicate_exists = TOTPEntry.objects.filter(
                    user=request.user,
                    team__isnull=True,
                    name=entry.name,
                    is_deleted=False,
                ).exclude(pk=entry.pk).exists()

            if duplicate_exists:
                conflicts.append(entry.name)
                continue
            entry.is_deleted = False
            entry.deleted_at = None
            entry.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
            restored += 1

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
        count = len(entries)
        TOTPEntry.all_objects.filter(pk__in=[entry.pk for entry in entries]).delete()
        messages.success(request, f"已永久删除 {count} 条密钥")
        return redirect("totp:trash")

    messages.error(request, "未知操作")
    return redirect("totp:trash")


@login_required
def restore_entry(request, pk: int):
    """从回收站恢复指定的 TOTP 条目。"""

    if request.method != "POST":
        messages.error(request, "请求方式不正确")
        return redirect("totp:trash")

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
    messages.success(request, "密钥已成功恢复")
    if entry.team_id:
        return redirect(f"{reverse('totp:list')}?space=team:{entry.team_id}")
    return redirect("totp:list")



@login_required
@require_POST
def batch_import_preview(request):
    """上传文件或文本后，返回解析结果供前端预览。"""

    try:
        space, target_team, target_label = _resolve_import_target(
            request.user, request.POST.get("space"), require_manage=True
        )
    except ValueError as exc:
        return JsonResponse({"ok": False, "errors": [str(exc)]}, status=400)

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
        # 预先查询名称，避免在循环中重复命中数据库
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
        else:
            group_value = entry.group
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

    try:
        space, target_team, target_label = _resolve_import_target(
            request.user, payload.get("space"), require_manage=True
        )
    except ValueError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    raw_entries = payload.get("entries") or []
    if not isinstance(raw_entries, list) or not raw_entries:
        return JsonResponse({"ok": False, "error": "缺少有效的导入数据"}, status=400)

    entries: list[importers.ParsedEntry] = []
    errors: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(raw_entries, 1):
        # 逐条校验名称、分组和密钥，保证落库前格式正确
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
            # 标准化后的数据统一封装成 ParsedEntry，便于后续批量处理
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

    created, skipped = _apply_import_entries(request.user, entries, team=target_team)

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


def _apply_import_entries(user, entries, *, team=None):
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
                    name=entry.name,
                    secret_encrypted=encrypt_str(entry.secret),
                )
            )
            existing_names.add(entry.name)

        if to_create:
            TOTPEntry.objects.bulk_create(to_create)
            created = len(to_create)

        return created, skipped

    # 一次性查出需要的分组，缺失的分组批量创建
    group_names = sorted({entry.group for entry in entries if entry.group})
    # 预拉取已有分组，缺失的分组统一创建，避免逐条查询
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
        # 先查出当前数据库中已有的名称，导入时直接过滤重复
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
            # 使用 bulk_create 批量写入以提升导入性能
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

    queryset = TOTPEntry.objects.filter(
        user=request.user,
        team__isnull=True,
        is_deleted=False,
    ).select_related("group").order_by("name")

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

    entries = []
    for entry in queryset:
        secret = decrypt_str(entry.secret_encrypted)
        issuer = entry.group.name if entry.group else request.user.username
        entries.append(
            {
                "name": entry.name,
                "secret": secret,
                "group": entry.group.name if entry.group else "",
                "period": 30,
                "digits": 6,
                "issuer": issuer,
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

    entry.name = new_name
    entry.save(update_fields=["name", "updated_at"])

    return JsonResponse({"ok": True, "name": entry.name})


@login_required
def one_time_link_audit(request):
    """展示当前用户创建的一次性访问链接审计信息。"""

    queryset = (
        OneTimeLink.objects.filter(created_by=request.user)
        .select_related("entry", "entry__group")
        .order_by("-created_at")
    )

    paginator = Paginator(queryset, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    status_labels = {
        "active": "可用",
        "expired": "已过期",
        "used": "已用尽",
        "revoked": "已撤销",
        "deleted": "关联密钥已删除",
    }
    badge_classes = {
        "active": "success",
        "expired": "secondary",
        "used": "warning",
        "revoked": "danger",
        "deleted": "danger",
    }

    records = []
    for link in page_obj.object_list:
        status_key = "active" if link.is_active else _resolve_link_inactive_reason(link)
        records.append(
            {
                "link": link,
                "status_key": status_key,
                "status_label": status_labels.get(status_key, "未知状态"),
                "badge_class": badge_classes.get(status_key, "secondary"),
                "remaining_views": max(0, link.max_views - link.view_count),
            }
    )

    active_count = OneTimeLink.active.filter(created_by=request.user).count()

    return render(
        request,
        "totp/one_time_links.html",
        {
            "records": records,
            "page_obj": page_obj,
            "total_count": paginator.count,
            "active_count": active_count,
        },
    )


@login_required
@require_POST
def create_one_time_link(request, pk: int):
    """为指定密钥生成一次性只读访问链接。"""

    entry = _get_entry_for_user(request.user, pk, require_manage=True)
    if entry.is_deleted:
        return JsonResponse(
            {"ok": False, "error": "deleted", "message": "条目已删除"},
            status=400,
        )

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
        # 最多重试 6 次生成随机 token，以避免哈希碰撞
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

    path = reverse("totp:one_time_view", args=[token])
    origin = request.headers.get("Origin")
    if not origin:
        # 如果缺少 Origin 头（例如旧浏览器），使用请求 scheme + host 拼装访问前缀
        origin = f"{request.scheme}://{request.get_host()}"
    url = f"{origin}{path}"
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


@never_cache
@require_GET
def external_totp(request):
    """根据链接参数返回动态验证码，供未登录场景使用。"""

    if not _external_totp_rate_limit_allow(request):
        return _external_totp_response(
            request,
            ok=False,
            message="请求过于频繁，请稍后再试",
            status_code=429,
        )

    secret_raw = (request.GET.get("secret") or "").strip()
    if not secret_raw:
        return _external_totp_response(request, ok=False, message="缺少 secret 参数")

    secret = normalize_google_secret(secret_raw)
    if not secret:
        return _external_totp_response(request, ok=False, message="密钥格式无效")

    digits = request.GET.get("digits") or "6"
    try:
        digits_int = int(digits)
    except (TypeError, ValueError):
        digits_int = 6
    # 限制验证码长度在合理范围内，避免异常参数导致计算失败
    digits_int = min(max(digits_int, 4), 8)

    period = request.GET.get("period") or "30"
    try:
        period_int = int(period)
    except (TypeError, ValueError):
        period_int = 30
    # 周期最短 15 秒，最长 120 秒，保持兼容常见 TOTP 设置
    period_int = min(max(period_int, 15), 120)

    timestamp = int(timezone.now().timestamp())
    code, remaining = totp_code_base32(
        secret,
        digits=digits_int,
        period=period_int,
        timestamp=timestamp,
    )

    payload = {
        "ok": True,
        "code": code,
        "remaining": remaining,
        "period": period_int,
        "digits": digits_int,
        "timestamp": timestamp,
        "secret_preview": _secret_preview(secret),
    }

    return _external_totp_response(request, **payload)


@never_cache
@require_GET
def external_totp_tool(request):
    """展示一个外部验证码生成工具页面。"""

    digits = (request.GET.get("digits") or "6").strip()
    period = (request.GET.get("period") or "30").strip()
    context = {
        "prefill_secret": (request.GET.get("secret") or "").strip(),
        "prefill_digits": digits,
        "prefill_period": period,
        "digits_choices": ["4", "5", "6", "7", "8"],
        "period_choices": ["15", "20", "30", "45", "60", "90", "120"],
    }
    return render(request, "totp/external_tool.html", context)


def one_time_view(request, token: str):
    """展示一次性访问链接的验证码。"""

    token = (token or "").strip()
    if not token:
        return _render_one_time_invalid(request, reason="not_found")

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    try:
        with transaction.atomic():
            # select_for_update 保证同一链接在并发访问时顺序处理，避免剩余次数被同时扣减
            link = (
                OneTimeLink.objects.select_for_update()
                .select_related("entry", "entry__user", "entry__group")
                .get(token_hash=token_hash)
            )

            if not link.is_active:
                reason = _resolve_link_inactive_reason(link)
                return _render_one_time_invalid(request, reason=reason)

            try:
                # mark_view 内部更新查看次数，如果超过上限会抛出异常
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


def _external_totp_rate_limit_allow(request) -> bool:
    """简单的 IP 级频率限制，限制单位时间内的访问次数。"""

    ip = _client_ip_from_request(request)
    cache_key = f"totp:external_totp:rl:{ip}"
    if cache.add(cache_key, 1, EXTERNAL_TOTP_RATE_WINDOW_SECONDS):
        return True
    try:
        count = cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 1, EXTERNAL_TOTP_RATE_WINDOW_SECONDS)
        return True
    return count <= EXTERNAL_TOTP_RATE_LIMIT


def _client_ip_from_request(request) -> str:
    forward = request.META.get("HTTP_X_FORWARDED_FOR")
    if forward:
        return forward.split(",")[0].strip() or "unknown"
    return request.META.get("REMOTE_ADDR") or "unknown"


def _external_totp_response(
    request,
    *,
    ok: bool,
    message: str | None = None,
    status_code: int | None = None,
    **extra,
):
    wants_json = request.GET.get("format") == "json"
    if not wants_json:
        accept = request.headers.get("Accept", "")
        if "application/json" in accept and "text/html" not in accept:
            # 尊重客户端 Accept 头部，如果明确只接受 JSON 则直接返回 JSON 响应
            wants_json = True

    payload = {"ok": ok}
    if message:
        payload["message"] = message
    payload.update(extra)

    default_status = 200 if ok else 400
    status = status_code or default_status
    if wants_json:
        return JsonResponse(payload, status=status)

    params = request.GET.copy()
    params["format"] = "json"
    json_url = request.build_absolute_uri(
        "?" + params.urlencode()
    ) if params else request.build_absolute_uri("?format=json")

    if request.GET:
        refresh_url = request.build_absolute_uri("?" + request.GET.urlencode())
    else:
        refresh_url = request.build_absolute_uri()

    context = {
        "ok": ok,
        "message": message,
        "code": payload.get("code"),
        "remaining": payload.get("remaining"),
        "period": payload.get("period"),
        "digits": payload.get("digits"),
        "timestamp": payload.get("timestamp"),
        "secret_preview": payload.get("secret_preview"),
        "refresh_url": refresh_url,
        "json_url": json_url,
    }
    if ok and status_code is None:
        response_status = 200
    else:
        response_status = status
    return render(
        request,
        "totp/external_totp.html",
        context,
        status=response_status,
    )
