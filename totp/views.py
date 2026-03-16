import hashlib
import json
import secrets
import csv
import base64
import os
import io
from datetime import datetime, time, timedelta
from urllib.parse import quote

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.paginator import Paginator
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Q, Prefetch
from django.http import Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import importers
from project.utils import client_ip
from .models import (
    Group,
    OneTimeLink,
    Team,
    TeamAudit,
    TeamInvitation,
    TeamMembership,
    TOTPEntry,
    TOTPEntryAudit,
    log_entry_audit,
    log_team_audit,
)
from .querysets import entries_queryset_for_list, teams_queryset_for_overview

UserModel = get_user_model()
from .utils import (
    decrypt_str,
    encrypt_str,
    normalize_google_secret,
    parse_otpauth,
    totp_code_base32,
)


EXPORT_REAUTH_MAX_AGE_SECONDS = 5 * 60
TEAM_ONE_TIME_LINK_ACTIVE_LIMIT = 50
TEAM_ONE_TIME_LINK_MAX_DURATION_MINUTES = 30

TEAM_MANAGER_ROLES = (
    TeamMembership.Role.OWNER,
    TeamMembership.Role.ADMIN,
)

PURGE_TRASH_THROTTLE_SECONDS = 60 * 60  # 每位用户至多每小时触发一次回收站清理


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
    return JsonResponse(
        {
            "ok": False,
            "error": "reauth_required",
            "redirect": f"{reverse('accounts:reauth')}?next={quote(reverse('totp:list'))}",
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

    q = (request.GET.get("q") or "").strip()
    teams = teams_queryset_for_overview(user=request.user, q=q)
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

    team_ids = [team.id for team in teams]
    share_links_by_team = {}
    if team_ids:
        share_links_by_team = {
            row["entry__team_id"]: row["cnt"]
            for row in OneTimeLink.active.filter(entry__team_id__in=team_ids)
            .values("entry__team_id")
            .annotate(cnt=Count("id"))
        }

    team_blocks = [
        {
            "team": team,
            "membership": membership_map.get(team.id),
            "member_count": team.member_count,
            "entry_count": team.entry_count,
            "pending_invites": invites_by_team.get(team.id, []),
            "can_manage": bool(membership_map.get(team.id) and membership_map.get(team.id).can_manage_entries),
            "active_share_links": share_links_by_team.get(team.id, 0),
        }
        for team in teams
    ]
    team_blocks.sort(key=lambda b: (not b["can_manage"], (b["team"].name or "").lower()))
    manageable_blocks = [b for b in team_blocks if b["can_manage"]]
    readonly_blocks = [b for b in team_blocks if not b["can_manage"]]
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
            "q": q,
            "manageable_blocks": manageable_blocks,
            "readonly_blocks": readonly_blocks,
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
        log_team_audit(
            team,
            request.user,
            TeamAudit.Action.TEAM_CREATED,
            old_value="",
            new_value=team.name,
            metadata={"team_id": team.id},
        )

    messages.success(request, "团队已创建")
    return redirect("totp:teams")


@login_required
@require_POST
def team_rename(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team

    name = (request.POST.get("name") or "").strip()
    if not name:
        messages.error(request, "团队名称不能为空")
        return redirect("totp:teams")
    if len(name) > 80:
        messages.error(request, "团队名称过长")
        return redirect("totp:teams")

    if Team.objects.filter(owner=team.owner, name=name).exclude(pk=team.pk).exists():
        messages.error(request, "已存在同名团队，请更换名称")
        return redirect("totp:teams")

    if team.name == name:
        messages.info(request, "团队名称未发生变化")
        return redirect("totp:teams")

    old_name = team.name
    team.name = name
    try:
        team.save(update_fields=["name"])
    except IntegrityError:
        messages.error(request, "已存在同名团队，请更换名称")
        return redirect("totp:teams")

    log_team_audit(
        team,
        request.user,
        TeamAudit.Action.TEAM_RENAMED,
        old_value=old_name,
        new_value=name,
        metadata={"team_id": team.id},
    )
    messages.success(request, "团队名称已更新")
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
            old_role = pending_invite.role
            pending_invite.role = desired_role
            pending_invite.inviter = request.user
            pending_invite.save(update_fields=["role", "inviter"])
            log_team_audit(
                team,
                request.user,
                TeamAudit.Action.INVITE_UPDATED,
                target_user=target_user,
                old_value=old_role,
                new_value=desired_role,
                metadata={"invitation_id": pending_invite.id},
            )
            messages.success(request, f"已更新对 {target_user} 的邀请角色")
        else:
            messages.info(request, f"已存在发送给 {target_user} 的待确认邀请")
        return redirect("totp:teams")

    invitation = TeamInvitation.objects.create(
        team=team,
        inviter=request.user,
        invitee=target_user,
        role=desired_role,
    )
    log_team_audit(
        team,
        request.user,
        TeamAudit.Action.INVITE_SENT,
        target_user=target_user,
        old_value="",
        new_value=desired_role,
        metadata={"invitation_id": invitation.id},
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

    old_role = target.role
    target.role = new_role
    target.save(update_fields=["role"])
    log_team_audit(
        membership.team,
        request.user,
        TeamAudit.Action.MEMBER_ROLE_CHANGED,
        target_user=target.user,
        old_value=old_role,
        new_value=new_role,
        metadata={"membership_id": target.id},
    )
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
        log_team_audit(
            membership.team,
            request.user,
            TeamAudit.Action.MEMBER_LEFT,
            target_user=request.user,
            metadata={"membership_id": target.id},
        )
        target.delete()
        messages.success(request, "已退出团队")
        return redirect("totp:teams")

    if membership.role not in TEAM_MANAGER_ROLES:
        messages.error(request, "只有团队管理员或拥有者可以移除其他成员")
        return redirect("totp:teams")

    if membership.role != TeamMembership.Role.OWNER and target.role != TeamMembership.Role.MEMBER:
        messages.error(request, "管理员只能移除普通成员")
        return redirect("totp:teams")

    log_team_audit(
        membership.team,
        request.user,
        TeamAudit.Action.MEMBER_REMOVED,
        target_user=target.user,
        old_value=target.role,
        metadata={"membership_id": target.id},
    )
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

    log_team_audit(
        invitation.team,
        request.user,
        TeamAudit.Action.INVITE_ACCEPTED,
        target_user=request.user,
        new_value=invitation.role,
        metadata={"invitation_id": invitation.id},
    )
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
    log_team_audit(
        invitation.team,
        request.user,
        TeamAudit.Action.INVITE_DECLINED,
        target_user=request.user,
        new_value=invitation.role,
        metadata={"invitation_id": invitation.id},
    )
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
    log_team_audit(
        invitation.team,
        request.user,
        TeamAudit.Action.INVITE_CANCELLED,
        target_user=invitation.invitee,
        new_value=invitation.role,
        metadata={"invitation_id": invitation.id},
    )
    messages.success(request, "已取消邀请")
    return redirect("totp:teams")


@login_required
def team_audit(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team

    action = (request.GET.get("action") or "").strip()
    q = (request.GET.get("q") or "").strip()
    actor_raw = (request.GET.get("actor") or "").strip()
    target_raw = (request.GET.get("target") or "").strip()

    queryset = TeamAudit.objects.filter(team=team).select_related(
        "actor", "target_user"
    )
    if action and action in dict(TeamAudit.Action.choices):
        queryset = queryset.filter(action=action)
    if actor_raw:
        try:
            queryset = queryset.filter(actor_id=int(actor_raw))
        except (TypeError, ValueError):
            pass
    if target_raw:
        try:
            queryset = queryset.filter(target_user_id=int(target_raw))
        except (TypeError, ValueError):
            pass
    if q:
        queryset = queryset.filter(
            Q(actor__username__icontains=q)
            | Q(actor__email__icontains=q)
            | Q(target_user__username__icontains=q)
            | Q(target_user__email__icontains=q)
            | Q(old_value__icontains=q)
            | Q(new_value__icontains=q)
        )

    paginator = Paginator(queryset, 30)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    actor_options = (
        TeamAudit.objects.filter(team=team, actor__isnull=False)
        .values("actor_id", "actor__username")
        .distinct()
        .order_by("actor__username")
    )
    target_options = (
        TeamAudit.objects.filter(team=team, target_user__isnull=False)
        .values("target_user_id", "target_user__username")
        .distinct()
        .order_by("target_user__username")
    )
    return render(
        request,
        "totp/team_audit.html",
        {
            "team": team,
            "membership": membership,
            "page_obj": page_obj,
            "records": page_obj.object_list,
            "action_choices": TeamAudit.Action.choices,
            "selected_action": action,
            "q": q,
            "actor_options": actor_options,
            "target_options": target_options,
            "selected_actor": actor_raw,
            "selected_target": target_raw,
        },
    )


@login_required
@never_cache
@require_GET
def team_audit_export(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team

    action = (request.GET.get("action") or "").strip()
    q = (request.GET.get("q") or "").strip()
    actor_raw = (request.GET.get("actor") or "").strip()
    target_raw = (request.GET.get("target") or "").strip()

    queryset = (
        TeamAudit.objects.filter(team=team)
        .select_related("actor", "target_user")
        .only(
            "created_at",
            "action",
            "actor_id",
            "actor__username",
            "target_user_id",
            "target_user__username",
            "old_value",
            "new_value",
            "metadata",
        )
    )
    if action and action in dict(TeamAudit.Action.choices):
        queryset = queryset.filter(action=action)
    if actor_raw:
        try:
            queryset = queryset.filter(actor_id=int(actor_raw))
        except (TypeError, ValueError):
            pass
    if target_raw:
        try:
            queryset = queryset.filter(target_user_id=int(target_raw))
        except (TypeError, ValueError):
            pass
    if q:
        queryset = queryset.filter(
            Q(actor__username__icontains=q)
            | Q(actor__email__icontains=q)
            | Q(target_user__username__icontains=q)
            | Q(target_user__email__icontains=q)
            | Q(old_value__icontains=q)
            | Q(new_value__icontains=q)
        )

    filename = timezone.now().strftime(f"team-audit-{team.id}-%Y%m%d-%H%M%S.csv")
    quoted = quote(filename)
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    response.write("\ufeff")
    writer = csv.writer(response)
    writer.writerow(["时间", "动作", "操作人", "目标用户", "旧值", "新值", "详情"])
    for idx, record in enumerate(queryset.order_by("-created_at").iterator(chunk_size=1000)):
        if idx >= 20000:
            break
        actor_label = record.actor.username if record.actor_id else "系统"
        target_label = record.target_user.username if record.target_user_id else ""
        writer.writerow(
            [
                record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                record.get_action_display(),
                actor_label,
                target_label,
                record.old_value,
                record.new_value,
                json.dumps(record.metadata or {}, ensure_ascii=False),
            ]
        )
    return response


@login_required
@require_POST
def team_revoke_all_share_links(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    if not _has_recent_reauth(request):
        messages.info(request, "为保障安全，请先确认密码后再执行此操作")
        return _reauth_redirect(request)

    now = timezone.now()
    queryset = OneTimeLink.active.filter(entry__team=team)
    updated = queryset.update(revoked_at=now)
    if not updated:
        messages.info(request, "当前没有需要撤销的有效分享链接")
        return redirect("totp:teams")
    log_team_audit(
        team,
        request.user,
        TeamAudit.Action.LINKS_REVOKED_ALL,
        metadata={"count": updated},
    )
    messages.success(request, f"已撤销 {updated} 条有效分享链接")
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
        log_entry_audit(
            entry,
            request.user,
            TOTPEntryAudit.Action.CREATED,
            new_value=name,
            metadata={
                "space": "team" if entry.team_id else "personal",
                "group": group.name if group else "",
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
            Q(user=request.user)
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
def restore_entry(request, pk: int):
    """从回收站恢复指定的 TOTP 条目。"""

    if request.method != "POST":
        messages.error(request, "请求方式不正确")
        return redirect("totp:trash")

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

    if not _has_recent_reauth(request):
        return _reauth_json(request)

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

    with transaction.atomic():
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
                                metadata={"space": "team", "import": True},
                            )
                            for created_entry in created_entries
                        ]
                    )

            return created, skipped

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


def _secret_preview(secret: str) -> str:
    """隐藏中间字符，仅展示密钥的头尾片段。"""

    if not secret:
        return ""
    if len(secret) <= 8:
        return secret
    return f"{secret[:4]}...{secret[-4:]}"



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

    response = StreamingHttpResponse(row_stream(), content_type="text/plain; charset=utf-8")
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
            f"密钥数量过多（{total} 条），为避免导出时占用过多资源，单次最多导出 {limit} 条。请减少条目数量或分批处理后再试。",
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
            f"密钥数量过多（{total} 条），离线包会包含所有密钥并占用较大内存，单次最多导出 {limit} 条。请减少条目数量或分批处理后再试。",
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

    context = {
        "generated_at": generated_at,
        "owner": request.user,
        "entries_payload": entries_payload,
        "entry_count": len(entries_payload),
    }

    response = render(request, "totp/offline_package.html", context)
    response["Content-Type"] = "text/html; charset=utf-8"
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    if audit_rows:
        TOTPEntryAudit.objects.bulk_create(audit_rows)
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

    old_name = entry.name
    entry.name = new_name
    entry.save(update_fields=["name", "updated_at"])
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


@login_required
def one_time_link_audit(request):
    """展示当前用户创建的一次性访问链接审计信息。"""

    now = timezone.now()
    status = (request.GET.get("status") or "").strip()
    space = (request.GET.get("space") or "").strip()
    team_id = (request.GET.get("team") or "").strip()
    q = (request.GET.get("q") or "").strip()

    queryset = OneTimeLink.objects.filter(created_by=request.user).select_related(
        "entry", "entry__group", "entry__team"
    )
    if q:
        queryset = queryset.filter(
            Q(entry__name__icontains=q)
            | Q(note__icontains=q)
            | Q(entry__team__name__icontains=q)
        )
    if space == "personal":
        queryset = queryset.filter(entry__team__isnull=True)
    elif space == "team":
        queryset = queryset.filter(entry__team__isnull=False)
        if team_id.isdigit():
            queryset = queryset.filter(entry__team_id=int(team_id))
    if status == "active":
        queryset = queryset.filter(
            expires_at__gt=now,
            view_count__lt=F("max_views"),
            entry__is_deleted=False,
            revoked_at__isnull=True,
        )
    elif status == "revoked":
        queryset = queryset.filter(revoked_at__isnull=False)
    elif status == "deleted":
        queryset = queryset.filter(entry__is_deleted=True)
    elif status == "used":
        queryset = queryset.filter(revoked_at__isnull=True, view_count__gte=F("max_views"))
    elif status == "expired":
        queryset = queryset.filter(
            revoked_at__isnull=True,
            view_count__lt=F("max_views"),
            expires_at__lte=now,
        )

    queryset = queryset.order_by("-created_at")

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
    params = request.GET.copy()
    params.pop("page", None)
    querystring = params.urlencode()
    page_prefix = f"{querystring}&" if querystring else ""
    memberships = _team_memberships_for_user(request.user)

    return render(
        request,
        "totp/one_time_links.html",
        {
            "records": records,
            "page_obj": page_obj,
            "total_count": paginator.count,
            "active_count": active_count,
            "filters": {
                "status": status,
                "space": space,
                "team": team_id,
                "q": q,
            },
            "querystring": querystring,
            "page_prefix": page_prefix,
            "team_memberships": memberships,
            "is_team_audit": False,
            "export_url": reverse("totp:one_time_audit_export"),
            "batch_invalidate_url": reverse("totp:one_time_batch_invalidate"),
            "batch_remind_url": "",
        },
    )


@login_required
@never_cache
@require_GET
def one_time_link_audit_export(request):
    now = timezone.now()
    status = (request.GET.get("status") or "").strip()
    space = (request.GET.get("space") or "").strip()
    team_id = (request.GET.get("team") or "").strip()
    q = (request.GET.get("q") or "").strip()

    queryset = OneTimeLink.objects.filter(created_by=request.user).select_related(
        "entry", "entry__group", "entry__team"
    )
    if q:
        queryset = queryset.filter(
            Q(entry__name__icontains=q)
            | Q(note__icontains=q)
            | Q(entry__team__name__icontains=q)
        )
    if space == "personal":
        queryset = queryset.filter(entry__team__isnull=True)
    elif space == "team":
        queryset = queryset.filter(entry__team__isnull=False)
        if team_id.isdigit():
            queryset = queryset.filter(entry__team_id=int(team_id))
    if status == "active":
        queryset = queryset.filter(
            expires_at__gt=now,
            view_count__lt=F("max_views"),
            entry__is_deleted=False,
            revoked_at__isnull=True,
        )
    elif status == "revoked":
        queryset = queryset.filter(revoked_at__isnull=False)
    elif status == "deleted":
        queryset = queryset.filter(entry__is_deleted=True)
    elif status == "used":
        queryset = queryset.filter(revoked_at__isnull=True, view_count__gte=F("max_views"))
    elif status == "expired":
        queryset = queryset.filter(
            revoked_at__isnull=True,
            view_count__lt=F("max_views"),
            expires_at__lte=now,
        )

    queryset = queryset.order_by("-created_at")

    def stream_rows():
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "link_id",
                "entry_name",
                "space",
                "team",
                "status",
                "created_at",
                "expires_at",
                "max_views",
                "view_count",
                "remaining_views",
                "note",
                "first_viewed_at",
                "last_viewed_at",
                "last_view_ip",
                "last_view_user_agent",
                "revoked_at",
            ]
        )
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)

        for link in queryset.iterator(chunk_size=200):
            status_key = "active" if link.is_active else _resolve_link_inactive_reason(link)
            team_name = link.entry.team.name if link.entry.team_id else ""
            space_label = "team" if link.entry.team_id else "personal"
            writer.writerow(
                [
                    link.id,
                    link.entry.name,
                    space_label,
                    team_name,
                    status_key,
                    link.created_at.isoformat(),
                    link.expires_at.isoformat(),
                    link.max_views,
                    link.view_count,
                    max(0, link.max_views - link.view_count),
                    link.note or "",
                    link.first_viewed_at.isoformat() if link.first_viewed_at else "",
                    link.last_viewed_at.isoformat() if link.last_viewed_at else "",
                    link.last_view_ip or "",
                    link.last_view_user_agent or "",
                    link.revoked_at.isoformat() if link.revoked_at else "",
                ]
            )
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    resp = StreamingHttpResponse(stream_rows(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="one_time_links_audit.csv"'
    return resp


@login_required
def one_time_link_team_audit(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    now = timezone.now()
    status = (request.GET.get("status") or "").strip()
    creator = (request.GET.get("creator") or "").strip()
    q = (request.GET.get("q") or "").strip()

    queryset = OneTimeLink.objects.filter(entry__team_id=team_id).select_related(
        "entry",
        "entry__group",
        "entry__team",
        "created_by",
    )
    if q:
        queryset = queryset.filter(
            Q(entry__name__icontains=q)
            | Q(note__icontains=q)
            | Q(created_by__username__icontains=q)
            | Q(created_by__email__icontains=q)
        )
    if creator.isdigit():
        queryset = queryset.filter(created_by_id=int(creator))
    if status == "active":
        queryset = queryset.filter(
            expires_at__gt=now,
            view_count__lt=F("max_views"),
            entry__is_deleted=False,
            revoked_at__isnull=True,
        )
    elif status == "revoked":
        queryset = queryset.filter(revoked_at__isnull=False)
    elif status == "deleted":
        queryset = queryset.filter(entry__is_deleted=True)
    elif status == "used":
        queryset = queryset.filter(revoked_at__isnull=True, view_count__gte=F("max_views"))
    elif status == "expired":
        queryset = queryset.filter(
            revoked_at__isnull=True,
            view_count__lt=F("max_views"),
            expires_at__lte=now,
        )

    queryset = queryset.order_by("-created_at")
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

    active_count = OneTimeLink.active.filter(entry__team_id=team_id).count()
    params = request.GET.copy()
    params.pop("page", None)
    querystring = params.urlencode()
    page_prefix = f"{querystring}&" if querystring else ""

    creator_memberships = (
        TeamMembership.objects.filter(team_id=team_id)
        .select_related("user")
        .order_by("user__username")
    )

    return render(
        request,
        "totp/one_time_links.html",
        {
            "records": records,
            "page_obj": page_obj,
            "total_count": paginator.count,
            "active_count": active_count,
            "filters": {
                "status": status,
                "q": q,
                "creator": creator,
            },
            "querystring": querystring,
            "page_prefix": page_prefix,
            "is_team_audit": True,
            "team": team,
            "creator_memberships": creator_memberships,
            "export_url": reverse("totp:one_time_team_audit_export", args=[team_id]),
            "batch_invalidate_url": reverse("totp:one_time_team_batch_invalidate", args=[team_id]),
            "batch_remind_url": reverse("totp:one_time_team_batch_remind", args=[team_id]),
        },
    )


@login_required
@never_cache
@require_GET
def one_time_link_team_audit_export(request, team_id: int):
    _get_team_membership(request.user, team_id, require_manage=True)
    now = timezone.now()
    status = (request.GET.get("status") or "").strip()
    creator = (request.GET.get("creator") or "").strip()
    q = (request.GET.get("q") or "").strip()

    queryset = OneTimeLink.objects.filter(entry__team_id=team_id).select_related(
        "entry",
        "entry__group",
        "entry__team",
        "created_by",
    )
    if q:
        queryset = queryset.filter(
            Q(entry__name__icontains=q)
            | Q(note__icontains=q)
            | Q(created_by__username__icontains=q)
            | Q(created_by__email__icontains=q)
        )
    if creator.isdigit():
        queryset = queryset.filter(created_by_id=int(creator))
    if status == "active":
        queryset = queryset.filter(
            expires_at__gt=now,
            view_count__lt=F("max_views"),
            entry__is_deleted=False,
            revoked_at__isnull=True,
        )
    elif status == "revoked":
        queryset = queryset.filter(revoked_at__isnull=False)
    elif status == "deleted":
        queryset = queryset.filter(entry__is_deleted=True)
    elif status == "used":
        queryset = queryset.filter(revoked_at__isnull=True, view_count__gte=F("max_views"))
    elif status == "expired":
        queryset = queryset.filter(
            revoked_at__isnull=True,
            view_count__lt=F("max_views"),
            expires_at__lte=now,
        )
    queryset = queryset.order_by("-created_at")

    def stream_rows():
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "link_id",
                "created_by",
                "created_by_email",
                "entry_name",
                "team",
                "status",
                "created_at",
                "expires_at",
                "max_views",
                "view_count",
                "remaining_views",
                "note",
                "first_viewed_at",
                "last_viewed_at",
                "last_view_ip",
                "last_view_user_agent",
                "revoked_at",
            ]
        )
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)

        for link in queryset.iterator(chunk_size=200):
            status_key = "active" if link.is_active else _resolve_link_inactive_reason(link)
            writer.writerow(
                [
                    link.id,
                    link.created_by.username,
                    link.created_by.email or "",
                    link.entry.name,
                    link.entry.team.name if link.entry.team_id else "",
                    status_key,
                    link.created_at.isoformat(),
                    link.expires_at.isoformat(),
                    link.max_views,
                    link.view_count,
                    max(0, link.max_views - link.view_count),
                    link.note or "",
                    link.first_viewed_at.isoformat() if link.first_viewed_at else "",
                    link.last_viewed_at.isoformat() if link.last_viewed_at else "",
                    link.last_view_ip or "",
                    link.last_view_user_agent or "",
                    link.revoked_at.isoformat() if link.revoked_at else "",
                ]
            )
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    resp = StreamingHttpResponse(stream_rows(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="one_time_links_team_audit.csv"'
    return resp


@login_required
@require_POST
def batch_invalidate_one_time_links_team(request, team_id: int):
    _get_team_membership(request.user, team_id, require_manage=True)
    if not _has_recent_reauth(request):
        return _reauth_json(request)

    data = None
    if (request.content_type or "").startswith("application/json"):
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        data = request.POST

    raw_ids = data.get("ids") or []
    ids: list[int] = []
    if isinstance(raw_ids, str):
        raw_ids = [part.strip() for part in raw_ids.split(",") if part.strip()]
    if isinstance(raw_ids, list):
        for item in raw_ids:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value > 0:
                ids.append(value)
    ids = list(dict.fromkeys(ids))[:50]
    if not ids:
        return JsonResponse({"ok": False, "message": "请选择要失效的链接"}, status=400)

    now = timezone.now()
    links = list(
        OneTimeLink.objects.filter(entry__team_id=team_id, id__in=ids).select_related(
            "entry", "entry__team"
        )
    )
    if not links:
        return JsonResponse({"ok": False, "message": "未找到可处理的链接"}, status=404)

    active_ids = [
        link.id
        for link in links
        if link.revoked_at is None and link.expires_at > now and link.view_count < link.max_views
    ]
    if not active_ids:
        return JsonResponse({"ok": False, "message": "所选链接均已失效，无需处理"}, status=400)

    OneTimeLink.objects.filter(id__in=active_ids, entry__team_id=team_id).update(
        expires_at=now, revoked_at=now, updated_at=now
    )
    for link in links:
        if link.id not in active_ids:
            continue
        entry = link.entry
        log_entry_audit(
            entry,
            request.user,
            TOTPEntryAudit.Action.ONE_TIME_LINK_REVOKED,
            old_value=entry.name,
            metadata={
                "space": "team",
                "one_time_link_id": link.id,
                "batch": True,
            },
        )

    return JsonResponse({"ok": True, "updated": len(active_ids), "requested": len(ids)})


@login_required
@require_POST
def batch_remind_one_time_links_team(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    if not _has_recent_reauth(request):
        return _reauth_json(request)

    data = None
    if (request.content_type or "").startswith("application/json"):
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        data = request.POST

    raw_ids = data.get("ids") or []
    ids: list[int] = []
    if isinstance(raw_ids, str):
        raw_ids = [part.strip() for part in raw_ids.split(",") if part.strip()]
    if isinstance(raw_ids, list):
        for item in raw_ids:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value > 0:
                ids.append(value)
    ids = list(dict.fromkeys(ids))[:50]
    if not ids:
        return JsonResponse({"ok": False, "message": "请选择要提醒的链接"}, status=400)

    now = timezone.now()
    links = list(
        OneTimeLink.objects.filter(entry__team_id=team_id, id__in=ids).select_related(
            "entry", "entry__team", "created_by"
        )
    )
    active_links = [
        link
        for link in links
        if link.revoked_at is None and link.expires_at > now and link.view_count < link.max_views
    ]
    if not active_links:
        return JsonResponse({"ok": False, "message": "所选链接均已失效，无需提醒"}, status=400)

    by_user: dict[int, list[OneTimeLink]] = {}
    for link in active_links:
        by_user.setdefault(link.created_by_id, []).append(link)

    audit_url = request.build_absolute_uri(
        reverse("totp:one_time_team_audit", args=[team_id])
    )
    reminded_users = 0
    reminded_links = 0
    skipped_no_email = 0

    for user_id, items in by_user.items():
        user = items[0].created_by
        if not user.email:
            skipped_no_email += 1
            continue
        lines = [
            f"团队：{team.name}",
            "以下一次性访问链接仍处于可用状态，请确认是否需要尽快失效：",
            "",
        ]
        for link in items:
            remaining = max(0, link.max_views - link.view_count)
            note = (link.note or "").replace("\n", " ").strip()
            lines.append(
                f"- link_id={link.id}  密钥={link.entry.name}  过期={link.expires_at.strftime('%Y-%m-%d %H:%M')}  剩余次数={remaining}"
                + (f"  备注={note}" if note else "")
            )
        lines.extend(["", f"请在审计页处理：{audit_url}", ""])
        send_mail(
            subject=f"[ToTP] 请检查并失效一次性访问链接（{team.name}）",
            message="\n".join(lines),
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
            recipient_list=[user.email],
            fail_silently=True,
        )
        log_team_audit(
            team,
            request.user,
            TeamAudit.Action.LINKS_REVOKE_REMINDER_SENT,
            target_user=user,
            metadata={"count": len(items), "link_ids": [l.id for l in items][:50]},
        )
        reminded_users += 1
        reminded_links += len(items)

    return JsonResponse(
        {
            "ok": True,
            "reminded_users": reminded_users,
            "reminded_links": reminded_links,
            "skipped_no_email": skipped_no_email,
        }
    )
@login_required
@require_POST
def batch_invalidate_one_time_links(request):
    if not _has_recent_reauth(request):
        return _reauth_json(request)

    data = None
    if (request.content_type or "").startswith("application/json"):
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        data = request.POST

    raw_ids = data.get("ids") or []
    ids: list[int] = []
    if isinstance(raw_ids, str):
        raw_ids = [part.strip() for part in raw_ids.split(",") if part.strip()]
    if isinstance(raw_ids, list):
        for item in raw_ids:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value > 0:
                ids.append(value)
    ids = list(dict.fromkeys(ids))[:50]
    if not ids:
        return JsonResponse({"ok": False, "message": "请选择要失效的链接"}, status=400)

    now = timezone.now()
    links = list(
        OneTimeLink.objects.filter(created_by=request.user, id__in=ids).select_related(
            "entry", "entry__team"
        )
    )
    if not links:
        return JsonResponse({"ok": False, "message": "未找到可处理的链接"}, status=404)

    active_ids = [
        link.id
        for link in links
        if link.revoked_at is None and link.expires_at > now and link.view_count < link.max_views
    ]
    if not active_ids:
        return JsonResponse({"ok": False, "message": "所选链接均已失效，无需处理"}, status=400)

    OneTimeLink.objects.filter(id__in=active_ids, created_by=request.user).update(
        expires_at=now, revoked_at=now, updated_at=now
    )
    for link in links:
        if link.id not in active_ids:
            continue
        entry = link.entry
        log_entry_audit(
            entry,
            request.user,
            TOTPEntryAudit.Action.ONE_TIME_LINK_REVOKED,
            old_value=entry.name,
            metadata={
                "space": "team" if entry.team_id else "personal",
                "one_time_link_id": link.id,
                "batch": True,
            },
        )

    return JsonResponse({"ok": True, "updated": len(active_ids), "requested": len(ids)})


@login_required
@require_POST
def create_one_time_link(request, pk: int):
    """为指定密钥生成一次性只读访问链接。"""

    if not _has_recent_reauth(request):
        return _reauth_json(request)

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
    max_duration = TEAM_ONE_TIME_LINK_MAX_DURATION_MINUTES if entry.team_id else 60
    duration_minutes = max(1, min(duration_minutes, max_duration))

    try:
        max_views = int(request.POST.get("max_views") or 3)
    except (TypeError, ValueError):
        max_views = 3
    max_views = max(1, min(max_views, 5))

    note = (request.POST.get("note") or "").strip()
    if len(note) > 120:
        note = note[:120]

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
    if entry.team_id:
        team_active_links = OneTimeLink.active.filter(entry__team=entry.team).count()
        if team_active_links >= TEAM_ONE_TIME_LINK_ACTIVE_LIMIT:
            return JsonResponse(
                {
                    "ok": False,
                    "error": "team_link_limit_reached",
                    "message": "团队当前有效分享链接过多，请先撤销旧链接后再试。",
                },
                status=400,
            )

    expires_at = now + timedelta(minutes=duration_minutes)

    token = None
    link = None
    for _ in range(6):
        # 最多重试 6 次生成随机 token，以避免哈希碰撞
        candidate = secrets.token_urlsafe(32)
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        try:
            link = OneTimeLink.objects.create(
                entry=entry,
                created_by=request.user,
                token_hash=candidate_hash,
                expires_at=expires_at,
                max_views=max_views,
                note=note,
            )
        except IntegrityError:
            continue
        token = candidate
        break
    if not token or link is None:
        return JsonResponse(
            {"ok": False, "error": "token_generation_failed"}, status=500
        )

    path = reverse("totp:one_time_view", args=[token])
    url = request.build_absolute_uri(path)
    log_entry_audit(
        entry,
        request.user,
        TOTPEntryAudit.Action.ONE_TIME_LINK_CREATED,
        old_value=entry.name,
        metadata={
            "space": "team" if entry.team_id else "personal",
            "one_time_link_id": link.id,
            "expires_at": expires_at.isoformat(),
            "max_views": link.max_views,
            "note": note,
        },
    )
    return JsonResponse(
        {
            "ok": True,
            "id": link.id,
            "url": url,
            "created_at": link.created_at.isoformat(),
            "created_at_timestamp": int(link.created_at.timestamp()),
            "expires_at": expires_at.isoformat(),
            "expires_at_timestamp": int(expires_at.timestamp()),
            "duration_minutes": duration_minutes,
            "max_views": link.max_views,
            "remaining_views": link.max_views - link.view_count,
            "note": note,
        }
    )


@login_required
@require_POST
def invalidate_one_time_link(request, pk: int):
    """立即失效指定的一次性访问链接。"""

    if not _has_recent_reauth(request):
        return _reauth_json(request)

    link = get_object_or_404(
        OneTimeLink.objects.select_related("entry", "entry__team"),
        pk=pk,
        created_by=request.user,
    )
    entry = link.entry
    log_entry_audit(
        entry,
        request.user,
        TOTPEntryAudit.Action.ONE_TIME_LINK_REVOKED,
        old_value=entry.name,
        metadata={
            "space": "team" if entry.team_id else "personal",
            "one_time_link_id": link.id,
        },
    )
    link.invalidate()
    return JsonResponse({"ok": True})


@never_cache
@csrf_exempt
@require_POST
def external_totp(request):
    """根据链接参数返回动态验证码，供未登录场景使用。"""

    if not getattr(settings, "EXTERNAL_TOOL_ENABLED", False):
        return JsonResponse({"ok": False, "message": "该功能已关闭"}, status=404)

    if not _external_totp_rate_limit_allow(request):
        return JsonResponse(
            {"ok": False, "message": "请求过于频繁，请稍后再试"},
            status=429,
        )

    if request.GET.get("secret"):
        return JsonResponse(
            {"ok": False, "message": "请使用 POST 方式提交 secret"},
            status=400,
        )

    data = None
    if (request.content_type or "").startswith("application/json"):
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        data = request.POST

    secret_raw = (data.get("secret") or "").strip()
    if not secret_raw:
        return JsonResponse({"ok": False, "message": "缺少 secret 参数"}, status=400)

    secret = normalize_google_secret(secret_raw)
    if not secret:
        return JsonResponse({"ok": False, "message": "密钥格式无效"}, status=400)

    digits = data.get("digits") or "6"
    try:
        digits_int = int(digits)
    except (TypeError, ValueError):
        digits_int = 6
    # 限制验证码长度在合理范围内，避免异常参数导致计算失败
    digits_int = min(max(digits_int, 4), 8)

    period = data.get("period") or "30"
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

    return JsonResponse(payload, status=200)


@never_cache
@require_GET
def external_totp_tool(request):
    """展示一个外部验证码生成工具页面。"""

    if not getattr(settings, "EXTERNAL_TOOL_ENABLED", False):
        raise Http404("Not found")

    digits = (request.GET.get("digits") or "6").strip()
    period = (request.GET.get("period") or "30").strip()
    context = {
        "prefill_secret": (
            (request.GET.get("secret") or "").strip()
            if getattr(settings, "EXTERNAL_TOOL_ALLOW_SECRET_PREFILL", False)
            else ""
        ),
        "prefill_digits": digits,
        "prefill_period": period,
        "digits_choices": ["4", "5", "6", "7", "8"],
        "period_choices": ["15", "20", "30", "45", "60", "90", "120"],
    }
    return render(request, "totp/external_tool.html", context)


@never_cache
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
                .select_related("entry", "entry__user", "entry__group", "created_by")
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

    ip = client_ip(request)
    short_key = f"totp:external_totp:rl:short:{ip}"
    long_key = f"totp:external_totp:rl:long:{ip}"

    short_window = int(getattr(settings, "EXTERNAL_TOTP_RATE_WINDOW_SECONDS", 60))
    short_limit = int(getattr(settings, "EXTERNAL_TOTP_RATE_LIMIT", 10))
    long_window = int(getattr(settings, "EXTERNAL_TOTP_RATE_WINDOW_SECONDS_LONG", 600))
    long_limit = int(getattr(settings, "EXTERNAL_TOTP_RATE_LIMIT_LONG", 60))

    if cache.add(short_key, 1, short_window):
        short_count = 1
    else:
        try:
            short_count = cache.incr(short_key)
        except ValueError:
            cache.set(short_key, 1, short_window)
            short_count = 1

    if cache.add(long_key, 1, long_window):
        long_count = 1
    else:
        try:
            long_count = cache.incr(long_key)
        except ValueError:
            cache.set(long_key, 1, long_window)
            long_count = 1

    return short_count <= short_limit and long_count <= long_limit


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
