import csv
import json
from datetime import timedelta
from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .models import (
    OneTimeLink,
    Team,
    TeamAudit,
    TeamInvitation,
    TeamMembership,
    log_team_audit,
)
from .querysets import teams_queryset_for_overview
from .views import (
    TEAM_MANAGER_ROLES,
    TEAM_NAME_MAX_LENGTH,
    _build_team_member_row,
    _cleanup_team_asset_user_roles,
    _get_team_membership,
    _has_recent_reauth,
    _reauth_redirect,
    _team_active_link_panel_stats,
    _team_audit_ui_meta,
    _team_overview_counts,
)

UserModel = get_user_model()


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
            team__in=teams,
            status=TeamInvitation.Status.PENDING,
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
            "can_manage": bool(
                membership_map.get(team.id)
                and membership_map.get(team.id).can_manage_entries
            ),
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
            invitee=request.user,
            status=TeamInvitation.Status.PENDING,
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
@require_GET
def team_home(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=False)
    team = membership.team
    can_manage = membership.can_manage_entries
    counts = _team_overview_counts(team=team, can_manage=can_manage)
    member_preview = list(
        TeamMembership.objects.filter(team=team)
        .select_related("user")
        .order_by("role", "joined_at")[:4]
    )
    recent_activity = list(
        TeamAudit.objects.filter(team=team)
        .select_related("actor", "target_user")
        .order_by("-created_at")[:5]
    )
    for audit in recent_activity:
        audit.ui_meta = _team_audit_ui_meta(audit.action)
    return render(
        request,
        "totp/team_home.html",
        {
            "team": team,
            "membership": membership,
            "can_manage": can_manage,
            "member_preview": member_preview,
            "recent_activity": recent_activity,
            **counts,
        },
    )


@login_required
@require_GET
def team_tab_fragment(request, team_id: int, tab: str):
    membership = _get_team_membership(request.user, team_id, require_manage=False)
    team = membership.team
    if tab not in {"members", "security", "audit"}:
        raise Http404()

    counts = _team_overview_counts(team=team, can_manage=membership.can_manage_entries)
    pending_invites = list(
        TeamInvitation.objects.filter(team=team, status=TeamInvitation.Status.PENDING)
        .select_related("invitee")
        .order_by("-created_at")
    )
    role_labels = dict(TeamMembership.Role.choices)
    available_roles = [
        (TeamMembership.Role.MEMBER, role_labels[TeamMembership.Role.MEMBER]),
        (TeamMembership.Role.ADMIN, role_labels[TeamMembership.Role.ADMIN]),
    ]

    context = {
        "team": team,
        "membership": membership,
        "can_manage": membership.can_manage_entries,
        "member_count": counts["member_count"],
        "entry_count": counts["entry_count"],
        "pending_invites": pending_invites,
        "active_share_links": counts["active_share_links"],
        "available_roles": available_roles,
    }
    if tab == "members":
        q = (request.GET.get("q") or "").strip()
        membership_qs = (
            TeamMembership.objects.filter(team=team)
            .select_related("user")
            .order_by("role", "user__username")
        )
        if q:
            membership_qs = membership_qs.filter(
                Q(user__username__icontains=q) | Q(user__email__icontains=q)
            )
        paginator = Paginator(membership_qs, 20)
        page_obj = paginator.get_page(request.GET.get("page"))
        context["q"] = q
        context["page_obj"] = page_obj
        context["member_rows"] = [
            _build_team_member_row(row=row, viewer=membership, current_user=request.user)
            for row in page_obj.object_list
        ]
        return render(request, "totp/_team_tab_members.html", context)
    if tab == "security":
        return render(request, "totp/_team_tab_security.html", context)
    return render(request, "totp/_team_tab_audit.html", context)


@login_required
@require_GET
def team_actions_panel(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=False)
    team = membership.team
    panel_context = (request.GET.get("context") or "").strip() or "teams"
    can_manage = membership.can_manage_entries
    counts = _team_overview_counts(team=team, can_manage=can_manage)
    active_share_links = counts["active_share_links"]
    link_creators = []
    latest_link_created_at = None
    latest_link_viewed_at = None
    has_link_views = False
    if can_manage and active_share_links:
        link_stats = _team_active_link_panel_stats(team=team)
        latest_link_created_at = link_stats["latest_link_created_at"]
        latest_link_viewed_at = link_stats["latest_link_viewed_at"]
        has_link_views = link_stats["has_link_views"]
        active_links = OneTimeLink.active.filter(entry__team=team)
        link_creators = list(
            active_links
            .values("created_by__username")
            .annotate(cnt=Count("id"))
            .order_by("-cnt", "created_by__username")[:5]
        )
    pending_invites_count = counts["pending_invites_count"]
    unassigned_entries_count = counts["unassigned_entries_count"]
    risk_empty = (
        active_share_links == 0
        and pending_invites_count == 0
        and unassigned_entries_count == 0
    )
    audits = list(
        TeamAudit.objects.filter(team=team)
        .select_related("actor", "target_user")
        .order_by("-created_at")[:30]
    )
    for audit in audits:
        meta = _team_audit_ui_meta(audit.action)
        audit.ui_meta = meta
        audit.is_high_risk = meta.get("priority") == "high"
    recent_high_risk = [a for a in audits if getattr(a, "is_high_risk", False)][:4]
    recent_normal = [a for a in audits if not getattr(a, "is_high_risk", False)][:6]
    return render(
        request,
        "totp/_team_actions_panel.html",
        {
            "team": team,
            "membership": membership,
            "panel_context": panel_context,
            "can_manage": can_manage,
            "active_share_links": active_share_links,
            "link_creators": link_creators,
            "latest_link_created_at": latest_link_created_at,
            "latest_link_viewed_at": latest_link_viewed_at,
            "has_link_views": has_link_views,
            "pending_invites_count": pending_invites_count,
            "unassigned_entries_count": unassigned_entries_count,
            "risk_empty": risk_empty,
            "recent_high_risk": recent_high_risk,
            "recent_audits": recent_normal,
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
    if len(name) > TEAM_NAME_MAX_LENGTH:
        messages.error(request, "团队名称过长")
        return redirect("totp:teams")

    if Team.objects.filter(owner=request.user, name=name).exists():
        messages.error(request, "已存在同名团队，请更换名称")
        return redirect("totp:teams")

    try:
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
    except IntegrityError:
        messages.error(request, "已存在同名团队，请更换名称")
        return redirect("totp:teams")

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
    if len(name) > TEAM_NAME_MAX_LENGTH:
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
        _cleanup_team_asset_user_roles(team=membership.team, user_id=request.user.id)
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

    _cleanup_team_asset_user_roles(team=membership.team, user_id=target.user_id)
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
    _get_team_membership(request.user, invitation.team_id, require_manage=True)
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
    high_risk_actions = [
        TeamAudit.Action.LINKS_REVOKED_ALL,
        TeamAudit.Action.MEMBER_ROLE_CHANGED,
        TeamAudit.Action.MEMBER_REMOVED,
        TeamAudit.Action.INVITE_SENT,
        TeamAudit.Action.INVITE_UPDATED,
        TeamAudit.Action.INVITE_CANCELLED,
    ]

    action = (request.GET.get("action") or "").strip()
    q = (request.GET.get("q") or "").strip()
    actor_raw = (request.GET.get("actor") or "").strip()
    target_raw = (request.GET.get("target") or "").strip()
    risk = (request.GET.get("risk") or "").strip()
    days_raw = (request.GET.get("days") or "").strip()

    queryset = TeamAudit.objects.filter(team=team).select_related("actor", "target_user")
    base_count = TeamAudit.objects.filter(team=team).count()
    if risk == "high":
        queryset = queryset.filter(action__in=high_risk_actions)
    days_value = None
    if days_raw.isdigit():
        days_value = int(days_raw)
        if days_value not in (7, 30, 90):
            days_value = None
    if days_value:
        since = timezone.now() - timedelta(days=days_value)
        queryset = queryset.filter(created_at__gte=since)
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
    page_obj = paginator.get_page(request.GET.get("page"))
    for record in page_obj.object_list:
        record.metadata_text = json.dumps(record.metadata or {}, ensure_ascii=False)
        record.ui_meta = _team_audit_ui_meta(record.action)
    actor_options = (
        TeamAudit.objects.filter(team=team, actor__isnull=False)
        .values("actor_id", "actor__username", "actor__email")
        .distinct()
        .order_by("actor__username")
    )
    target_options = (
        TeamAudit.objects.filter(team=team, target_user__isnull=False)
        .values("target_user_id", "target_user__username", "target_user__email")
        .distinct()
        .order_by("target_user__username")
    )
    params = request.GET.copy()
    params.pop("page", None)
    querystring = params.urlencode()
    is_filtered = bool(action or q or actor_raw or target_raw or risk or days_value)

    total_pages = page_obj.paginator.num_pages
    current_page = page_obj.number
    start = max(1, current_page - 2)
    end = min(total_pages, current_page + 2)
    page_window = list(range(start, end + 1))

    actor_label_map = {
        str(row["actor_id"]): (
            f'{row["actor__username"]}（{row["actor__email"]}）'
            if row.get("actor__email")
            else row["actor__username"]
        )
        for row in actor_options
    }
    target_label_map = {
        str(row["target_user_id"]): (
            f'{row["target_user__username"]}（{row["target_user__email"]}）'
            if row.get("target_user__email")
            else row["target_user__username"]
        )
        for row in target_options
    }
    action_label_map = dict(TeamAudit.Action.choices)

    def build_remove_url(keys):
        next_params = request.GET.copy()
        next_params.pop("page", None)
        for k in keys:
            next_params.pop(k, None)
        base = reverse("totp:team_audit", args=[team.id])
        qs = next_params.urlencode()
        return f"{base}?{qs}" if qs else base

    filter_chips = []
    if risk == "high":
        filter_chips.append({"label": "高风险", "remove_url": build_remove_url(["risk"])})
    if days_value:
        filter_chips.append(
            {"label": f"最近 {days_value} 天", "remove_url": build_remove_url(["days"])}
        )
    if action and action in action_label_map:
        filter_chips.append(
            {
                "label": f"动作：{action_label_map.get(action)}",
                "remove_url": build_remove_url(["action"]),
            }
        )
    if actor_raw and actor_raw in actor_label_map:
        filter_chips.append(
            {
                "label": f"操作人：{actor_label_map.get(actor_raw)}",
                "remove_url": build_remove_url(["actor"]),
            }
        )
    if target_raw and target_raw in target_label_map:
        filter_chips.append(
            {
                "label": f"目标：{target_label_map.get(target_raw)}",
                "remove_url": build_remove_url(["target"]),
            }
        )
    if q:
        filter_chips.append({"label": f"搜索：{q}", "remove_url": build_remove_url(["q"])})

    quick_params = request.GET.copy()
    quick_params.pop("page", None)
    quick_links = {}
    high_risk_params = quick_params.copy()
    high_risk_params["risk"] = "high"
    quick_links["high_risk"] = f'{reverse("totp:team_audit", args=[team.id])}?{high_risk_params.urlencode()}'
    last7_params = quick_params.copy()
    last7_params["days"] = "7"
    quick_links["last7"] = f'{reverse("totp:team_audit", args=[team.id])}?{last7_params.urlencode()}'
    last30_params = quick_params.copy()
    last30_params["days"] = "30"
    quick_links["last30"] = f'{reverse("totp:team_audit", args=[team.id])}?{last30_params.urlencode()}'
    return render(
        request,
        "totp/team_audit.html",
        {
            "team": team,
            "membership": membership,
            "page_obj": page_obj,
            "records": page_obj.object_list,
            "base_count": base_count,
            "filtered_count": paginator.count,
            "action_choices": TeamAudit.Action.choices,
            "selected_action": action,
            "q": q,
            "actor_options": actor_options,
            "target_options": target_options,
            "selected_actor": actor_raw,
            "selected_target": target_raw,
            "querystring": querystring,
            "is_filtered": is_filtered,
            "page_window": page_window,
            "show_start_ellipsis": start > 2,
            "show_end_ellipsis": end < total_pages - 1,
            "risk": risk,
            "days": days_value or "",
            "filter_chips": filter_chips,
            "quick_links": quick_links,
            "high_risk_count": TeamAudit.objects.filter(team=team, action__in=high_risk_actions).count(),
            "active_filter_count": len(filter_chips),
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
    risk = (request.GET.get("risk") or "").strip()
    days_raw = (request.GET.get("days") or "").strip()

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
    if risk == "high":
        queryset = queryset.filter(
            action__in=[
                TeamAudit.Action.LINKS_REVOKED_ALL,
                TeamAudit.Action.MEMBER_ROLE_CHANGED,
                TeamAudit.Action.MEMBER_REMOVED,
                TeamAudit.Action.INVITE_SENT,
                TeamAudit.Action.INVITE_UPDATED,
                TeamAudit.Action.INVITE_CANCELLED,
            ]
        )
    days_value = None
    if days_raw.isdigit():
        days_value = int(days_raw)
        if days_value not in (7, 30, 90):
            days_value = None
    if days_value:
        since = timezone.now() - timedelta(days=days_value)
        queryset = queryset.filter(created_at__gte=since)
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

    export_limit = 20000
    total_count = queryset.count()
    filename = timezone.now().strftime(f"team-audit-{team.id}-%Y%m%d-%H%M%S.csv")
    quoted = quote(filename)
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = (
        f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quoted}"
    )
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    response["X-Export-Limit"] = str(export_limit)
    response["X-Export-Total"] = str(total_count)
    if total_count > export_limit:
        response["X-Export-Truncated"] = "1"
    response.write("\ufeff")
    writer = csv.writer(response)
    writer.writerow(["时间", "动作", "操作人", "目标用户", "旧值", "新值", "详情"])
    if total_count > export_limit:
        writer.writerow(
            [
                "提示",
                f"导出上限 {export_limit} 条，本次已导出前 {export_limit} 条（共 {total_count} 条）。建议添加筛选后再次导出。",
                "",
                "",
                "",
                "",
                "",
            ]
        )
    for idx, record in enumerate(queryset.order_by("-created_at").iterator(chunk_size=1000)):
        if idx >= export_limit:
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
