import csv
import hashlib
import io
import json
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import F, Q
from django.http import Http404, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from project.utils import client_ip

from .models import (
    OneTimeLink,
    TeamAudit,
    TeamMembership,
    TOTPEntryAudit,
    log_entry_audit,
    log_team_audit,
)
from .utils import decrypt_str, normalize_google_secret, totp_code_base32
from .views import (
    _active_one_time_links_queryset,
    _creator_accessible_one_time_links,
    _get_entry_for_user,
    _get_team_membership,
    _has_recent_reauth,
    _reauth_json,
    _secret_preview,
)


def _parse_ids(raw_ids, *, limit=50):
    values: list[int] = []
    if isinstance(raw_ids, str):
        raw_ids = [part.strip() for part in raw_ids.split(",") if part.strip()]
    if isinstance(raw_ids, list):
        for item in raw_ids:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value > 0:
                values.append(value)
    return list(dict.fromkeys(values))[:limit]


def _resolve_days_value(days_raw: str):
    if not days_raw.isdigit():
        return None
    days_value = int(days_raw)
    if days_value not in (7, 30, 90):
        return None
    return days_value


def _filter_one_time_link_queryset(
    queryset,
    *,
    now,
    status="",
    q="",
    days_raw="",
    unvisited="",
    team_id=None,
    creator="",
    space="",
):
    if q:
        if team_id is None:
            queryset = queryset.filter(
                Q(entry__name__icontains=q)
                | Q(note__icontains=q)
                | Q(entry__team__name__icontains=q)
            )
        else:
            queryset = queryset.filter(
                Q(entry__name__icontains=q)
                | Q(note__icontains=q)
                | Q(created_by__username__icontains=q)
                | Q(created_by__email__icontains=q)
            )
    days_value = _resolve_days_value(days_raw)
    if days_value:
        since = now - timedelta(days=days_value)
        queryset = queryset.filter(created_at__gte=since)
    if unvisited in ("1", "true", "yes"):
        queryset = queryset.filter(first_viewed_at__isnull=True)
    if creator.isdigit():
        queryset = queryset.filter(created_by_id=int(creator))
    if space == "personal":
        queryset = queryset.filter(entry__team__isnull=True)
    elif space == "team":
        queryset = queryset.filter(entry__team__isnull=False)
        if isinstance(team_id, str) and team_id.isdigit():
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
    return queryset, days_value


def _build_link_records(page_obj):
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
    return records


@login_required
def one_time_link_audit(request):
    """展示当前用户创建的一次性访问链接审计信息。"""

    now = timezone.now()
    status = (request.GET.get("status") or "").strip()
    space = (request.GET.get("space") or "").strip()
    team_id = (request.GET.get("team") or "").strip()
    q = (request.GET.get("q") or "").strip()
    days_raw = (request.GET.get("days") or "").strip()
    unvisited = (request.GET.get("unvisited") or "").strip()

    queryset = _creator_accessible_one_time_links(request.user).select_related(
        "entry",
        "entry__group",
        "entry__team",
    )
    queryset, days_value = _filter_one_time_link_queryset(
        queryset,
        now=now,
        status=status,
        q=q,
        days_raw=days_raw,
        unvisited=unvisited,
        space=space,
        team_id=team_id,
    )
    queryset = queryset.order_by("-created_at")

    paginator = Paginator(queryset, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    records = _build_link_records(page_obj)

    active_count = _active_one_time_links_queryset(
        _creator_accessible_one_time_links(request.user),
        now=now,
    ).count()
    params = request.GET.copy()
    params.pop("page", None)
    querystring = params.urlencode()
    page_prefix = f"{querystring}&" if querystring else ""
    memberships = TeamMembership.objects.filter(user=request.user).select_related("team").order_by("team__name")
    is_filtered = bool(status or space or team_id or q or days_value or unvisited)

    total_pages = page_obj.paginator.num_pages
    current_page = page_obj.number
    start = max(1, current_page - 2)
    end = min(total_pages, current_page + 2)
    page_window = list(range(start, end + 1))

    team_label_map = {str(m.team_id): m.team.name for m in memberships}
    space_label_map = {"personal": "个人", "team": "团队"}
    status_label_map = {
        "active": "可用",
        "expired": "已过期",
        "used": "已用尽",
        "revoked": "已撤销",
        "deleted": "关联密钥已删除",
    }

    def build_remove_url(keys):
        next_params = request.GET.copy()
        next_params.pop("page", None)
        for key in keys:
            next_params.pop(key, None)
        base = reverse("totp:one_time_audit")
        qs = next_params.urlencode()
        return f"{base}?{qs}" if qs else base

    filter_chips = []
    if status and status in status_label_map:
        filter_chips.append(
            {"label": f"状态：{status_label_map.get(status)}", "remove_url": build_remove_url(["status"])}
        )
    if space and space in space_label_map:
        filter_chips.append(
            {"label": f"空间：{space_label_map.get(space)}", "remove_url": build_remove_url(["space", "team"])}
        )
    if team_id and team_id in team_label_map:
        filter_chips.append(
            {"label": f"团队：{team_label_map.get(team_id)}", "remove_url": build_remove_url(["team"])}
        )
    if days_value:
        filter_chips.append(
            {"label": f"最近 {days_value} 天", "remove_url": build_remove_url(["days"])}
        )
    if unvisited in ("1", "true", "yes"):
        filter_chips.append({"label": "未访问", "remove_url": build_remove_url(["unvisited"])})
    if q:
        filter_chips.append({"label": f"搜索：{q}", "remove_url": build_remove_url(["q"])})

    quick_params = request.GET.copy()
    quick_params.pop("page", None)
    active_params = quick_params.copy()
    active_params["status"] = "active"
    last7_params = quick_params.copy()
    last7_params["days"] = "7"
    unvisited_params = quick_params.copy()
    unvisited_params["unvisited"] = "1"

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
                "days": str(days_value) if days_value else "",
                "unvisited": "1" if unvisited in ("1", "true", "yes") else "",
            },
            "querystring": querystring,
            "page_prefix": page_prefix,
            "team_memberships": list(memberships),
            "is_team_audit": False,
            "export_url": reverse("totp:one_time_audit_export"),
            "batch_invalidate_url": reverse("totp:one_time_batch_invalidate"),
            "batch_remind_url": "",
            "filter_chips": filter_chips,
            "quick_links": {
                "active": f'{reverse("totp:one_time_audit")}?{active_params.urlencode()}',
                "last7": f'{reverse("totp:one_time_audit")}?{last7_params.urlencode()}',
                "unvisited": f'{reverse("totp:one_time_audit")}?{unvisited_params.urlencode()}',
            },
            "is_filtered": is_filtered,
            "page_window": page_window,
            "show_start_ellipsis": start > 2,
            "show_end_ellipsis": end < total_pages - 1,
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
    days_raw = (request.GET.get("days") or "").strip()
    unvisited = (request.GET.get("unvisited") or "").strip()

    queryset = _creator_accessible_one_time_links(request.user).select_related(
        "entry",
        "entry__group",
        "entry__team",
    )
    queryset, _days_value = _filter_one_time_link_queryset(
        queryset,
        now=now,
        status=status,
        q=q,
        days_raw=days_raw,
        unvisited=unvisited,
        space=space,
        team_id=team_id,
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
            writer.writerow(
                [
                    link.id,
                    link.entry.name,
                    "team" if link.entry.team_id else "personal",
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

    response = StreamingHttpResponse(
        stream_rows(),
        content_type="text/csv; charset=utf-8",
    )
    response["Content-Disposition"] = 'attachment; filename="one_time_links_audit.csv"'
    return response


@login_required
def one_time_link_team_audit(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    now = timezone.now()
    status = (request.GET.get("status") or "").strip()
    creator = (request.GET.get("creator") or "").strip()
    q = (request.GET.get("q") or "").strip()
    days_raw = (request.GET.get("days") or "").strip()
    unvisited = (request.GET.get("unvisited") or "").strip()

    queryset = OneTimeLink.objects.filter(entry__team_id=team_id).select_related(
        "entry",
        "entry__group",
        "entry__team",
        "created_by",
    )
    queryset, days_value = _filter_one_time_link_queryset(
        queryset,
        now=now,
        status=status,
        q=q,
        days_raw=days_raw,
        unvisited=unvisited,
        creator=creator,
        team_id=team_id,
    )
    queryset = queryset.order_by("-created_at")

    paginator = Paginator(queryset, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    records = _build_link_records(page_obj)

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
    is_filtered = bool(status or creator or q or days_value or unvisited)

    total_pages = page_obj.paginator.num_pages
    current_page = page_obj.number
    start = max(1, current_page - 2)
    end = min(total_pages, current_page + 2)
    page_window = list(range(start, end + 1))

    creator_label_map = {str(m.user_id): m.user.username for m in creator_memberships}
    status_label_map = {
        "active": "可用",
        "expired": "已过期",
        "used": "已用尽",
        "revoked": "已撤销",
        "deleted": "关联密钥已删除",
    }

    def build_remove_url(keys):
        next_params = request.GET.copy()
        next_params.pop("page", None)
        for key in keys:
            next_params.pop(key, None)
        base = reverse("totp:one_time_team_audit", args=[team_id])
        qs = next_params.urlencode()
        return f"{base}?{qs}" if qs else base

    filter_chips = []
    if status and status in status_label_map:
        filter_chips.append(
            {"label": f"状态：{status_label_map.get(status)}", "remove_url": build_remove_url(["status"])}
        )
    if creator and creator in creator_label_map:
        filter_chips.append(
            {"label": f"创建人：{creator_label_map.get(creator)}", "remove_url": build_remove_url(["creator"])}
        )
    if days_value:
        filter_chips.append(
            {"label": f"最近 {days_value} 天", "remove_url": build_remove_url(["days"])}
        )
    if unvisited in ("1", "true", "yes"):
        filter_chips.append({"label": "未访问", "remove_url": build_remove_url(["unvisited"])})
    if q:
        filter_chips.append({"label": f"搜索：{q}", "remove_url": build_remove_url(["q"])})

    quick_params = request.GET.copy()
    quick_params.pop("page", None)
    active_params = quick_params.copy()
    active_params["status"] = "active"
    last7_params = quick_params.copy()
    last7_params["days"] = "7"
    unvisited_params = quick_params.copy()
    unvisited_params["unvisited"] = "1"

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
                "days": str(days_value) if days_value else "",
                "unvisited": "1" if unvisited in ("1", "true", "yes") else "",
            },
            "querystring": querystring,
            "page_prefix": page_prefix,
            "is_team_audit": True,
            "team": team,
            "creator_memberships": creator_memberships,
            "export_url": reverse("totp:one_time_team_audit_export", args=[team_id]),
            "batch_invalidate_url": reverse("totp:one_time_team_batch_invalidate", args=[team_id]),
            "batch_remind_url": reverse("totp:one_time_team_batch_remind", args=[team_id]),
            "filter_chips": filter_chips,
            "quick_links": {
                "active": f'{reverse("totp:one_time_team_audit", args=[team_id])}?{active_params.urlencode()}',
                "last7": f'{reverse("totp:one_time_team_audit", args=[team_id])}?{last7_params.urlencode()}',
                "unvisited": f'{reverse("totp:one_time_team_audit", args=[team_id])}?{unvisited_params.urlencode()}',
            },
            "is_filtered": is_filtered,
            "page_window": page_window,
            "show_start_ellipsis": start > 2,
            "show_end_ellipsis": end < total_pages - 1,
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
    days_raw = (request.GET.get("days") or "").strip()
    unvisited = (request.GET.get("unvisited") or "").strip()

    queryset = OneTimeLink.objects.filter(entry__team_id=team_id).select_related(
        "entry",
        "entry__group",
        "entry__team",
        "created_by",
    )
    queryset, _days_value = _filter_one_time_link_queryset(
        queryset,
        now=now,
        status=status,
        q=q,
        days_raw=days_raw,
        unvisited=unvisited,
        creator=creator,
        team_id=team_id,
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

    response = StreamingHttpResponse(
        stream_rows(),
        content_type="text/csv; charset=utf-8",
    )
    response["Content-Disposition"] = 'attachment; filename="one_time_links_team_audit.csv"'
    return response


@login_required
@require_POST
def batch_invalidate_one_time_links_team(request, team_id: int):
    _get_team_membership(request.user, team_id, require_manage=True)
    if not _has_recent_reauth(request):
        return _reauth_json(request)

    try:
        data = (
            json.loads(request.body.decode("utf-8") or "{}")
            if (request.content_type or "").startswith("application/json")
            else request.POST
        )
    except json.JSONDecodeError:
        data = request.POST
    if not isinstance(data, dict):
        data = request.POST

    ids = _parse_ids(data.get("ids") or [])
    if not ids:
        return JsonResponse({"ok": False, "message": "请选择要失效的链接"}, status=400)

    now = timezone.now()
    links = list(
        OneTimeLink.objects.filter(entry__team_id=team_id, id__in=ids).select_related(
            "entry",
            "entry__team",
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
        expires_at=now,
        revoked_at=now,
        updated_at=now,
    )
    for link in links:
        if link.id not in active_ids:
            continue
        log_entry_audit(
            link.entry,
            request.user,
            TOTPEntryAudit.Action.ONE_TIME_LINK_REVOKED,
            old_value=link.entry.name,
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

    try:
        data = (
            json.loads(request.body.decode("utf-8") or "{}")
            if (request.content_type or "").startswith("application/json")
            else request.POST
        )
    except json.JSONDecodeError:
        data = request.POST
    if not isinstance(data, dict):
        data = request.POST

    ids = _parse_ids(data.get("ids") or [])
    if not ids:
        return JsonResponse({"ok": False, "message": "请选择要提醒的链接"}, status=400)

    now = timezone.now()
    links = list(
        OneTimeLink.objects.filter(entry__team_id=team_id, id__in=ids).select_related(
            "entry",
            "entry__team",
            "created_by",
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

    audit_url = request.build_absolute_uri(reverse("totp:one_time_team_audit", args=[team_id]))
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
            metadata={"count": len(items), "link_ids": [link.id for link in items][:50]},
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

    try:
        data = (
            json.loads(request.body.decode("utf-8") or "{}")
            if (request.content_type or "").startswith("application/json")
            else request.POST
        )
    except json.JSONDecodeError:
        data = request.POST
    if not isinstance(data, dict):
        data = request.POST

    ids = _parse_ids(data.get("ids") or [])
    if not ids:
        return JsonResponse({"ok": False, "message": "请选择要失效的链接"}, status=400)

    now = timezone.now()
    links = list(
        _creator_accessible_one_time_links(request.user).filter(id__in=ids).select_related(
            "entry",
            "entry__team",
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
        expires_at=now,
        revoked_at=now,
        updated_at=now,
    )
    for link in links:
        if link.id not in active_ids:
            continue
        log_entry_audit(
            link.entry,
            request.user,
            TOTPEntryAudit.Action.ONE_TIME_LINK_REVOKED,
            old_value=link.entry.name,
            metadata={
                "space": "team" if link.entry.team_id else "personal",
                "one_time_link_id": link.id,
                "batch": True,
            },
        )

    return JsonResponse({"ok": True, "updated": len(active_ids), "requested": len(ids)})


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
    from . import views as root_views

    try:
        duration_minutes = int(request.POST.get("duration") or 10)
    except (TypeError, ValueError):
        duration_minutes = 10
    duration_minutes = max(
        1,
        min(duration_minutes, root_views.TEAM_ONE_TIME_LINK_MAX_DURATION_MINUTES),
    )

    try:
        max_views = int(request.POST.get("max_views") or 3)
    except (TypeError, ValueError):
        max_views = 3
    max_views = max(1, min(max_views, 10))

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
        if team_active_links >= root_views.TEAM_ONE_TIME_LINK_ACTIVE_LIMIT:
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
        candidate = secrets.token_urlsafe(32)
        try:
            link = OneTimeLink.objects.create(
                entry=entry,
                created_by=request.user,
                token_hash=hashlib.sha256(candidate.encode()).hexdigest(),
                expires_at=expires_at,
                max_views=max_views,
                note=note,
            )
        except IntegrityError:
            continue
        token = candidate
        break
    if not token or link is None:
        return JsonResponse({"ok": False, "error": "token_generation_failed"}, status=500)

    path = reverse("totp:one_time_view", args=[token])
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
            "path": path,
            "url": request.build_absolute_uri(path),
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
        _creator_accessible_one_time_links(request.user).select_related("entry", "entry__team"),
        pk=pk,
    )
    log_entry_audit(
        link.entry,
        request.user,
        TOTPEntryAudit.Action.ONE_TIME_LINK_REVOKED,
        old_value=link.entry.name,
        metadata={
            "space": "team" if link.entry.team_id else "personal",
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

    max_body_bytes = int(getattr(settings, "EXTERNAL_TOTP_MAX_BODY_BYTES", 4096) or 4096)
    raw_body = request.body or b""
    if max_body_bytes > 0 and len(raw_body) > max_body_bytes:
        return JsonResponse(
            {"ok": False, "message": "请求体过大，请精简后重试"},
            status=413,
        )

    if request.GET.get("secret"):
        return JsonResponse(
            {"ok": False, "message": "请使用 POST 方式提交 secret"},
            status=400,
        )

    try:
        data = (
            json.loads(raw_body.decode("utf-8") or "{}")
            if (request.content_type or "").startswith("application/json")
            else request.POST
        )
    except json.JSONDecodeError:
        data = request.POST
    if not isinstance(data, dict):
        data = request.POST

    secret_raw = (data.get("secret") or "").strip()
    if not secret_raw:
        return JsonResponse({"ok": False, "message": "缺少 secret 参数"}, status=400)
    max_secret_length = int(getattr(settings, "EXTERNAL_TOTP_MAX_SECRET_LENGTH", 256) or 256)
    if max_secret_length > 0 and len(secret_raw) > max_secret_length:
        return JsonResponse({"ok": False, "message": "密钥长度超出限制"}, status=400)

    secret = normalize_google_secret(secret_raw)
    if not secret:
        return JsonResponse({"ok": False, "message": "密钥格式无效"}, status=400)

    try:
        digits_int = int(data.get("digits") or "6")
    except (TypeError, ValueError):
        digits_int = 6
    digits_int = min(max(digits_int, 4), 8)

    try:
        period_int = int(data.get("period") or "30")
    except (TypeError, ValueError):
        period_int = 30
    period_int = min(max(period_int, 15), 120)

    timestamp = int(timezone.now().timestamp())
    code, remaining = totp_code_base32(
        secret,
        digits=digits_int,
        period=period_int,
        timestamp=timestamp,
    )
    return JsonResponse(
        {
            "ok": True,
            "code": code,
            "remaining": remaining,
            "period": period_int,
            "digits": digits_int,
            "timestamp": timestamp,
            "secret_preview": _secret_preview(secret),
        },
        status=200,
    )


@never_cache
@require_GET
def external_totp_tool(request):
    """展示一个外部验证码生成工具页面。"""

    if not getattr(settings, "EXTERNAL_TOOL_ENABLED", False):
        raise Http404("Not found")

    max_secret_length = int(getattr(settings, "EXTERNAL_TOTP_MAX_SECRET_LENGTH", 256) or 256)
    return render(
        request,
        "totp/external_tool.html",
        {
            "prefill_secret": (
                (request.GET.get("secret") or "").strip()[:max_secret_length]
                if getattr(settings, "EXTERNAL_TOOL_ALLOW_SECRET_PREFILL", False)
                else ""
            ),
            "prefill_digits": (request.GET.get("digits") or "6").strip(),
            "prefill_period": (request.GET.get("period") or "30").strip(),
            "digits_choices": ["4", "5", "6", "7", "8"],
            "period_choices": ["15", "20", "30", "45", "60", "90", "120"],
        },
    )


@never_cache
def one_time_view(request, token: str):
    """展示一次性访问链接的验证码。"""

    token = (token or "").strip()
    if not token:
        return _render_one_time_invalid(request, reason="not_found")

    try:
        with transaction.atomic():
            link = (
                OneTimeLink.objects.select_for_update()
                .select_related("entry", "entry__user", "entry__group", "created_by")
                .get(token_hash=hashlib.sha256(token.encode()).hexdigest())
            )
            if not link.is_active:
                return _render_one_time_invalid(
                    request,
                    reason=_resolve_link_inactive_reason(link),
                )
            try:
                link.mark_view(request)
            except ValueError:
                return _render_one_time_invalid(
                    request,
                    reason=_resolve_link_inactive_reason(link),
                )
    except OneTimeLink.DoesNotExist:
        return _render_one_time_invalid(request, reason="not_found")

    secret = decrypt_str(link.entry.secret_encrypted)
    code, remaining = totp_code_base32(secret, digits=6, period=30)
    return render(
        request,
        "totp/one_time_link.html",
        {
            "link": link,
            "entry": link.entry,
            "code": code,
            "remaining": remaining,
            "owner": link.created_by,
            "remaining_views": max(0, link.max_views - link.view_count),
            "expires_at": link.expires_at,
        },
    )


def _render_one_time_invalid(request, reason: str, status: int | None = None):
    status_map = {
        "not_found": 404,
        "deleted": 410,
        "expired": 410,
        "used": 410,
        "revoked": 410,
    }
    return render(
        request,
        "totp/one_time_link.html",
        {"reason": reason},
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
