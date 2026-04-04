from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .models import TeamAsset, TeamMembership, TOTPEntry
from .views import TEAM_ASSET_NAME_MAX_LENGTH, _get_team_membership


def _parse_int_list(values, *, limit=200):
    ids: list[int] = []
    for item in values or []:
        try:
            value = int(item)
        except (TypeError, ValueError):
            continue
        if value > 0:
            ids.append(value)
    ids = list(dict.fromkeys(ids))
    return ids[:limit]


@login_required
def team_assets(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=False)
    team = membership.team
    q = (request.GET.get("q") or "").strip()
    all_assets = TeamAsset.objects.filter(team=team)
    queryset = all_assets.prefetch_related("owners", "watchers")
    if q:
        queryset = queryset.filter(
            Q(name__icontains=q)
            | Q(description__icontains=q)
            | Q(owners__username__icontains=q)
            | Q(watchers__username__icontains=q)
        ).distinct()
    assets = list(
        queryset.annotate(
            entry_count=Count("entries", filter=Q(entries__is_deleted=False)),
        ).order_by("name")
    )
    entry_summary = TOTPEntry.objects.filter(team=team, is_deleted=False).aggregate(
        entry_total=Count("id"),
        unassigned_entries=Count("id", filter=Q(asset__isnull=True)),
    )
    return render(
        request,
        "totp/team_assets.html",
        {
            "team": team,
            "membership": membership,
            "can_manage": membership.can_manage_entries,
            "q": q,
            "assets": assets,
            "asset_summary": {
                "asset_total": all_assets.count(),
                "member_total": TeamMembership.objects.filter(team=team).count(),
                "entry_total": entry_summary.get("entry_total") or 0,
                "unassigned_entries": entry_summary.get("unassigned_entries") or 0,
            },
        },
    )


@login_required
@require_GET
def team_asset_options(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    assets = list(
        TeamAsset.objects.filter(team=membership.team).order_by("name").values("id", "name")
    )
    return JsonResponse({"ok": True, "assets": assets})


@login_required
@require_http_methods(["GET", "POST"])
def team_asset_create(request, team_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    members = (
        TeamMembership.objects.filter(team=team)
        .select_related("user")
        .order_by("user__username")
    )
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        description = (request.POST.get("description") or "").strip()
        owner_ids = request.POST.getlist("owners")
        watcher_ids = request.POST.getlist("watchers")
        if not name:
            messages.error(request, "资产名称不能为空")
            return render(
                request,
                "totp/team_asset_form.html",
                {
                    "team": team,
                    "membership": membership,
                    "members": members,
                    "asset": None,
                    "form": {
                        "name": name,
                        "description": description,
                        "owners": owner_ids,
                        "watchers": watcher_ids,
                    },
                },
                status=400,
            )
        if len(name) > TEAM_ASSET_NAME_MAX_LENGTH:
            messages.error(request, "资产名称过长")
            return render(
                request,
                "totp/team_asset_form.html",
                {
                    "team": team,
                    "membership": membership,
                    "members": members,
                    "asset": None,
                    "form": {
                        "name": name,
                        "description": description,
                        "owners": owner_ids,
                        "watchers": watcher_ids,
                    },
                },
                status=400,
            )
        try:
            with transaction.atomic():
                asset = TeamAsset.objects.create(team=team, name=name, description=description)
        except IntegrityError:
            messages.error(request, "已存在同名资产，请更换名称")
            return render(
                request,
                "totp/team_asset_form.html",
                {
                    "team": team,
                    "membership": membership,
                    "members": members,
                    "asset": None,
                    "form": {
                        "name": name,
                        "description": description,
                        "owners": owner_ids,
                        "watchers": watcher_ids,
                    },
                },
                status=400,
            )
        allowed_user_ids = set(members.values_list("user_id", flat=True))
        owners = [int(v) for v in owner_ids if str(v).isdigit() and int(v) in allowed_user_ids]
        watchers = [int(v) for v in watcher_ids if str(v).isdigit() and int(v) in allowed_user_ids]
        asset.owners.set(owners)
        asset.watchers.set(watchers)
        messages.success(request, "资产已创建")
        return redirect("totp:team_asset_detail", team_id=team.id, asset_id=asset.id)
    return render(
        request,
        "totp/team_asset_form.html",
        {
            "team": team,
            "membership": membership,
            "members": members,
            "asset": None,
            "form": {
                "name": "",
                "description": "",
                "owners": [],
                "watchers": [],
            },
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def team_asset_edit(request, team_id: int, asset_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    asset = get_object_or_404(
        TeamAsset.objects.prefetch_related("owners", "watchers"),
        team=team,
        id=asset_id,
    )
    members = (
        TeamMembership.objects.filter(team=team)
        .select_related("user")
        .order_by("user__username")
    )
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        description = (request.POST.get("description") or "").strip()
        owner_ids = request.POST.getlist("owners")
        watcher_ids = request.POST.getlist("watchers")
        if not name:
            messages.error(request, "资产名称不能为空")
            return render(
                request,
                "totp/team_asset_form.html",
                {
                    "team": team,
                    "membership": membership,
                    "members": members,
                    "asset": asset,
                    "form": {
                        "name": name,
                        "description": description,
                        "owners": owner_ids,
                        "watchers": watcher_ids,
                    },
                },
                status=400,
            )
        if len(name) > TEAM_ASSET_NAME_MAX_LENGTH:
            messages.error(request, "资产名称过长")
            return render(
                request,
                "totp/team_asset_form.html",
                {
                    "team": team,
                    "membership": membership,
                    "members": members,
                    "asset": asset,
                    "form": {
                        "name": name,
                        "description": description,
                        "owners": owner_ids,
                        "watchers": watcher_ids,
                    },
                },
                status=400,
            )
        asset.name = name
        asset.description = description
        try:
            with transaction.atomic():
                asset.save(update_fields=["name", "description", "updated_at"])
        except IntegrityError:
            messages.error(request, "已存在同名资产，请更换名称")
            return render(
                request,
                "totp/team_asset_form.html",
                {
                    "team": team,
                    "membership": membership,
                    "members": members,
                    "asset": asset,
                    "form": {
                        "name": name,
                        "description": description,
                        "owners": owner_ids,
                        "watchers": watcher_ids,
                    },
                },
                status=400,
            )
        allowed_user_ids = set(members.values_list("user_id", flat=True))
        owners = [int(v) for v in owner_ids if str(v).isdigit() and int(v) in allowed_user_ids]
        watchers = [int(v) for v in watcher_ids if str(v).isdigit() and int(v) in allowed_user_ids]
        asset.owners.set(owners)
        asset.watchers.set(watchers)
        messages.success(request, "资产已更新")
        return redirect("totp:team_asset_detail", team_id=team.id, asset_id=asset.id)
    return render(
        request,
        "totp/team_asset_form.html",
        {
            "team": team,
            "membership": membership,
            "members": members,
            "asset": asset,
            "form": {
                "name": asset.name,
                "description": asset.description,
                "owners": [str(u.id) for u in asset.owners.all()],
                "watchers": [str(u.id) for u in asset.watchers.all()],
            },
        },
    )


@login_required
@require_POST
def team_asset_delete(request, team_id: int, asset_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    asset = get_object_or_404(TeamAsset, team=team, id=asset_id)
    TOTPEntry.objects.filter(team=team, asset=asset).update(asset=None)
    asset.delete()
    messages.success(request, "资产已删除")
    return redirect("totp:team_assets", team_id=team.id)


@login_required
def team_asset_detail(request, team_id: int, asset_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=False)
    team = membership.team
    asset = get_object_or_404(
        TeamAsset.objects.prefetch_related("owners", "watchers"),
        team=team,
        id=asset_id,
    )
    entries = list(
        TOTPEntry.objects.filter(team=team, asset=asset, is_deleted=False)
        .select_related("group")
        .order_by("name")
    )
    unassigned = list(
        TOTPEntry.objects.filter(team=team, asset__isnull=True, is_deleted=False)
        .select_related("group")
        .order_by("name")
    )
    return render(
        request,
        "totp/team_asset_detail.html",
        {
            "team": team,
            "membership": membership,
            "can_manage": membership.can_manage_entries,
            "asset": asset,
            "entries": entries,
            "unassigned_entries": unassigned,
            "detail_summary": {
                "entry_total": len(entries),
                "unassigned_total": len(unassigned),
                "owner_total": len(asset.owners.all()),
                "watcher_total": len(asset.watchers.all()),
            },
        },
    )


@login_required
@require_POST
def team_asset_assign_entries(request, team_id: int, asset_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    asset = get_object_or_404(TeamAsset, team=team, id=asset_id)
    entry_ids = _parse_int_list(request.POST.getlist("entry_ids"), limit=200)
    if not entry_ids:
        messages.error(request, "请选择要关联的密钥")
        return redirect("totp:team_asset_detail", team_id=team.id, asset_id=asset.id)
    updated = TOTPEntry.objects.filter(team=team, id__in=entry_ids, is_deleted=False).update(asset=asset)
    if updated:
        messages.success(request, f"已关联 {updated} 个密钥")
    return redirect("totp:team_asset_detail", team_id=team.id, asset_id=asset.id)


@login_required
@require_POST
def team_asset_remove_entries(request, team_id: int, asset_id: int):
    membership = _get_team_membership(request.user, team_id, require_manage=True)
    team = membership.team
    asset = get_object_or_404(TeamAsset, team=team, id=asset_id)
    entry_ids = _parse_int_list(request.POST.getlist("entry_ids"), limit=200)
    if not entry_ids:
        messages.error(request, "请选择要移除的密钥")
        return redirect("totp:team_asset_detail", team_id=team.id, asset_id=asset.id)
    updated = TOTPEntry.objects.filter(team=team, asset=asset, id__in=entry_ids).update(asset=None)
    if updated:
        messages.success(request, f"已移除 {updated} 个密钥")
    return redirect("totp:team_asset_detail", team_id=team.id, asset_id=asset.id)
