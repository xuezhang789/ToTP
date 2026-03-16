from django.db.models import Count, Prefetch, Q

from .models import Group, Team, TeamMembership, TOTPEntry


def entries_queryset_for_list(*, user, selected_team: Team | None, q: str, group_id: str, asset_id: str = ""):
    if selected_team is not None:
        entry_qs = (
            TOTPEntry.objects.filter(team=selected_team)
            .select_related("team", "asset")
            .order_by("-created_at")
        )
        if asset_id == "0":
            entry_qs = entry_qs.filter(asset__isnull=True)
        elif asset_id:
            entry_qs = entry_qs.filter(asset_id=asset_id)
        groups = []
    else:
        entry_qs = (
            TOTPEntry.objects.filter(user=user, team__isnull=True)
            .select_related("group", "asset")
            .order_by("-created_at")
        )
        if group_id == "0":
            entry_qs = entry_qs.filter(group__isnull=True)
        elif group_id:
            entry_qs = entry_qs.filter(group_id=group_id)
        groups = (
            Group.objects.filter(user=user)
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

    entry_qs = entry_qs.select_related("group", "team", "asset").prefetch_related(
        Prefetch(
            "team__memberships",
            queryset=TeamMembership.objects.filter(user=user),
        )
    )
    return entry_qs, groups


def teams_queryset_for_overview(*, user, q: str):
    return (
        Team.objects.filter(memberships__user=user)
        .filter(Q(name__icontains=q) if q else Q())
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
                queryset=TeamMembership.objects.filter(user=user).select_related("user"),
            )
        )
        .order_by("name")
    )
