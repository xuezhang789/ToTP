from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, Team, TeamAsset, TeamInvitation, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class QueryCountGuardrailTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="queryguard",
            password="StrongPassword123!",
        )

    def test_list_view_query_count_is_bounded(self):
        self.client.force_login(self.user)
        for i in range(25):
            TOTPEntry.objects.create(
                user=self.user,
                name=f"Entry {i}",
                secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
            )
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:list"))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 25)

    def test_teams_overview_query_count_is_bounded(self):
        self.client.force_login(self.user)
        for i in range(8):
            team = Team.objects.create(owner=self.user, name=f"Team {i}")
            TeamMembership.objects.create(team=team, user=self.user, role=TeamMembership.Role.OWNER)
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:teams"))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 25)

    def test_team_home_query_count_is_bounded(self):
        self.client.force_login(self.user)
        team = Team.objects.create(owner=self.user, name="Perf Home")
        TeamMembership.objects.create(team=team, user=self.user, role=TeamMembership.Role.OWNER)
        asset = TeamAsset.objects.create(team=team, name="Infra")
        TOTPEntry.objects.create(
            user=self.user,
            team=team,
            asset=asset,
            name="Assigned Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=self.user,
            team=team,
            name="Unassigned Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TeamInvitation.objects.create(
            team=team,
            inviter=self.user,
            invitee=self.user,
            role=TeamMembership.Role.MEMBER,
        )
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:team_home", args=[team.id]))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 12)

    def test_team_actions_panel_query_count_is_bounded(self):
        self.client.force_login(self.user)
        team = Team.objects.create(owner=self.user, name="Perf Risk")
        TeamMembership.objects.create(team=team, user=self.user, role=TeamMembership.Role.OWNER)
        other = get_user_model().objects.create_user(
            username="perfmember",
            password="StrongPassword123!",
        )
        TeamMembership.objects.create(team=team, user=other, role=TeamMembership.Role.MEMBER)
        entry = TOTPEntry.objects.create(
            user=self.user,
            team=team,
            name="Risk Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TeamInvitation.objects.create(
            team=team,
            inviter=self.user,
            invitee=other,
            role=TeamMembership.Role.MEMBER,
        )
        for idx in range(3):
            OneTimeLink.objects.create(
                entry=entry,
                created_by=self.user,
                token_hash=f"{idx:064d}",
                expires_at=timezone.now() + timezone.timedelta(minutes=10),
                max_views=3,
                last_viewed_at=timezone.now() if idx % 2 == 0 else None,
            )
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:team_actions_panel", args=[team.id]))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 15)

    def test_team_assets_query_count_is_bounded(self):
        self.client.force_login(self.user)
        team = Team.objects.create(owner=self.user, name="Perf Assets")
        TeamMembership.objects.create(team=team, user=self.user, role=TeamMembership.Role.OWNER)
        asset = TeamAsset.objects.create(team=team, name="Infra")
        asset.owners.add(self.user)
        TOTPEntry.objects.create(
            user=self.user,
            team=team,
            asset=asset,
            name="Asset Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=self.user,
            team=team,
            name="Unassigned Asset Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:team_assets", args=[team.id]))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 10)
