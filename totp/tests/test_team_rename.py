from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamAudit, TeamMembership


class TeamRenameTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user("owner", password="testpass")
        self.admin = user_model.objects.create_user("admin", password="testpass")
        self.member = user_model.objects.create_user("member", password="testpass")

        self.team = Team.objects.create(owner=self.owner, name="Alpha Team")
        TeamMembership.objects.create(
            team=self.team,
            user=self.owner,
            role=TeamMembership.Role.OWNER,
        )
        TeamMembership.objects.create(
            team=self.team,
            user=self.admin,
            role=TeamMembership.Role.ADMIN,
        )
        TeamMembership.objects.create(
            team=self.team,
            user=self.member,
            role=TeamMembership.Role.MEMBER,
        )

    def test_owner_can_rename_team(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("totp:team_rename", args=[self.team.id]),
            {"name": "New Team Name"},
        )
        self.assertEqual(response.status_code, 302)
        self.team.refresh_from_db()
        self.assertEqual(self.team.name, "New Team Name")
        self.assertTrue(
            TeamAudit.objects.filter(
                team=self.team,
                action=TeamAudit.Action.TEAM_RENAMED,
                actor=self.owner,
            ).exists()
        )

    def test_admin_can_rename_team(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("totp:team_rename", args=[self.team.id]),
            {"name": "Admin Renamed"},
        )
        self.assertEqual(response.status_code, 302)
        self.team.refresh_from_db()
        self.assertEqual(self.team.name, "Admin Renamed")
        self.assertTrue(
            TeamAudit.objects.filter(
                team=self.team,
                action=TeamAudit.Action.TEAM_RENAMED,
                actor=self.admin,
            ).exists()
        )

    def test_member_cannot_rename_team(self):
        self.client.force_login(self.member)
        response = self.client.post(
            reverse("totp:team_rename", args=[self.team.id]),
            {"name": "Member Renamed"},
        )
        self.assertEqual(response.status_code, 404)
        self.team.refresh_from_db()
        self.assertEqual(self.team.name, "Alpha Team")

    def test_rename_rejects_duplicate_name_for_owner(self):
        another_team = Team.objects.create(owner=self.owner, name="Beta Team")
        TeamMembership.objects.create(
            team=another_team,
            user=self.owner,
            role=TeamMembership.Role.OWNER,
        )

        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("totp:team_rename", args=[self.team.id]),
            {"name": "Beta Team"},
        )
        self.assertEqual(response.status_code, 302)
        self.team.refresh_from_db()
        self.assertEqual(self.team.name, "Alpha Team")

    def test_create_rejects_overlong_name(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("totp:team_create"),
            {"name": "X" * 81},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Team.objects.filter(owner=self.owner, name="X" * 81).exists())
