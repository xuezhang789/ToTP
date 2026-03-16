from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamAudit, TeamMembership


class TeamAuditExportTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user(
            username="owner",
            password="StrongPassword123!",
        )
        self.member = user_model.objects.create_user(
            username="member",
            password="StrongPassword123!",
        )
        self.team = Team.objects.create(owner=self.owner, name="Team A")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=self.team, user=self.member, role=TeamMembership.Role.MEMBER)

    def test_export_requires_manager_role(self):
        self.client.force_login(self.member)
        res = self.client.get(reverse("totp:team_audit_export", args=[self.team.id]))
        self.assertEqual(res.status_code, 404)

    def test_export_is_no_store_and_contains_csv(self):
        TeamAudit.objects.create(
            team=self.team,
            actor=self.owner,
            action=TeamAudit.Action.TEAM_CREATED,
            old_value="",
            new_value="Team A",
            metadata={"source": "test"},
        )
        self.client.force_login(self.owner)
        res = self.client.get(reverse("totp:team_audit_export", args=[self.team.id]))
        self.assertEqual(res.status_code, 200)
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))
        self.assertEqual(res.headers.get("Pragma"), "no-cache")
        content = res.content.decode("utf-8")
        self.assertTrue(content.startswith("\ufeff"))
        self.assertIn("时间,动作,操作人,目标用户,旧值,新值,详情", content)
