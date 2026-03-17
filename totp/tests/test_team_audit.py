from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import Team, TeamAudit, TeamMembership, log_team_audit
from datetime import timedelta


class TeamAuditViewTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user("owner", password="testpass")
        self.admin = user_model.objects.create_user("admin", password="testpass")
        self.member = user_model.objects.create_user("member", password="testpass")
        self.team = Team.objects.create(owner=self.owner, name="Alpha Team")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=self.team, user=self.admin, role=TeamMembership.Role.ADMIN)
        TeamMembership.objects.create(team=self.team, user=self.member, role=TeamMembership.Role.MEMBER)
        log_team_audit(self.team, self.owner, TeamAudit.Action.TEAM_RENAMED, old_value="A", new_value="B")
        old_record = TeamAudit.objects.create(
            team=self.team,
            actor=self.owner,
            action=TeamAudit.Action.MEMBER_REMOVED,
            old_value="old_rm",
            new_value="",
            metadata={"reason": "test"},
        )
        TeamAudit.objects.filter(pk=old_record.pk).update(
            created_at=timezone.now() - timedelta(days=10)
        )
        log_team_audit(self.team, self.owner, TeamAudit.Action.MEMBER_REMOVED, old_value="new_rm")

    def test_requires_login(self):
        res = self.client.get(reverse("totp:team_audit", args=[self.team.id]))
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/login/", res.url)

    def test_member_cannot_access_team_audit(self):
        self.client.force_login(self.member)
        res = self.client.get(reverse("totp:team_audit", args=[self.team.id]))
        self.assertEqual(res.status_code, 404)

    def test_admin_can_view_team_audit(self):
        self.client.force_login(self.admin)
        res = self.client.get(reverse("totp:team_audit", args=[self.team.id]))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("团队审计", html)
        self.assertIn("共 3 条", html)

    def test_filters_are_preserved_in_export_link(self):
        self.client.force_login(self.owner)
        url = reverse("totp:team_audit", args=[self.team.id]) + "?action=team_renamed&q=owner"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn(reverse("totp:team_audit_export", args=[self.team.id]) + "?action=team_renamed", html)
        self.assertIn("q=owner", html)

    def test_quick_filter_high_risk(self):
        self.client.force_login(self.owner)
        url = reverse("totp:team_audit", args=[self.team.id]) + "?risk=high"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("只看高风险", html)
        self.assertNotIn(">B</div>", html)
        self.assertIn("移除成员", html)

    def test_quick_filter_last_7_days(self):
        self.client.force_login(self.owner)
        url = reverse("totp:team_audit", args=[self.team.id]) + "?days=7"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("最近 7 天", html)
        self.assertNotIn("old_rm", html)

    def test_export_csv(self):
        self.client.force_login(self.owner)
        res = self.client.get(reverse("totp:team_audit_export", args=[self.team.id]))
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/csv", res["Content-Type"])
        content = res.content.decode("utf-8", errors="ignore")
        self.assertIn("时间,动作,操作人,目标用户,旧值,新值,详情", content)
