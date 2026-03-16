from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from django.utils import timezone

from totp.models import OneTimeLink, Team, TeamAudit, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class TeamActivityRiskPanelTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user("risk_owner", password="pass", email="risk_owner@example.com")
        self.other = User.objects.create_user("risk_other", password="pass", email="risk_other@example.com")
        self.team = Team.objects.create(owner=self.owner, name="Risk Team")
        self.owner_membership = TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=self.team, user=self.other, role=TeamMembership.Role.MEMBER)

    def test_high_risk_section_pins_items(self):
        TeamAudit.objects.create(team=self.team, actor=self.owner, action=TeamAudit.Action.INVITE_SENT)
        TeamAudit.objects.create(team=self.team, actor=self.owner, action=TeamAudit.Action.MEMBER_ROLE_CHANGED, target_user=self.other)
        TeamAudit.objects.create(team=self.team, actor=self.owner, action=TeamAudit.Action.LINKS_REVOKED_ALL)

        self.client.force_login(self.owner)
        url = reverse("totp:team_actions_panel", args=[self.team.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("高风险", html)
        self.assertIn("撤销全部分享链接", html)
        self.assertIn("成员角色调整", html)
        self.assertIn("bg-danger-subtle", html)
        self.assertIn("bg-warning-subtle", html)

        idx_risk = html.find("撤销全部分享链接")
        idx_recent = html.find("发送邀请")
        self.assertTrue(idx_risk != -1 and idx_recent != -1)
        self.assertLess(idx_risk, idx_recent)

    def test_high_risk_suggested_actions_show(self):
        entry = TOTPEntry.objects.create(
            user=self.owner,
            team=self.team,
            name="Risk Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        OneTimeLink.objects.create(
            entry=entry,
            created_by=self.owner,
            token_hash="x" * 64,
            expires_at=timezone.now() + timezone.timedelta(days=1),
            max_views=3,
            view_count=0,
            revoked_at=None,
            last_viewed_at=timezone.now(),
        )
        TeamAudit.objects.create(team=self.team, actor=self.owner, action=TeamAudit.Action.LINKS_REVOKED_ALL)

        self.client.force_login(self.owner)
        url = reverse("totp:team_actions_panel", args=[self.team.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("去审计", html)
        self.assertIn("去撤销", html)
        self.assertIn("撤销确认摘要", html)
        self.assertIn("继续撤销", html)
        self.assertIn("最近创建者", html)
        self.assertIn("最近创建时间", html)
        self.assertIn("最近访问时间", html)
        self.assertIn("已访问", html)
        self.assertIn(reverse("totp:team_audit", args=[self.team.id]), html)

    def test_high_risk_suggested_actions_show_unviewed_badge(self):
        entry = TOTPEntry.objects.create(
            user=self.owner,
            team=self.team,
            name="Risk Entry 2",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        OneTimeLink.objects.create(
            entry=entry,
            created_by=self.owner,
            token_hash="y" * 64,
            expires_at=timezone.now() + timezone.timedelta(days=1),
            max_views=3,
            view_count=0,
            revoked_at=None,
            last_viewed_at=None,
        )
        TeamAudit.objects.create(team=self.team, actor=self.owner, action=TeamAudit.Action.LINKS_REVOKED_ALL)

        self.client.force_login(self.owner)
        url = reverse("totp:team_actions_panel", args=[self.team.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("未访问", html)
