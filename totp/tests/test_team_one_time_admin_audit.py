import hashlib
import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, Team, TeamAudit, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class TeamOneTimeAdminAuditTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user("owner2", password="testpass", email="owner2@example.com")
        self.admin = User.objects.create_user("admin2", password="testpass", email="admin2@example.com")
        self.member = User.objects.create_user("member2", password="testpass", email="member2@example.com")
        self.team = Team.objects.create(owner=self.owner, name="Beta Team")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=self.team, user=self.admin, role=TeamMembership.Role.ADMIN)
        TeamMembership.objects.create(team=self.team, user=self.member, role=TeamMembership.Role.MEMBER)
        self.entry = TOTPEntry.objects.create(
            user=self.owner,
            team=self.team,
            name="PagerDuty",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

    def _create_link(self, created_by, token_seed, **kwargs):
        now = timezone.now()
        return OneTimeLink.objects.create(
            entry=self.entry,
            created_by=created_by,
            token_hash=hashlib.sha256(token_seed.encode()).hexdigest(),
            expires_at=now + timedelta(minutes=10),
            max_views=3,
            **kwargs,
        )

    def _reauth(self):
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()

    def test_team_audit_requires_manage_role(self):
        self.client.force_login(self.member)
        res = self.client.get(reverse("totp:one_time_team_audit", args=[self.team.id]))
        self.assertEqual(res.status_code, 404)

    def test_team_audit_can_filter_by_creator(self):
        link_owner = self._create_link(self.owner, "t-owner")
        link_admin = self._create_link(self.admin, "t-admin")
        self.client.force_login(self.owner)
        res_all = self.client.get(reverse("totp:one_time_team_audit", args=[self.team.id]))
        self.assertEqual(res_all.status_code, 200)
        content = res_all.content.decode("utf-8")
        self.assertIn("owner2", content)
        self.assertIn("admin2", content)

        res_owner = self.client.get(
            reverse("totp:one_time_team_audit", args=[self.team.id]) + f"?creator={self.owner.id}"
        )
        content_owner = res_owner.content.decode("utf-8")
        self.assertIn("创建人：owner2", content_owner)
        self.assertNotIn("创建人：admin2", content_owner)
        self.assertNotIn("\n                        admin2\n                    </td>", content_owner)

    def test_team_batch_remind_sends_emails_and_logs_audit(self):
        link1 = self._create_link(self.owner, "remind-1", note="rotate")
        link2 = self._create_link(self.admin, "remind-2")
        self.client.force_login(self.owner)
        self._reauth()
        url = reverse("totp:one_time_team_batch_remind", args=[self.team.id])
        res = self.client.post(
            url,
            data=json.dumps({"ids": [link1.id, link2.id]}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["reminded_users"], 2)
        self.assertEqual(payload["reminded_links"], 2)
        self.assertEqual(payload["skipped_no_email"], 0)
        self.assertEqual(len(mail.outbox), 2)
        all_bodies = "\n".join(m.body for m in mail.outbox)
        self.assertIn("PagerDuty", all_bodies)
        self.assertIn(str(link1.id), all_bodies)
        self.assertIn(str(link2.id), all_bodies)
        self.assertTrue(
            TeamAudit.objects.filter(team=self.team, action=TeamAudit.Action.LINKS_REVOKE_REMINDER_SENT).exists()
        )
