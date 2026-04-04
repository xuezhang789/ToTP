from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, Team, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class TeamAccessRevocationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user("team_owner", password="StrongPassword123!")
        self.member = User.objects.create_user("team_member", password="StrongPassword123!")
        self.team = Team.objects.create(owner=self.owner, name="Ops Team")
        TeamMembership.objects.create(
            team=self.team,
            user=self.owner,
            role=TeamMembership.Role.OWNER,
        )
        TeamMembership.objects.create(
            team=self.team,
            user=self.member,
            role=TeamMembership.Role.MEMBER,
        )
        self.entry = TOTPEntry.objects.create(
            user=self.member,
            team=self.team,
            name="Shared AWS",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        self.link = OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.member,
            token_hash="a" * 64,
            expires_at=timezone.now() + timedelta(minutes=10),
            max_views=3,
        )

    def _reauth(self):
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()

    def test_removed_member_loses_access_to_created_team_entries(self):
        self.client.force_login(self.member)
        self.assertTrue(TOTPEntry.objects.for_user(self.member).filter(pk=self.entry.pk).exists())

        TeamMembership.objects.filter(team=self.team, user=self.member).delete()

        self.assertFalse(TOTPEntry.objects.for_user(self.member).filter(pk=self.entry.pk).exists())

        list_response = self.client.get(reverse("totp:list") + f"?space=team:{self.team.id}")
        self.assertEqual(list_response.status_code, 404)

        tokens_response = self.client.get(
            reverse("totp:api_tokens") + f"?ids={self.entry.id}"
        )
        self.assertEqual(tokens_response.status_code, 200)
        self.assertEqual(tokens_response.json()["items"], [])

    def test_removed_member_cannot_manage_old_team_share_links(self):
        self.client.force_login(self.member)
        self._reauth()

        TeamMembership.objects.filter(team=self.team, user=self.member).delete()

        audit_response = self.client.get(reverse("totp:one_time_audit"))
        self.assertEqual(audit_response.status_code, 200)
        self.assertNotContains(audit_response, self.entry.name)

        revoke_response = self.client.post(
            reverse("totp:one_time_invalidate", args=[self.link.id])
        )
        self.assertEqual(revoke_response.status_code, 404)

        self.link.refresh_from_db()
        self.assertIsNone(self.link.revoked_at)
