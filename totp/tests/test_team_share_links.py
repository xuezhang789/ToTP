from datetime import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from urllib.parse import parse_qs, urlparse

from totp.models import OneTimeLink, Team, TeamAudit, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class TeamShareLinkTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user("owner", password="testpass")
        self.team = Team.objects.create(owner=self.owner, name="Alpha Team")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        self.entry_a = TOTPEntry.objects.create(
            user=self.owner,
            team=self.team,
            name="GitHub",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        self.entry_b = TOTPEntry.objects.create(
            user=self.owner,
            team=self.team,
            name="GitLab",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

    def _reauth(self):
        self.client.force_login(self.owner)
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()

    def test_team_share_link_duration_is_capped(self):
        self._reauth()
        res = self.client.post(
            reverse("totp:one_time_create", args=[self.entry_a.id]),
            {"duration": 99999, "max_views": 1},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["ok"])
        expires_at = datetime.fromisoformat(data["expires_at"])
        delta = expires_at - timezone.now()
        self.assertLessEqual(delta.total_seconds(), 12 * 60 * 60 + 10)

    def test_team_share_link_quota_blocks_creation(self):
        self._reauth()
        with patch("totp.views.TEAM_ONE_TIME_LINK_ACTIVE_LIMIT", 1):
            first = self.client.post(
                reverse("totp:one_time_create", args=[self.entry_a.id]),
                {"duration": 5, "max_views": 1},
            )
            self.assertEqual(first.status_code, 200)
            self.assertTrue(first.json()["ok"])
            second = self.client.post(
                reverse("totp:one_time_create", args=[self.entry_b.id]),
                {"duration": 5, "max_views": 1},
            )
            self.assertEqual(second.status_code, 400)
            payload = second.json()
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"], "team_link_limit_reached")

    def test_owner_can_revoke_all_team_share_links(self):
        self._reauth()
        self.client.post(reverse("totp:one_time_create", args=[self.entry_a.id]), {"duration": 5, "max_views": 1})
        self.client.post(reverse("totp:one_time_create", args=[self.entry_b.id]), {"duration": 5, "max_views": 1})
        self.assertTrue(OneTimeLink.active.filter(entry__team=self.team).exists())
        res = self.client.post(reverse("totp:team_revoke_all_share_links", args=[self.team.id]))
        self.assertEqual(res.status_code, 302)
        self.assertFalse(OneTimeLink.active.filter(entry__team=self.team).exists())
        self.assertTrue(
            TeamAudit.objects.filter(team=self.team, action=TeamAudit.Action.LINKS_REVOKED_ALL).exists()
        )

    def test_reauth_redirect_for_post_action_goes_back_to_referer(self):
        self.client.force_login(self.owner)
        res = self.client.post(
            reverse("totp:team_revoke_all_share_links", args=[self.team.id]),
            HTTP_REFERER=reverse("totp:teams"),
        )
        self.assertEqual(res.status_code, 302)
        location = res["Location"]
        self.assertTrue(location.startswith(reverse("accounts:reauth")))
        query = parse_qs(urlparse(location).query)
        self.assertEqual(query.get("next"), [reverse("totp:teams")])
