import json
import re
from unittest.mock import patch

import requests
from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, Team, TeamAsset, TeamAudit, TeamInvitation, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class EndToEndFlowTests(StaticLiveServerTestCase):
    host = "127.0.0.1"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user_model = get_user_model()

    def _absolute_url(self, path: str) -> str:
        return f"{self.live_server_url}{path}"

    def _extract_csrf_token(self, html: str) -> str:
        match = re.search(
            r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
            html,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def _fetch_csrf(self, session: requests.Session, path: str) -> tuple[str, str]:
        url = self._absolute_url(path)
        response = session.get(url, timeout=10)
        self.assertEqual(response.status_code, 200)
        token = self._extract_csrf_token(response.text)
        return url, token

    def _login(self, session: requests.Session, username: str, password: str):
        login_path = reverse("accounts:login")
        login_url, csrf_token = self._fetch_csrf(session, login_path)
        response = session.post(
            login_url,
            data={
                "csrfmiddlewaretoken": csrf_token,
                "username": username,
                "password": password,
                "next": "",
            },
            headers={"Referer": login_url},
            timeout=10,
            allow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_onetap_http_flow_creates_session_and_profile_access(self, verify_mock):
        verify_mock.return_value = {
            "email": "e2e-google@example.com",
            "email_verified": True,
            "name": "E2E Google User",
            "sub": "e2e-sub-123",
        }

        with requests.Session() as session:
            login_url, csrf_token = self._fetch_csrf(session, reverse("accounts:login"))
            response = session.post(
                self._absolute_url(reverse("accounts:google_onetap")),
                data=json.dumps({"credential": "fake-google-credential"}),
                headers={
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrf_token,
                    "Referer": login_url,
                },
                timeout=10,
            )

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertTrue(payload["ok"])

            profile = session.get(
                self._absolute_url(reverse("accounts:profile")),
                timeout=10,
            )
            self.assertEqual(profile.status_code, 200)
            self.assertIn("e2e-google@example.com", profile.text)

    def test_member_removal_revokes_asset_and_share_link_access_over_http(self):
        owner = self.user_model.objects.create_user(
            username="e2e_owner",
            password="StrongPass123!",
            email="owner@example.com",
        )
        member = self.user_model.objects.create_user(
            username="e2e_member",
            password="StrongPass123!",
            email="member@example.com",
        )
        team = Team.objects.create(owner=owner, name="E2E Team")
        TeamMembership.objects.create(team=team, user=owner, role=TeamMembership.Role.OWNER)
        member_membership = TeamMembership.objects.create(
            team=team,
            user=member,
            role=TeamMembership.Role.ADMIN,
        )
        asset = TeamAsset.objects.create(team=team, name="Critical Asset", description="")
        asset.owners.add(member)
        asset.watchers.add(member)
        entry = TOTPEntry.objects.create(
            user=owner,
            team=team,
            name="Shared Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        OneTimeLink.objects.create(
            entry=entry,
            created_by=member,
            token_hash="a" * 64,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            max_views=3,
        )

        with requests.Session() as owner_session, requests.Session() as member_session:
            self._login(owner_session, "e2e_owner", "StrongPass123!")
            self._login(member_session, "e2e_member", "StrongPass123!")

            audit_before = member_session.get(
                self._absolute_url(reverse("totp:one_time_audit")),
                timeout=10,
            )
            self.assertEqual(audit_before.status_code, 200)
            self.assertIn("Shared Entry", audit_before.text)

            teams_url, csrf_token = self._fetch_csrf(owner_session, reverse("totp:teams"))
            remove_response = owner_session.post(
                self._absolute_url(
                    reverse("totp:team_remove_member", args=[team.id, member_membership.id])
                ),
                data={"csrfmiddlewaretoken": csrf_token},
                headers={"Referer": teams_url},
                timeout=10,
                allow_redirects=True,
            )
            self.assertEqual(remove_response.status_code, 200)

            audit_after = member_session.get(
                self._absolute_url(reverse("totp:one_time_audit")),
                timeout=10,
            )
            self.assertEqual(audit_after.status_code, 200)
            self.assertNotIn("Shared Entry", audit_after.text)

            asset_detail = owner_session.get(
                self._absolute_url(reverse("totp:team_asset_detail", args=[team.id, asset.id])),
                timeout=10,
            )
            self.assertEqual(asset_detail.status_code, 200)
            self.assertNotIn("e2e_member", asset_detail.text)

    def test_team_risk_panel_http_flow_renders_high_risk_summary(self):
        owner = self.user_model.objects.create_user(
            username="risk_owner_e2e",
            password="StrongPass123!",
            email="risk-owner@example.com",
        )
        invitee = self.user_model.objects.create_user(
            username="risk_invitee_e2e",
            password="StrongPass123!",
            email="risk-invitee@example.com",
        )
        target = self.user_model.objects.create_user(
            username="risk_target_e2e",
            password="StrongPass123!",
            email="risk-target@example.com",
        )
        team = Team.objects.create(owner=owner, name="Risk Panel Team")
        TeamMembership.objects.create(team=team, user=owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=team, user=target, role=TeamMembership.Role.MEMBER)
        TeamInvitation.objects.create(
            team=team,
            inviter=owner,
            invitee=invitee,
            role=TeamMembership.Role.MEMBER,
        )
        entry = TOTPEntry.objects.create(
            user=owner,
            team=team,
            name="Risk Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=owner,
            team=team,
            name="Unassigned Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        OneTimeLink.objects.create(
            entry=entry,
            created_by=owner,
            token_hash="b" * 64,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            max_views=3,
            last_viewed_at=timezone.now(),
        )
        TeamAudit.objects.create(team=team, actor=owner, action=TeamAudit.Action.LINKS_REVOKED_ALL)
        TeamAudit.objects.create(
            team=team,
            actor=owner,
            action=TeamAudit.Action.MEMBER_ROLE_CHANGED,
            target_user=target,
        )

        with requests.Session() as session:
            self._login(session, "risk_owner_e2e", "StrongPass123!")
            response = session.get(
                self._absolute_url(reverse("totp:team_actions_panel", args=[team.id])),
                timeout=10,
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn("高风险", response.text)
            self.assertIn("撤销全部分享链接", response.text)
            self.assertIn("最近创建者", response.text)
            self.assertIn("分享链接", response.text)
            self.assertIn("邀请", response.text)
