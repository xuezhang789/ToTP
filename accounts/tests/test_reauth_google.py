import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class GoogleReauthTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="alice", password="temp12345", email="alice@example.com")
        self.user.set_unusable_password()
        self.user.save(update_fields=["password"])

    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_reauth_sets_session(self, verify_mock):
        verify_mock.return_value = {
            "email": "alice@example.com",
            "email_verified": True,
        }
        self.client.force_login(self.user)
        res = self.client.post(
            reverse("accounts:reauth_google"),
            data=json.dumps({"credential": "fake"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["ok"])
        session = self.client.session
        self.assertIn("reauth_at", session)

    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_reauth_rejects_email_mismatch(self, verify_mock):
        verify_mock.return_value = {
            "email": "other@example.com",
            "email_verified": True,
        }
        self.client.force_login(self.user)
        res = self.client.post(
            reverse("accounts:reauth_google"),
            data=json.dumps({"credential": "fake"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 403)

