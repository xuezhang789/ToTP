import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class GoogleOneTapTests(TestCase):
    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_onetap_creates_user_with_unusable_password(self, verify_mock):
        verify_mock.return_value = {
            "email": "newuser@example.com",
            "email_verified": True,
            "name": "New User",
            "sub": "sub-123",
        }
        res = self.client.post(
            reverse("accounts:google_onetap"),
            data=json.dumps({"credential": "fake"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["created"])

        User = get_user_model()
        user = User.objects.get(email="newuser@example.com")
        self.assertFalse(user.has_usable_password())

        self.client.force_login(user)
        res2 = self.client.get(reverse("accounts:reauth"))
        self.assertEqual(res2.status_code, 200)
        self.assertContains(res2, "该账号未设置本地密码")

    @patch("accounts.views._username_from_email")
    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_onetap_retries_when_generated_username_is_taken(self, verify_mock, username_mock):
        User = get_user_model()
        existing = User.objects.create_user(
            username="newuser",
            password="StrongPassword123!",
            email="old@example.com",
        )
        username_mock.side_effect = ["newuser", "newuser1"]
        verify_mock.return_value = {
            "email": "newuser@example.com",
            "email_verified": True,
            "name": "Collision User",
            "sub": "sub-456",
        }

        res = self.client.post(
            reverse("accounts:google_onetap"),
            data=json.dumps({"credential": "fake"}),
            content_type="application/json",
        )

        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["created"])

        created = User.objects.get(email="newuser@example.com")
        self.assertNotEqual(created.pk, existing.pk)
        self.assertEqual(created.username, "newuser1")
        self.assertEqual(self.client.session.get("_auth_user_id"), str(created.pk))

    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_onetap_rejects_inactive_existing_user(self, verify_mock):
        user_model = get_user_model()
        inactive_user = user_model.objects.create_user(
            username="inactive_google_user",
            password="StrongPassword123!",
            email="inactive@example.com",
            is_active=False,
        )
        verify_mock.return_value = {
            "email": inactive_user.email,
            "email_verified": True,
            "sub": "sub-inactive",
        }

        response = self.client.post(
            reverse("accounts:google_onetap"),
            data=json.dumps({"credential": "fake"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "account_disabled")
        self.assertNotIn("_auth_user_id", self.client.session)
