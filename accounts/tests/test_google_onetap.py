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

