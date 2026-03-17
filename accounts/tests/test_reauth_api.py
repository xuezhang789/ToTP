import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class ReauthApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="reauth_api_user", password="StrongPassword123!")

    def test_reauth_api_sets_session_on_success(self):
        self.client.force_login(self.user)
        url = reverse("accounts:reauth_api")
        res = self.client.post(
            url,
            data=json.dumps({"password": "StrongPassword123!"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("ok"), True)
        self.assertTrue(self.client.session.get("reauth_at"))

    def test_reauth_api_rejects_wrong_password(self):
        self.client.force_login(self.user)
        url = reverse("accounts:reauth_api")
        res = self.client.post(
            url,
            data=json.dumps({"password": "wrong"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json().get("ok"), False)
        self.assertEqual(res.json().get("error"), "wrong_password")

