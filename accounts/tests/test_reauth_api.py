import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from accounts.views import REAUTH_RATE_LIMIT


class ReauthApiTests(TestCase):
    def setUp(self):
        cache.clear()
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

    def test_reauth_api_rate_limits_repeated_failures(self):
        self.client.force_login(self.user)
        url = reverse("accounts:reauth_api")

        for _ in range(REAUTH_RATE_LIMIT):
            res = self.client.post(
                url,
                data=json.dumps({"password": "wrong"}),
                content_type="application/json",
            )
            self.assertEqual(res.status_code, 403)

        res = self.client.post(
            url,
            data=json.dumps({"password": "wrong"}),
            content_type="application/json",
        )

        self.assertEqual(res.status_code, 429)
        self.assertEqual(res.json().get("error"), "rate_limited")

    def test_reauth_api_preserves_password_whitespace(self):
        user_model = get_user_model()
        spaced_user = user_model.objects.create_user(
            username="reauth_space_user",
            password=" LeadingAndTrailing123! ",
        )
        self.client.force_login(spaced_user)
        url = reverse("accounts:reauth_api")

        res = self.client.post(
            url,
            data=json.dumps({"password": " LeadingAndTrailing123! "}),
            content_type="application/json",
        )

        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json().get("ok"))
