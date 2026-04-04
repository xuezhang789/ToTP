from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse


class LoginSecurityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = get_user_model().objects.create_user(
            username="secure_login_user",
            password="StrongPassword123!",
            email="secure_login_user@example.com",
        )
        self.url = reverse("accounts:login")

    @override_settings(AUTH_LOGIN_CHALLENGE_THRESHOLD=2)
    def test_login_requires_challenge_after_repeated_failures(self):
        for _ in range(2):
            response = self.client.post(
                self.url,
                {"username": self.user.username, "password": "wrong-password"},
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.get(self.url)
        self.assertContains(response, "安全校验")

        challenge_answer = self.client.session["auth_login_challenge_v1"]["answer"]
        success = self.client.post(
            self.url,
            {
                "username": self.user.username,
                "password": "StrongPassword123!",
                "challenge_answer": challenge_answer,
            },
        )

        self.assertEqual(success.status_code, 302)
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))

    @override_settings(AUTH_LOGIN_IP_RATE_LIMIT=3, AUTH_LOGIN_IP_RATE_WINDOW_SECONDS=300)
    def test_login_ip_total_rate_limit_blocks_username_spray(self):
        for idx in range(3):
            response = self.client.post(
                self.url,
                {"username": f"unknown-{idx}", "password": "wrong-password"},
            )
            self.assertEqual(response.status_code, 200)

        limited = self.client.post(
            self.url,
            {"username": self.user.username, "password": "StrongPassword123!"},
        )

        self.assertEqual(limited.status_code, 429)
        messages = [str(message) for message in limited.context["messages"]]
        self.assertTrue(any("登录请求过于频繁" in message for message in messages))

    @override_settings(AUTH_LOGIN_CHALLENGE_THRESHOLD=1)
    def test_login_challenge_rejects_missing_answer(self):
        self.client.post(
            self.url,
            {"username": self.user.username, "password": "wrong-password"},
        )

        response = self.client.post(
            self.url,
            {"username": self.user.username, "password": "StrongPassword123!"},
        )

        self.assertEqual(response.status_code, 400)
        messages = [str(message) for message in response.context["messages"]]
        self.assertTrue(any("安全校验" in message for message in messages))
