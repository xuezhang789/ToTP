from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class AuthFlowRegressionTests(TestCase):
    def test_signup_redirects_to_safe_next_url(self):
        next_url = reverse("totp:list")
        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "nextuser",
                "email": "nextuser@example.com",
                "password": "EvenStronger456!",
                "next": next_url,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)

    def test_signup_rejects_password_with_outer_whitespace(self):
        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "spaceuser",
                "email": "spaceuser@example.com",
                "password": " EvenStronger456! ",
            },
        )

        self.assertEqual(response.status_code, 400)
        messages = [str(message) for message in response.context["messages"]]
        self.assertTrue(any("密码不能包含空白字符" in message for message in messages))

    def test_login_preserves_password_whitespace(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username="space_login_user",
            password=" LeadingAndTrailing123! ",
            email="space_login_user@example.com",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {
                "username": user.username,
                "password": " LeadingAndTrailing123! ",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session.get("_auth_user_id"), str(user.pk))

    def test_login_supports_case_insensitive_email_identifier(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username="email_login_user",
            password="StrongPassword123!",
            email="EmailLoginUser@example.com",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {
                "username": "emailloginuser@example.com",
                "password": "StrongPassword123!",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session.get("_auth_user_id"), str(user.pk))

    def test_login_prefers_exact_username_over_same_value_email(self):
        user_model = get_user_model()
        user_model.objects.create_user(
            username="shared@example.com",
            password="UsernameOwner123!",
            email="username-owner@example.com",
        )
        user_model.objects.create_user(
            username="email_owner_user",
            password="EmailOwner123!",
            email="shared@example.com",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {
                "username": "shared@example.com",
                "password": "EmailOwner123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        messages = [str(message) for message in response.context["messages"]]
        self.assertTrue(any("账号或密码错误" in message for message in messages))

    def test_logout_redirects_back_to_login_with_signed_out_state(self):
        user = get_user_model().objects.create_user(
            username="logout_flow_user",
            password="StrongPassword123!",
        )
        self.client.force_login(user)

        response = self.client.post(reverse("accounts:logout"), follow=True)

        self.assertRedirects(response, f"{reverse('accounts:login')}?logged_out=1")
        self.assertNotIn("_auth_user_id", self.client.session)
        messages = [str(message) for message in response.context["messages"]]
        self.assertTrue(any("安全退出" in message for message in messages))
