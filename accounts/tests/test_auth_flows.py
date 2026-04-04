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
