from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class ProfileViewTests(TestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            username="alice",
            password="StrongPass123!",
            email="old@example.com",
        )

    def test_requires_login(self):
        response = self.client.get(reverse("accounts:profile"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login/", response.url)

    def test_update_profile_success(self):
        self.client.force_login(self.user)
        payload = {
            "first_name": "Alice",
            "last_name": "Li",
            "email": "alice@example.com",
        }
        response = self.client.post(reverse("accounts:profile"), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Alice")
        self.assertEqual(self.user.last_name, "Li")
        self.assertEqual(self.user.email, "alice@example.com")
        messages = list(response.context["messages"])
        self.assertTrue(any("已更新" in str(msg) for msg in messages))

    def test_email_must_be_unique(self):
        other = self.user_model.objects.create_user(
            username="bob",
            password="AnotherPass123!",
            email="taken@example.com",
        )
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("accounts:profile"),
            {"email": other.email},
        )
        self.assertEqual(response.status_code, 200)
        form = response.context["form"]
        self.assertTrue(form.errors)
        self.assertIn("该邮箱已被其他账号使用", form.errors.get("email", []))
