from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, TOTPEntry
from totp.utils import encrypt_str


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

    def test_change_password_success(self):
        self.client.force_login(self.user)
        payload = {
            "password_submit": "1",
            "old_password": "StrongPass123!",
            "new_password1": "EvenStronger456!",
            "new_password2": "EvenStronger456!",
        }
        response = self.client.post(reverse("accounts:profile"), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("EvenStronger456!"))
        messages = list(response.context["messages"])
        self.assertTrue(any("密码已更新" in str(msg) for msg in messages))

    def test_change_password_requires_correct_old(self):
        self.client.force_login(self.user)
        payload = {
            "password_submit": "1",
            "old_password": "WrongPass123!",
            "new_password1": "NewSecure789!",
            "new_password2": "NewSecure789!",
        }
        response = self.client.post(reverse("accounts:profile"), payload)
        self.assertEqual(response.status_code, 200)
        password_form = response.context["password_form"]
        self.assertTrue(password_form.errors)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("StrongPass123!"))

    def test_security_alerts_include_active_link_and_stale_entries(self):
        self.client.force_login(self.user)
        secret = encrypt_str("JBSWY3DPEHPK3PXP")
        old_entry = TOTPEntry.objects.create(
            user=self.user,
            name="Old",
            secret_encrypted=secret,
        )
        old_entry.created_at = timezone.now() - timedelta(days=120)
        old_entry.save(update_fields=["created_at"])
        active_link = OneTimeLink.objects.create(
            entry=old_entry,
            created_by=self.user,
            token_hash="hash1",
            expires_at=timezone.now() + timedelta(minutes=10),
            max_views=3,
        )
        response = self.client.get(reverse("accounts:profile"))
        self.assertEqual(response.status_code, 200)
        alerts = response.context["security_alerts"]
        self.assertTrue(any("一次性访问链接" in alert for alert in alerts))
        self.assertTrue(any("90 天" in alert for alert in alerts))
        summary = response.context["security_summary"]
        self.assertEqual(summary["total_entries"], 1)
        self.assertEqual(summary["active_links"], 1)

    def test_change_password_strength_validation(self):
        self.client.force_login(self.user)
        payload = {
            "password_submit": "1",
            "old_password": "StrongPass123!",
            "new_password1": "abc12345",
            "new_password2": "abc12345",
        }
        response = self.client.post(reverse("accounts:profile"), payload)
        self.assertEqual(response.status_code, 200)
        password_form = response.context["password_form"]
        self.assertTrue(password_form.errors)
        self.assertIn("密码需至少包含", password_form.errors.get("new_password2", [""])[0])
