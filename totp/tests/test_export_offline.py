from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class OfflineExportTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="bob",
            password="StrongPwd123!",
            email="bob@example.com",
        )
        self.url = reverse("totp:export_offline")

    def test_login_required(self):
        res = self.client.get(self.url)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/login/", res.url)

    def test_export_html_contains_entries(self):
        self.client.force_login(self.user)
        TOTPEntry.objects.create(
            user=self.user,
            name="GitLab",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/html; charset=utf-8")
        disposition = response["Content-Disposition"]
        self.assertIn("totp-offline", disposition)
        content = response.content.decode("utf-8")
        self.assertIn("GitLab", content)
        self.assertIn("离线验证码包", content)

    def test_export_with_no_entries_redirects(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.resolver_match.view_name, "totp:list")
        messages = list(response.context["messages"])
        self.assertTrue(any("无法生成离线包" in str(m) for m in messages))
