from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class ExportEntriesTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="bob",
            password="StrongPwd123!",
            email="bob@example.com",
        )
        self.url = reverse("totp:export")

    def test_export_requires_reauth(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/reauth", response.url)

    def test_export_creates_audit_rows(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="GitLab",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response["Content-Type"])
        if getattr(response, "streaming", False):
            b"".join(response.streaming_content)
        self.assertTrue(entry.audits.filter(action="exported").exists())
