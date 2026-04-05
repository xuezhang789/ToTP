import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class ExportEncryptedTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="bob",
            password="StrongPwd123!",
            email="bob@example.com",
        )
        self.url = reverse("totp:export_encrypted")

    def test_requires_reauth(self):
        self.client.force_login(self.user)
        res = self.client.post(self.url, {"passphrase": "password123", "passphrase2": "password123"})
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/reauth", res.url)

    def test_success_returns_json_and_creates_audits(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="GitLab",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        res = self.client.post(self.url, {"passphrase": "password123", "passphrase2": "password123"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res["Content-Type"])
        payload = json.loads(res.content.decode("utf-8"))
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["kdf"]["name"], "pbkdf2-sha256")
        self.assertEqual(payload["cipher"]["name"], "fernet")
        self.assertTrue(payload["cipher"]["token"])
        self.assertTrue(entry.audits.filter(action="encrypted_exported").exists())

    def test_encrypted_export_skips_undecryptable_entries(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()
        valid_entry = TOTPEntry.objects.create(
            user=self.user,
            name="GitLab",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=self.user,
            name="Broken",
            secret_encrypted="not-a-valid-token",
        )

        res = self.client.post(self.url, {"passphrase": "password123", "passphrase2": "password123"})

        self.assertEqual(res.status_code, 200)
        payload = json.loads(res.content.decode("utf-8"))
        self.assertEqual(payload["meta"]["count"], 1)
        self.assertEqual(payload["meta"]["skipped_unavailable"], 1)
        self.assertTrue(payload["meta"]["warnings"])
        self.assertEqual(res["X-Export-Skipped-Unavailable"], "1")
        self.assertTrue(valid_entry.audits.filter(action="encrypted_exported").exists())
