import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class ExportViewsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="exporter", password="StrongPassword123!")
        self.client.force_login(self.user)
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()

    def test_export_entries_returns_no_store(self):
        TOTPEntry.objects.create(
            user=self.user,
            name="Entry A",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        res = self.client.get(reverse("totp:export"))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.streaming)
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))
        self.assertIn("attachment;", res.headers.get("Content-Disposition", ""))
        body = b"".join(res.streaming_content).decode("utf-8")
        self.assertIn("Entry A", body)

    def test_export_encrypted_returns_no_store(self):
        TOTPEntry.objects.create(
            user=self.user,
            name="Entry B",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        res = self.client.post(
            reverse("totp:export_encrypted"),
            {"passphrase": "StrongPassphrase123!", "passphrase2": "StrongPassphrase123!"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))
        payload = json.loads(res.content.decode("utf-8"))
        self.assertEqual(payload.get("version"), 1)
        self.assertEqual(payload.get("meta", {}).get("count"), 1)
        self.assertIn("kdf", payload)
        self.assertIn("cipher", payload)
