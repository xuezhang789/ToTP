import hashlib
import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import OneTimeLink, TOTPEntry
from totp.utils import encrypt_str


class OneTimeLinkAuditBatchTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="batchuser",
            password="TestPass123!",
            email="batch@example.com",
        )
        self.entry = TOTPEntry.objects.create(
            user=self.user,
            name="Entry A",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

    def _set_reauth(self):
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()

    def test_export_csv(self):
        now = timezone.now()
        OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.user,
            token_hash=hashlib.sha256(b"t1").hexdigest(),
            expires_at=now + timedelta(minutes=10),
            max_views=3,
            note="for oncall",
        )
        self.client.force_login(self.user)
        res = self.client.get(reverse("totp:one_time_audit_export"))
        self.assertEqual(res.status_code, 200)
        body = b"".join(res.streaming_content).decode("utf-8")
        self.assertIn("entry_name", body)
        self.assertIn("Entry A", body)
        self.assertIn("for oncall", body)

    def test_batch_invalidate_requires_reauth(self):
        self.client.force_login(self.user)
        url = reverse("totp:one_time_batch_invalidate")
        res = self.client.post(url, data=json.dumps({"ids": [1]}), content_type="application/json")
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json().get("error"), "reauth_required")

    def test_batch_invalidate_updates_active_links_only(self):
        now = timezone.now()
        active1 = OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.user,
            token_hash=hashlib.sha256(b"a1").hexdigest(),
            expires_at=now + timedelta(minutes=10),
            max_views=3,
            view_count=0,
        )
        active2 = OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.user,
            token_hash=hashlib.sha256(b"a2").hexdigest(),
            expires_at=now + timedelta(minutes=10),
            max_views=3,
            view_count=1,
        )
        used = OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.user,
            token_hash=hashlib.sha256(b"u1").hexdigest(),
            expires_at=now + timedelta(minutes=10),
            max_views=1,
            view_count=1,
        )
        self.client.force_login(self.user)
        self._set_reauth()
        url = reverse("totp:one_time_batch_invalidate")
        res = self.client.post(
            url,
            data=json.dumps({"ids": [active1.id, active2.id, used.id]}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["updated"], 2)

        active1.refresh_from_db()
        active2.refresh_from_db()
        used.refresh_from_db()
        self.assertIsNotNone(active1.revoked_at)
        self.assertIsNotNone(active2.revoked_at)
        self.assertIsNone(used.revoked_at)
