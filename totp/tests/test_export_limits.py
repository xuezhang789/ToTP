from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from totp.models import TOTPEntry, TOTPEntryAudit
from totp.utils import encrypt_str


class ExportLimitTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="limituser",
            password="StrongPassword123!",
        )
        self.client.force_login(self.user)
        session = self.client.session
        session["reauth_at"] = int(timezone.now().timestamp())
        session.save()

    @override_settings(EXPORT_ENCRYPTED_MAX_ENTRIES=1)
    def test_encrypted_export_over_limit_redirects_with_message(self):
        TOTPEntry.objects.create(
            user=self.user,
            name="Entry 1",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=self.user,
            name="Entry 2",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        res = self.client.post(
            reverse("totp:export_encrypted"),
            {"passphrase": "StrongPassphrase123!", "passphrase2": "StrongPassphrase123!"},
            follow=True,
        )
        self.assertEqual(res.status_code, 200)
        msgs = [m.message for m in get_messages(res.wsgi_request)]
        self.assertTrue(any("最多导出" in m for m in msgs))
        self.assertEqual(
            TOTPEntryAudit.objects.filter(action=TOTPEntryAudit.Action.ENCRYPTED_EXPORTED).count(),
            0,
        )

    @override_settings(EXPORT_OFFLINE_MAX_ENTRIES=1)
    def test_offline_export_over_limit_redirects_with_message(self):
        TOTPEntry.objects.create(
            user=self.user,
            name="Entry 1",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        TOTPEntry.objects.create(
            user=self.user,
            name="Entry 2",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        res = self.client.get(reverse("totp:export_offline"), follow=True)
        self.assertEqual(res.status_code, 200)
        msgs = [m.message for m in get_messages(res.wsgi_request)]
        self.assertTrue(any("最多导出" in m for m in msgs))
        self.assertEqual(
            TOTPEntryAudit.objects.filter(action=TOTPEntryAudit.Action.OFFLINE_EXPORTED).count(),
            0,
        )

