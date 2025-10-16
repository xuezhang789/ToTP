from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import TOTPEntry, TOTPEntryAudit
from totp.utils import encrypt_str


class AuditLogTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user("auditor", password="StrongPass123!")
        self.client.force_login(self.user)

    def test_add_entry_creates_audit(self):
        response = self.client.post(
            reverse("totp:add"),
            {
                "name": "GitHub",
                "secret": "JBSWY3DPEHPK3PXP",
            },
        )
        self.assertEqual(response.status_code, 302)
        entry = TOTPEntry.objects.get(user=self.user, name="GitHub")
        audit = TOTPEntryAudit.objects.filter(entry=entry, action=TOTPEntryAudit.Action.CREATED).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.new_value, "GitHub")

    def test_rename_entry_logs_audit(self):
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="Old",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        response = self.client.post(
            reverse("totp:rename_entry", args=[entry.id]),
            {"name": "New"},
            HTTP_X_REQUESTED_WITH="fetch",
        )
        self.assertEqual(response.status_code, 200)
        entry.refresh_from_db()
        audit = TOTPEntryAudit.objects.filter(entry=entry, action=TOTPEntryAudit.Action.RENAMED).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.old_value, "Old")
        self.assertEqual(audit.new_value, "New")

    def test_dashboard_includes_recent_audits(self):
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="Item",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        log = TOTPEntryAudit.objects.create(
            entry=entry,
            actor=self.user,
            action=TOTPEntryAudit.Action.CREATED,
            new_value="Item",
        )
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        audits = response.context["recent_audits"]
        self.assertIn(log, audits)
