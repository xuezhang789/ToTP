import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.models import AuthAudit


class AuthAuditTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="audit_user",
            password="StrongPassword123!",
            email="audit@example.com",
        )

    def test_password_login_writes_failed_and_success_audits(self):
        response = self.client.post(
            reverse("accounts:login"),
            {"username": self.user.username, "password": "wrong-password"},
        )
        self.assertEqual(response.status_code, 200)

        failed_audit = AuthAudit.objects.latest("created_at")
        self.assertEqual(failed_audit.action, AuthAudit.Action.LOGIN)
        self.assertEqual(failed_audit.method, AuthAudit.Method.PASSWORD)
        self.assertEqual(failed_audit.status, AuthAudit.Status.FAILED)
        self.assertEqual(failed_audit.identifier, self.user.username)

        success = self.client.post(
            reverse("accounts:login"),
            {"username": self.user.username, "password": "StrongPassword123!"},
        )
        self.assertEqual(success.status_code, 302)

        success_audit = AuthAudit.objects.latest("created_at")
        self.assertEqual(success_audit.action, AuthAudit.Action.LOGIN)
        self.assertEqual(success_audit.method, AuthAudit.Method.PASSWORD)
        self.assertEqual(success_audit.status, AuthAudit.Status.SUCCESS)
        self.assertEqual(success_audit.user_id, self.user.id)

    @patch("accounts.views.id_token.verify_oauth2_token")
    def test_google_login_writes_blocked_audit_for_inactive_user(self, verify_mock):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        verify_mock.return_value = {
            "email": self.user.email,
            "email_verified": True,
            "sub": "google-audit-user",
        }

        response = self.client.post(
            reverse("accounts:google_onetap"),
            data=json.dumps({"credential": "fake"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
        audit = AuthAudit.objects.latest("created_at")
        self.assertEqual(audit.action, AuthAudit.Action.LOGIN)
        self.assertEqual(audit.method, AuthAudit.Method.GOOGLE)
        self.assertEqual(audit.status, AuthAudit.Status.BLOCKED)
        self.assertEqual(audit.user_id, self.user.id)
        self.assertEqual(audit.identifier, self.user.email)

    def test_reauth_api_writes_success_audit(self):
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("accounts:reauth_api"),
            data=json.dumps({"password": "StrongPassword123!"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        audit = AuthAudit.objects.latest("created_at")
        self.assertEqual(audit.action, AuthAudit.Action.REAUTH)
        self.assertEqual(audit.method, AuthAudit.Method.PASSWORD)
        self.assertEqual(audit.status, AuthAudit.Status.SUCCESS)
        self.assertEqual(audit.user_id, self.user.id)
