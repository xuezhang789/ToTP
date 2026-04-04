from datetime import timedelta
from pathlib import Path
import hashlib
import json
from urllib.parse import quote

from django.contrib.auth import get_user_model
from django.core import signing
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from totp.import_preview_service import (
    IMPORT_PREVIEW_SESSION_KEY,
    IMPORT_PREVIEW_SIGNING_SALT,
)
from totp.models import OneTimeLink, TOTPEntry
from totp.utils import encrypt_str


class SecurityHardeningTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="secuser", password="StrongPassword123!")
        self.client.force_login(self.user)

    def _make_import_preview_token(self) -> str:
        preview_id = "security-preview"
        session = self.client.session
        session[IMPORT_PREVIEW_SESSION_KEY] = {
            preview_id: {
                "user_id": self.user.pk,
                "space": "personal",
                "target_label": "个人空间",
                "asset_id": "",
                "entries": [
                    {
                        "name": "Preview Entry",
                        "group": "",
                        "secret": "JBSWY3DPEHPK3PXP",
                        "source": "manual",
                    }
                ],
                "created_at": int(timezone.now().timestamp()),
            }
        }
        session.save()
        return signing.dumps(
            {"preview_id": preview_id, "uid": self.user.pk},
            salt=IMPORT_PREVIEW_SIGNING_SALT,
        )

    def test_one_time_view_is_never_cached(self):
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="OT Entry",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        token = "test-token-123"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        OneTimeLink.objects.create(
            entry=entry,
            created_by=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() + timedelta(minutes=10),
            max_views=3,
        )
        res = self.client.get(reverse("totp:one_time_view", args=[token]))
        self.assertEqual(res.status_code, 200)
        cache_control = res.headers.get("Cache-Control", "")
        self.assertIn("no-store", cache_control)

    def test_external_tool_can_be_disabled(self):
        with override_settings(EXTERNAL_TOOL_ENABLED=False):
            res_page = self.client.get(reverse("totp:external_totp_tool"))
            self.assertEqual(res_page.status_code, 404)
            res_api = self.client.post(reverse("totp:external_totp"), {"secret": "JBSWY3DPEHPK3PXP"})
            self.assertEqual(res_api.status_code, 404)

    def test_external_tool_does_not_prefill_secret_by_default(self):
        with override_settings(EXTERNAL_TOOL_ENABLED=True, EXTERNAL_TOOL_ALLOW_SECRET_PREFILL=False):
            secret = "ZZZZZZZTESTSECRETZZZZZZZ"
            res = self.client.get(f"{reverse('totp:external_totp_tool')}?secret={secret}")
            self.assertEqual(res.status_code, 200)
            self.assertNotContains(res, secret)

    def test_api_tokens_is_never_cached(self):
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="Entry 1",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        res = self.client.get(f"{reverse('totp:api_tokens')}?ids={entry.id}")
        self.assertEqual(res.status_code, 200)
        cache_control = res.headers.get("Cache-Control", "")
        self.assertIn("no-store", cache_control)

    def test_offline_package_template_avoids_innerhtml(self):
        root = Path(__file__).resolve().parents[2]
        template_path = root / "templates" / "totp" / "offline_package.html"
        content = template_path.read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", content)

    def test_csp_allows_google_login_iframe(self):
        self.client.logout()
        with override_settings(CSP_ENABLED=True, CSP_REPORT_ONLY=False):
            res = self.client.get(reverse("accounts:login"))
        csp = res.headers.get("Content-Security-Policy", "")
        self.assertIn("frame-src", csp)
        self.assertIn("https://accounts.google.com", csp)
        self.assertNotIn("oauth2.googleapis.com", csp)
        self.assertNotIn("www.googleapis.com", csp)

    def test_reauth_json_redirects_to_referer(self):
        """测试 _reauth_json 返回的重定向链接是否包含 Referer"""
        # 使用 batch_import_apply 作为触发点，因为它调用 _reauth_json
        url = reverse("totp:batch_import_apply")
        referer = "/totp/some/random/page/"
        
        # 确保 session 中没有 reauth_at，触发 _has_recent_reauth 失败
        if "reauth_at" in self.client.session:
            del self.client.session["reauth_at"]
            self.client.session.save()

        response = self.client.post(
            url,
            data=json.dumps({"preview_token": self._make_import_preview_token()}),
            content_type="application/json",
            HTTP_REFERER=referer
        )

        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data["error"], "reauth_required")
        
        # 验证 redirect URL 中包含 referer
        expected_next = quote(referer)
        self.assertIn(f"next={expected_next}", data["redirect"])

    def test_reauth_json_rejects_external_referer(self):
        url = reverse("totp:batch_import_apply")
        response = self.client.post(
            url,
            data=json.dumps({"preview_token": self._make_import_preview_token()}),
            content_type="application/json",
            HTTP_REFERER="https://evil.example/phish",
        )

        self.assertEqual(response.status_code, 403)
        data = response.json()
        expected_next = quote(reverse("totp:list"))
        self.assertIn(f"next={expected_next}", data["redirect"])
