from django.core.cache import cache
from django.test import Client
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
import json


class ExternalTotpRateLimitTests(TestCase):
    def setUp(self):
        cache.clear()
        self.url = reverse("totp:external_totp")
        self.payload = {
            "secret": "JBSWY3DPEHPK3PXP",
        }

    def test_allows_requests_within_limit(self):
        for _ in range(20):
            response = self.client.post(self.url, self.payload)
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertTrue(payload["ok"])

    def test_blocks_requests_over_limit(self):
        for _ in range(20):
            self.client.post(self.url, self.payload)

        response = self.client.post(self.url, self.payload)
        self.assertEqual(response.status_code, 429)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("请求过于频繁", payload["message"])


class ExternalTotpCsrfTests(TestCase):
    def setUp(self):
        cache.clear()
        self.url = reverse("totp:external_totp")

    @override_settings(EXTERNAL_TOOL_ENABLED=True)
    def test_csrf_exempt_allows_post_without_token(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(self.url, {"secret": "JBSWY3DPEHPK3PXP"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])

    @override_settings(EXTERNAL_TOOL_ENABLED=True, EXTERNAL_TOTP_MAX_BODY_BYTES=32)
    def test_rejects_oversized_request_body(self):
        response = self.client.post(
            self.url,
            data=json.dumps({"secret": "JBSWY3DPEHPK3PXP", "note": "x" * 128}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 413)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("请求体过大", payload["message"])
