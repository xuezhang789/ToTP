from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse


class ExternalTotpRateLimitTests(TestCase):
    def setUp(self):
        cache.clear()
        self.url = reverse("totp:external_totp")
        self.params = {
            "secret": "JBSWY3DPEHPK3PXP",
            "format": "json",
        }

    def test_allows_requests_within_limit(self):
        for _ in range(20):
            response = self.client.get(self.url, self.params)
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertTrue(payload["ok"])

    def test_blocks_requests_over_limit(self):
        for _ in range(20):
            self.client.get(self.url, self.params)

        response = self.client.get(self.url, self.params)
        self.assertEqual(response.status_code, 429)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("请求过于频繁", payload["message"])
