from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class ApiTokensTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="carol",
            password="StrongPassword123!",
        )
        self.client.force_login(self.user)

    def test_response_includes_remaining_for_each_item(self):
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="GitHub",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

        response = self.client.get(reverse("totp:api_tokens"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("remaining", payload)
        items = payload.get("items") or []
        self.assertEqual(len(items), 1)

        item = items[0]
        self.assertEqual(item["id"], entry.id)
        self.assertEqual(len(item["code"]), 6)
        self.assertEqual(item["period"], 30)
        self.assertIn("remaining", item)
        self.assertIsInstance(item["remaining"], int)
        self.assertIsInstance(payload["remaining"], int)
        self.assertEqual(item["remaining"], payload["remaining"])
        self.assertGreaterEqual(item["remaining"], 0)
        self.assertLessEqual(item["remaining"], item["period"])
