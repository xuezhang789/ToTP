from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import OneTimeLink, TOTPEntry
from totp.utils import encrypt_str


class OneTimeLinkTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="alice",
            password="TestPass123!",
            email="alice@example.com",
        )
        secret = "JBSWY3DPEHPK3PXP"
        self.entry = TOTPEntry.objects.create(
            user=self.user,
            name="GitHub",
            secret_encrypted=encrypt_str(secret),
        )

    def _create_link(self, **payload):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("totp:one_time_create", args=[self.entry.pk]),
            payload or {"duration": 5, "max_views": 2},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.client.logout()
        return data

    def test_create_link_persists_record(self):
        data = self._create_link(duration=10, max_views=3)
        link = OneTimeLink.objects.get(pk=data["id"])
        self.assertEqual(link.entry, self.entry)
        self.assertEqual(link.max_views, 3)
        self.assertTrue(link.expires_at)
        self.assertEqual(link.view_count, 0)

    def test_view_consumes_quota(self):
        data = self._create_link(max_views=1)
        token = data["url"].rstrip("/").split("/")[-1]
        view_url = reverse("totp:one_time_view", args=[token])

        first = self.client.get(view_url)
        self.assertEqual(first.status_code, 200)
        self.assertContains(first, "当前验证码")

        link = OneTimeLink.objects.get(pk=data["id"])
        self.assertEqual(link.view_count, 1)

        second = self.client.get(view_url)
        self.assertEqual(second.status_code, 410)
        self.assertContains(second, "已被使用", status_code=410)

    def test_invalidate_endpoint(self):
        data = self._create_link()
        link_id = data["id"]
        token = data["url"].rstrip("/").split("/")[-1]

        self.client.force_login(self.user)
        resp = self.client.post(
            reverse("totp:one_time_invalidate", args=[link_id])
        )
        self.assertEqual(resp.status_code, 200)
        self.client.logout()

        view_resp = self.client.get(reverse("totp:one_time_view", args=[token]))
        self.assertEqual(view_resp.status_code, 410)
        self.assertContains(view_resp, "撤销", status_code=410)
