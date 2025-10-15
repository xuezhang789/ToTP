import hashlib
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

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

    def test_audit_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("totp:one_time_audit"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login/", response.url)

    def test_audit_displays_links_with_status(self):
        now = timezone.now()
        link_active = OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.user,
            token_hash=hashlib.sha256(b"token-active").hexdigest(),
            expires_at=now + timedelta(minutes=10),
            max_views=3,
            view_count=1,
            first_viewed_at=now - timedelta(minutes=2),
            last_viewed_at=now - timedelta(minutes=1),
            last_view_ip="1.2.3.4",
            last_view_user_agent="UnitTestAgent/1.0",
        )
        link_used = OneTimeLink.objects.create(
            entry=self.entry,
            created_by=self.user,
            token_hash=hashlib.sha256(b"token-used").hexdigest(),
            expires_at=now + timedelta(minutes=5),
            max_views=2,
            view_count=2,
        )

        self.client.force_login(self.user)
        response = self.client.get(reverse("totp:one_time_audit"))

        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertIn("一次性访问链接审计", content)
        self.assertIn(self.entry.name, content)
        self.assertIn("可用", content)
        self.assertIn("已用尽", content)
        self.assertIn("剩余 2 次", content)
        self.assertIn("1.2.3.4", content)
        self.assertIn("UnitTestAgent/1.0", content)

    def test_audit_paginates_records(self):
        self.client.force_login(self.user)
        now = timezone.now()
        for idx in range(25):
            OneTimeLink.objects.create(
                entry=self.entry,
                created_by=self.user,
                token_hash=hashlib.sha256(f"token-{idx}".encode()).hexdigest(),
                expires_at=now + timedelta(minutes=idx + 1),
                max_views=3,
            )

        response = self.client.get(reverse("totp:one_time_audit"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("page_obj", response.context)
        page_obj = response.context["page_obj"]
        records = response.context["records"]
        self.assertEqual(page_obj.paginator.count, 25)
        self.assertEqual(len(records), 20)
        self.assertTrue(page_obj.has_next())

        response_page2 = self.client.get(reverse("totp:one_time_audit") + "?page=2")
        self.assertEqual(response_page2.status_code, 200)
        page_obj2 = response_page2.context["page_obj"]
        records2 = response_page2.context["records"]
        self.assertEqual(page_obj2.number, 2)
        self.assertEqual(len(records2), 5)
