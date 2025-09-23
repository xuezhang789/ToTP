from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class RecycleBinTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="bob", password="password"
        )
        self.client.force_login(self.user)
        self.secret = encrypt_str("JBSWY3DPEHPK3PXP")

    def test_delete_moves_entry_to_trash_and_restore(self):
        entry = TOTPEntry.objects.create(
            user=self.user,
            name="Sample",
            secret_encrypted=self.secret,
        )

        response = self.client.get(reverse("totp:delete", args=[entry.pk]), follow=True)
        self.assertEqual(response.status_code, 200)

        trash_entry = TOTPEntry.all_objects.get(pk=entry.pk)
        self.assertTrue(trash_entry.is_deleted)
        self.assertIsNotNone(trash_entry.deleted_at)

        trash_page = self.client.get(reverse("totp:trash"))
        self.assertEqual(trash_page.status_code, 200)
        page_entries = list(trash_page.context["entries"].object_list)
        self.assertEqual(len(page_entries), 1)
        self.assertEqual(page_entries[0].name, "Sample")

        restore_response = self.client.post(
            reverse("totp:restore", args=[entry.pk]), follow=True
        )
        self.assertEqual(restore_response.status_code, 200)
        restored = TOTPEntry.objects.get(pk=entry.pk)
        self.assertFalse(restored.is_deleted)
        self.assertIsNone(restored.deleted_at)

    def test_restore_blocked_when_name_conflict(self):
        TOTPEntry.objects.create(
            user=self.user,
            name="Duplicate",
            secret_encrypted=self.secret,
        )
        trashed = TOTPEntry.all_objects.create(
            user=self.user,
            name="Duplicate",
            secret_encrypted=self.secret,
            is_deleted=True,
            deleted_at=timezone.now(),
        )

        response = self.client.post(
            reverse("totp:restore", args=[trashed.pk]), follow=True
        )
        self.assertEqual(response.status_code, 200)
        trashed.refresh_from_db()
        self.assertTrue(trashed.is_deleted)
        messages = list(response.context["messages"])
        self.assertTrue(messages)
        self.assertIn("无法恢复", str(messages[0]))

    def test_delete_allows_multiple_entries_in_trash_with_same_name(self):
        first = TOTPEntry.objects.create(
            user=self.user,
            name="Sample",
            secret_encrypted=self.secret,
        )
        resp1 = self.client.get(reverse("totp:delete", args=[first.pk]), follow=True)
        self.assertEqual(resp1.status_code, 200)

        second = TOTPEntry.objects.create(
            user=self.user,
            name="Sample",
            secret_encrypted=self.secret,
        )

        resp2 = self.client.get(reverse("totp:delete", args=[second.pk]), follow=True)
        self.assertEqual(resp2.status_code, 200)

        trashed = TOTPEntry.all_objects.filter(
            user=self.user, name="Sample", is_deleted=True
        )
        self.assertEqual(trashed.count(), 2)

    def test_purge_expired_trash_on_visit(self):
        expired = TOTPEntry.all_objects.create(
            user=self.user,
            name="Expired",
            secret_encrypted=self.secret,
            is_deleted=True,
            deleted_at=timezone.now() - timedelta(days=31),
        )

        response = self.client.get(reverse("totp:trash"))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(TOTPEntry.all_objects.filter(pk=expired.pk).exists())
        # 页面提示回收站为空
        self.assertIn("回收站为空", response.content.decode())
