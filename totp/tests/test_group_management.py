from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Group, TOTPEntry
from totp.utils import encrypt_str


class GroupManagementTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="groupie",
            password="TestPass123!",
        )
        self.client.force_login(self.user)

    def test_rename_group(self):
        group = Group.objects.create(user=self.user, name="Work")
        other = Group.objects.create(user=self.user, name="Personal")

        url = reverse("totp:rename_group", args=[group.pk])
        resp = self.client.post(url, {"name": "Team"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["ok"])
        group.refresh_from_db()
        self.assertEqual(group.name, "Team")

        # 重命名为已有名称应失败
        resp_dup = self.client.post(url, {"name": other.name})
        self.assertEqual(resp_dup.status_code, 400)
        payload_dup = resp_dup.json()
        self.assertFalse(payload_dup["ok"])
        group.refresh_from_db()
        self.assertEqual(group.name, "Team")

    def test_delete_group_resets_entries(self):
        group = Group.objects.create(user=self.user, name="Temp")
        entry = TOTPEntry.objects.create(
            user=self.user,
            group=group,
            name="Example",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

        url = reverse("totp:delete_group", args=[group.pk])
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["released_entries"], 1)
        self.assertFalse(Group.objects.filter(pk=group.pk).exists())

        entry.refresh_from_db()
        self.assertIsNone(entry.group)

        # 重复删除应返回 404
        resp_missing = self.client.post(url)
        self.assertEqual(resp_missing.status_code, 404)
