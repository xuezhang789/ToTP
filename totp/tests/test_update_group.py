from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Group, TOTPEntry
from totp.utils import encrypt_str


class UpdateGroupTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="bob", password="password"
        )
        self.client.force_login(self.user)
        self.entry = TOTPEntry.objects.create(
            user=self.user,
            name="Example",
            group=None,
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

    def test_assign_group(self):
        group = Group.objects.create(user=self.user, name="Team")

        response = self.client.post(
            reverse("totp:update_group", args=[self.entry.id]),
            {"group_id": str(group.id)},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("group_name"), "Team")

        self.entry.refresh_from_db()
        self.assertEqual(self.entry.group, group)

    def test_clear_group(self):
        group = Group.objects.create(user=self.user, name="Temp")
        self.entry.group = group
        self.entry.save(update_fields=["group", "updated_at"])

        response = self.client.post(
            reverse("totp:update_group", args=[self.entry.id]),
            {"group_id": ""},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("group_name"), "未分组")

        self.entry.refresh_from_db()
        self.assertIsNone(self.entry.group)

    def test_invalid_group(self):
        other_user = get_user_model().objects.create_user(
            username="mallory", password="password"
        )
        other_group = Group.objects.create(user=other_user, name="Other")

        response = self.client.post(
            reverse("totp:update_group", args=[self.entry.id]),
            {"group_id": str(other_group.id)},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)

        self.entry.refresh_from_db()
        self.assertIsNone(self.entry.group)