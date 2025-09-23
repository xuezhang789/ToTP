from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Group, TOTPEntry
from totp.utils import decrypt_str, encrypt_str


class BatchImportTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="alice", password="password"
        )
        self.client.force_login(self.user)

    def test_import_otpauth_uri(self):
        secret = "JBSWY3DPEHPK3PXP"
        uri = f"otpauth://totp/Example:alice?secret={secret}"

        response = self.client.post(
            reverse("totp:batch_import"),
            {"bulk_text": uri},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        entry = TOTPEntry.objects.get(user=self.user)
        self.assertEqual(entry.name, "Example:alice")
        self.assertEqual(decrypt_str(entry.secret_encrypted), secret)

        messages = list(response.context["messages"])
        self.assertTrue(messages)
        self.assertIn("成功导入 1 条", str(messages[0]))

    def test_import_text_with_groups_and_invalid_lines(self):
        existing_secret = "JBSWY3DPEHPK3PXP"
        TOTPEntry.objects.create(
            user=self.user,
            name="Existing",
            group=None,
            secret_encrypted=encrypt_str(existing_secret),
        )

        payload = "\n".join(
            [
                "JBSWY3DPEHPK3PXP|Existing|Team",  # duplicate name, should be skipped
                "JBSWY3DPEHPK3PXQ|New Entry|Team",  # valid new entry
                "INVALIDSECRET123|Bad Entry|Team",  # invalid secret
            ]
        )

        response = self.client.post(
            reverse("totp:batch_import"),
            {"bulk_text": payload},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)

        entries = TOTPEntry.objects.filter(user=self.user)
        self.assertEqual(entries.count(), 2)
        self.assertTrue(entries.filter(name="Existing").exists())
        new_entry = entries.get(name="New Entry")
        self.assertIsNotNone(new_entry.group)
        self.assertEqual(new_entry.group.name, "Team")
        self.assertEqual(decrypt_str(new_entry.secret_encrypted), "JBSWY3DPEHPK3PXQ")

        groups = Group.objects.filter(user=self.user, name="Team")
        self.assertEqual(groups.count(), 1)

        messages = list(response.context["messages"])
        self.assertTrue(messages)
        text = str(messages[0])
        self.assertIn("成功导入 1 条", text)
        self.assertIn("1 条无效密钥", text)
