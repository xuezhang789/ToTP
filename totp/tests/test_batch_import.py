import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Group, Team, TeamMembership, TOTPEntry
from totp.utils import decrypt_str, encrypt_str


class BatchImportTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="alice", password="password"
        )
        self.client.force_login(self.user)

    def _preview_manual(self, text: str, space: str | None = None):
        url = reverse("totp:batch_import_preview")
        data = {"mode": "manual", "manual_text": text}
        if space:
            data["space"] = space
        return self.client.post(url, data, follow=False)

    def _apply_entries(self, entries, space: str | None = None):
        url = reverse("totp:batch_import_apply")
        payload = {"entries": entries}
        if space:
            payload["space"] = space
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            follow=False,
        )

    def test_import_otpauth_uri(self):
        secret = "JBSWY3DPEHPK3PXP"
        uri = f"otpauth://totp/Example:alice?secret={secret}"

        preview = self._preview_manual(uri)
        self.assertEqual(preview.status_code, 200)
        payload = preview.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["entries"]), 1)

        entries = [
            {
                "name": item["name"],
                "group": item["group"],
                "secret": item["secret"],
                "source": item["source"],
            }
            for item in payload["entries"]
        ]

        apply_resp = self._apply_entries(entries)
        self.assertEqual(apply_resp.status_code, 200)
        self.assertTrue(apply_resp.json()["ok"])

        entry = TOTPEntry.objects.get(user=self.user)
        self.assertEqual(entry.name, "Example:alice")
        self.assertEqual(decrypt_str(entry.secret_encrypted), secret)

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

        preview = self._preview_manual(payload)
        self.assertEqual(preview.status_code, 200)
        data = preview.json()
        self.assertTrue(data["ok"])
        warnings = data.get("warnings") or []
        # 既提示重复条目，也提示无效密钥
        self.assertTrue(any("重复" in text for text in warnings))
        self.assertTrue(any("无效" in text for text in warnings))

        entries = [
            {
                "name": item["name"],
                "group": item["group"],
                "secret": item["secret"],
                "source": item["source"],
            }
            for item in data["entries"]
        ]

        apply_resp = self._apply_entries(entries)
        self.assertEqual(apply_resp.status_code, 200)
        self.assertTrue(apply_resp.json()["ok"])

        entries_qs = TOTPEntry.objects.filter(user=self.user)
        self.assertEqual(entries_qs.count(), 2)
        self.assertTrue(entries_qs.filter(name="Existing").exists())
        new_entry = entries_qs.get(name="New Entry")
        self.assertIsNotNone(new_entry.group)
        self.assertEqual(new_entry.group.name, "Team")
        self.assertEqual(decrypt_str(new_entry.secret_encrypted), "JBSWY3DPEHPK3PXQ")

        groups = Group.objects.filter(user=self.user, name="Team")
        self.assertEqual(groups.count(), 1)

    def test_import_into_team_space(self):
        team = Team.objects.create(owner=self.user, name="Dev Team")
        TeamMembership.objects.create(
            team=team, user=self.user, role=TeamMembership.Role.OWNER
        )
        existing_secret = "JBSWY3DPEHPK3PXP"
        TOTPEntry.objects.create(
            user=self.user,
            team=team,
            name="Existing",
            secret_encrypted=encrypt_str(existing_secret),
        )

        payload = "\n".join(
            [
                "JBSWY3DPEHPK3PXP|Existing|Team",  # duplicate inside team
                "JBSWY3DPEHPK3PXQ|Team Entry|TeamGroup",  # new entry, group ignored
            ]
        )
        space = f"team:{team.id}"

        preview = self._preview_manual(payload, space=space)
        self.assertEqual(preview.status_code, 200)
        data = preview.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["space"], space)
        warnings = data.get("warnings") or []
        self.assertTrue(any("团队空间不支持分组" in text for text in warnings))
        entries = [
            {
                "name": item["name"],
                "group": item["group"],
                "secret": item["secret"],
                "source": item["source"],
            }
            for item in data["entries"]
        ]

        apply_resp = self._apply_entries(entries, space=space)
        self.assertEqual(apply_resp.status_code, 200)
        apply_data = apply_resp.json()
        self.assertTrue(apply_data["ok"])
        self.assertIn("redirect", apply_data)
        self.assertTrue(apply_data["redirect"].endswith(f"?space=team:{team.id}"))

        team_entries = TOTPEntry.objects.filter(team=team, is_deleted=False)
        self.assertEqual(team_entries.count(), 2)
        created_entry = team_entries.get(name="Team Entry")
        self.assertIsNone(created_entry.group_id)
        self.assertEqual(decrypt_str(created_entry.secret_encrypted), "JBSWY3DPEHPK3PXQ")
