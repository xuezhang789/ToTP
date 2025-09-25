from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import BackupArchive, TOTPEntry
from totp.utils import encrypt_str


class BackupTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="alice",
            password="StrongPwd123!",
            email="alice@example.com",
        )
        self.client.force_login(self.user)
        TOTPEntry.objects.create(
            user=self.user,
            name="GitHub",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

    def test_create_and_download_backup(self):
        create_url = reverse("totp:backup_create")
        resp = self.client.post(create_url, {"password": "secret123"})
        self.assertEqual(resp.status_code, 302)
        archive = BackupArchive.objects.get(user=self.user)
        download_url = reverse("totp:backup_download", args=[archive.pk])
        resp = self.client.post(download_url, {"password": "secret123"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp["Content-Type"])
        self.assertIn("GitHub", resp.content.decode("utf-8"))

    def test_restore_replaces_entries(self):
        archive = BackupArchive.create_manual(self.user, "测试备份", "secret123")
        # 删除现有条目以验证恢复功能
        TOTPEntry.objects.filter(user=self.user).delete()
        self.assertEqual(TOTPEntry.objects.filter(user=self.user).count(), 0)
        restore_url = reverse("totp:backup_restore", args=[archive.pk])
        resp = self.client.post(restore_url, {"password": "secret123", "mode": "replace"})
        self.assertEqual(resp.status_code, 302)
        self.assertGreater(TOTPEntry.objects.filter(user=self.user).count(), 0)

    def test_invalid_password_on_download(self):
        archive = BackupArchive.create_manual(self.user, "测试备份", "secret123")
        download_url = reverse("totp:backup_download", args=[archive.pk])
        resp = self.client.post(download_url, {"password": "wrong"}, follow=True)
        self.assertEqual(resp.resolver_match.url_name, "totp:backup_dashboard")
        messages = list(resp.context["messages"])
        self.assertTrue(any("解密失败" in str(m) for m in messages))
