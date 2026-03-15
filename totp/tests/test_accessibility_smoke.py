from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import TOTPEntry
from totp.utils import encrypt_str


class AccessibilitySmokeTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="access",
            password="StrongPassword123!",
        )

    def test_anonymous_dashboard_has_primary_cta(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn('href="/auth/login/"', html)
        self.assertIn('href="/auth/signup/"', html)

    def test_list_page_modals_have_aria_labels(self):
        self.client.force_login(self.user)
        TOTPEntry.objects.create(
            user=self.user,
            name="GitHub",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )
        response = self.client.get(reverse("totp:list"))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")

        self.assertIn('id="shareLinkModal"', html)
        self.assertIn('aria-labelledby="shareLinkModalLabel"', html)
        self.assertIn('id="shareLinkModalLabel"', html)

        self.assertIn('id="exportEncryptedModal"', html)
        self.assertIn('aria-labelledby="exportEncryptedModalLabel"', html)
        self.assertIn('id="exportEncryptedModalLabel"', html)

        self.assertIn('id="renameModal"', html)
        self.assertIn('aria-labelledby="renameModalLabel"', html)
        self.assertIn('aria-label="复制验证码"', html)
        self.assertIn('aria-label="生成一次性访问链接"', html)

    def test_add_and_group_modals_have_aria_labels(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn('id="addModal"', html)
        self.assertIn('aria-labelledby="addModalLabel"', html)
        self.assertIn('id="addModalLabel"', html)

        response = self.client.get(reverse("totp:list"))
        html = response.content.decode("utf-8")
        self.assertIn('id="addGroupModal"', html)
        self.assertIn('aria-labelledby="addGroupModalLabel"', html)
        self.assertIn('id="addGroupModalLabel"', html)
