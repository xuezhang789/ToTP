from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class ShareLinkModalGoogleUserTests(TestCase):
    def test_list_page_renders_direct_share_link_controls_for_users_without_password(self):
        User = get_user_model()
        user = User.objects.create_user(username="google_user", password="StrongPassword123!")
        user.set_unusable_password()
        user.save(update_fields=["password"])

        self.client.force_login(user)
        res = self.client.get(reverse("totp:list"))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertNotIn('id="shareLinkGoogleBox"', html)
        self.assertNotIn('handleShareLinkReauthCredential', html)
        self.assertIn('id="shareLinkResult"', html)
        self.assertIn('id="shareLinkUrl"', html)
