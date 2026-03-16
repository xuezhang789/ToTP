from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase


class FixEmptyPasswordsCommandTests(TestCase):
    def test_dry_run_does_not_modify(self):
        User = get_user_model()
        u1 = User.objects.create(username="empty1", email="e1@example.com", password="")
        out = StringIO()
        call_command("fix_empty_passwords", stdout=out)
        u1.refresh_from_db()
        self.assertEqual(u1.password, "")

    def test_apply_sets_unusable_password(self):
        User = get_user_model()
        u1 = User.objects.create(username="empty2", email="e2@example.com", password="")
        u2 = User.objects.create_user(username="normal", password="StrongPassword123!", email="n@example.com")

        out = StringIO()
        call_command("fix_empty_passwords", "--apply", stdout=out)
        u1.refresh_from_db()
        u2.refresh_from_db()
        self.assertNotEqual(u1.password, "")
        self.assertFalse(u1.has_usable_password())
        self.assertTrue(u2.has_usable_password())

