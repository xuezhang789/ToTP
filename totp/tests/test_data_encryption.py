from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings

from totp.models import TOTPEntry
from totp.utils import decrypt_str, encrypt_str, reset_encryption_cache


class DataEncryptionTests(TestCase):
    def tearDown(self):
        reset_encryption_cache()

    @override_settings(
        SECRET_KEY="django-secret-one",
        TOTP_DATA_KEYS=["data-key-one"],
        TOTP_ENC_KEYS=[],
        TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK=False,
        TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK=False,
    )
    def test_data_key_is_independent_from_django_secret_key(self):
        reset_encryption_cache()
        token = encrypt_str("JBSWY3DPEHPK3PXP")

        with override_settings(
            SECRET_KEY="django-secret-two",
            TOTP_DATA_KEYS=["data-key-one"],
            TOTP_ENC_KEYS=[],
            TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK=False,
            TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK=False,
        ):
            reset_encryption_cache()
            self.assertEqual(decrypt_str(token), "JBSWY3DPEHPK3PXP")

    def test_rotate_totp_data_keys_reencrypts_entries_with_new_primary(self):
        user = get_user_model().objects.create_user(
            username="rotate_owner",
            password="StrongPassword123!",
        )
        with override_settings(
            TOTP_DATA_KEYS=["old-data-key"],
            TOTP_ENC_KEYS=[],
            TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK=False,
            TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK=False,
        ):
            reset_encryption_cache()
            old_token = encrypt_str("JBSWY3DPEHPK3PXP")

        entry = TOTPEntry.objects.create(
            user=user,
            name="Rotate Entry",
            secret_encrypted=old_token,
        )

        out = StringIO()
        with override_settings(
            TOTP_DATA_KEYS=["new-data-key", "old-data-key"],
            TOTP_ENC_KEYS=[],
            TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK=False,
            TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK=False,
        ):
            reset_encryption_cache()
            call_command("rotate_totp_data_keys", "--apply", stdout=out)
            entry.refresh_from_db()
            rotated_token = entry.secret_encrypted
            self.assertNotEqual(rotated_token, old_token)
            self.assertEqual(decrypt_str(rotated_token), "JBSWY3DPEHPK3PXP")

        with override_settings(
            TOTP_DATA_KEYS=["new-data-key"],
            TOTP_ENC_KEYS=[],
            TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK=False,
            TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK=False,
        ):
            reset_encryption_cache()
            self.assertEqual(decrypt_str(rotated_token), "JBSWY3DPEHPK3PXP")
