from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase, TransactionTestCase
from django.urls import reverse


class UserEmailUniquenessConstraintTests(TransactionTestCase):
    reset_sequences = True

    def test_db_rejects_case_insensitive_duplicate_email(self):
        user_model = get_user_model()
        user_model.objects.create_user(
            username="alpha",
            password="StrongPass123!",
            email="Dup@example.com",
        )

        with self.assertRaises(IntegrityError):
            user_model.objects.create_user(
                username="beta",
                password="StrongPass123!",
                email="dup@example.com",
            )


class SignupEmailUniquenessTests(TestCase):
    def test_signup_rejects_case_insensitive_duplicate_email(self):
        user_model = get_user_model()
        user_model.objects.create_user(
            username="existing",
            password="StrongPass123!",
            email="taken@example.com",
        )

        response = self.client.post(
            reverse("accounts:signup"),
            {
                "username": "newuser",
                "email": "Taken@Example.com",
                "password": "EvenStronger456!",
            },
        )

        self.assertEqual(response.status_code, 400)
        messages = list(response.context["messages"])
        self.assertTrue(any("邮箱已存在" in str(msg) for msg in messages))
