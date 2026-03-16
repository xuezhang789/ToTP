from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from totp.models import Team, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class QueryCountGuardrailTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="queryguard",
            password="StrongPassword123!",
        )

    def test_list_view_query_count_is_bounded(self):
        self.client.force_login(self.user)
        for i in range(25):
            TOTPEntry.objects.create(
                user=self.user,
                name=f"Entry {i}",
                secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
            )
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:list"))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 25)

    def test_teams_overview_query_count_is_bounded(self):
        self.client.force_login(self.user)
        for i in range(8):
            team = Team.objects.create(owner=self.user, name=f"Team {i}")
            TeamMembership.objects.create(team=team, user=self.user, role=TeamMembership.Role.OWNER)
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(reverse("totp:teams"))
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(ctx), 25)

