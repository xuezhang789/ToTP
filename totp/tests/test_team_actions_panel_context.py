from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamMembership


class TeamActionsPanelContextTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("ctx_user", password="StrongPassword123!")
        self.team = Team.objects.create(owner=self.user, name="Ctx Team")
        TeamMembership.objects.create(team=self.team, user=self.user, role=TeamMembership.Role.OWNER)

    def test_panel_in_teams_context_renders_links_to_team_home(self):
        self.client.force_login(self.user)
        url = reverse("totp:team_actions_panel", args=[self.team.id]) + "?context=teams"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn(reverse("totp:team_home", args=[self.team.id]) + "?tab=members", html)
        self.assertIn(reverse("totp:team_home", args=[self.team.id]) + "?tab=security", html)
        self.assertIn(reverse("totp:team_home", args=[self.team.id]) + "?tab=audit", html)

