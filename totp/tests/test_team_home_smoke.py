from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamMembership


class TeamHomeSmokeTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="team_home_user", password="StrongPassword123!")
        self.team = Team.objects.create(owner=self.user, name="Home Team")
        TeamMembership.objects.create(team=self.team, user=self.user, role=TeamMembership.Role.OWNER)

    def test_team_home_renders_core_shell(self):
        self.client.force_login(self.user)
        res = self.client.get(reverse("totp:team_home", args=[self.team.id]))
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn('id="teamSidebarPanel"', html)
        self.assertIn('id="teamActionsOffcanvas"', html)
        self.assertIn('id="renameTeamModal"', html)
        self.assertIn('data-team-kpi="members"', html)
        self.assertIn('data-team-kpi="links"', html)
        self.assertIn("治理面板", html)
        self.assertIn("资产归档", html)
        self.assertIn("风险摘要", html)
        self.assertIn(f'id="teamTabs-{self.team.id}"', html)
        self.assertIn(f'id="teamPane-{self.team.id}-members"', html)
        self.assertIn(f'id="teamPane-{self.team.id}-security"', html)
        self.assertIn(f'id="teamPane-{self.team.id}-audit"', html)
