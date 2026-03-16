from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamMembership


class TeamMembersFragmentTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user("owner_frag", password="pass", email="owner_frag@example.com")
        self.team = Team.objects.create(owner=self.owner, name="Frag Team")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        for i in range(35):
            user = User.objects.create_user(f"u{i:02d}", password="pass", email=f"u{i:02d}@example.com")
            TeamMembership.objects.create(team=self.team, user=user, role=TeamMembership.Role.MEMBER)

    def test_members_fragment_paginates(self):
        self.client.force_login(self.owner)
        url = reverse("totp:team_tab_fragment", args=[self.team.id, "members"])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("成员分页", html)
        self.assertIn("下一页", html)

        res2 = self.client.get(url + "?page=2")
        self.assertEqual(res2.status_code, 200)
        html2 = res2.content.decode("utf-8")
        self.assertIn("上一页", html2)

    def test_members_fragment_filters_by_query(self):
        self.client.force_login(self.owner)
        url = reverse("totp:team_tab_fragment", args=[self.team.id, "members"])
        res = self.client.get(url + "?q=u01")
        self.assertEqual(res.status_code, 200)
        html = res.content.decode("utf-8")
        self.assertIn("u01", html)
        self.assertNotIn("u20", html)

