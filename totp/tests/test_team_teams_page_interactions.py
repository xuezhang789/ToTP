from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamInvitation, TeamMembership


class TeamTeamsPageInteractionsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user(username="owner1", password="StrongPassword123!")
        self.invitee = user_model.objects.create_user(username="invitee1", password="StrongPassword123!")
        self.member = user_model.objects.create_user(username="member1", password="StrongPassword123!")

        self.team = Team.objects.create(owner=self.owner, name="Tab Team")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        self.member_membership = TeamMembership.objects.create(
            team=self.team,
            user=self.member,
            role=TeamMembership.Role.MEMBER,
        )

        self.invite = TeamInvitation.objects.create(
            team=self.team,
            inviter=self.owner,
            invitee=self.invitee,
            role=TeamMembership.Role.MEMBER,
        )

    def test_teams_page_renders_tab_sections(self):
        self.client.force_login(self.owner)
        response = self.client.get(reverse("totp:teams"))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn(f'id="teamTabs-{self.team.id}"', html)
        self.assertIn(f'id="teamPane-{self.team.id}-members"', html)
        self.assertIn(f'id="teamPane-{self.team.id}-security"', html)
        self.assertIn(f'id="teamPane-{self.team.id}-audit"', html)

    def test_cancel_invitation_endpoint_still_works(self):
        self.client.force_login(self.owner)
        response = self.client.post(reverse("totp:team_invitation_cancel", args=[self.invite.id]))
        self.assertEqual(response.status_code, 302)
        self.invite.refresh_from_db()
        self.assertEqual(self.invite.status, TeamInvitation.Status.CANCELLED)

    def test_update_member_role_endpoint_still_works(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("totp:team_member_role", args=[self.team.id, self.member_membership.id]),
            {"role": "admin"},
        )
        self.assertEqual(response.status_code, 302)
        self.member_membership.refresh_from_db()
        self.assertEqual(self.member_membership.role, TeamMembership.Role.ADMIN)
