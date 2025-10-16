from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamInvitation, TeamMembership


class TeamInvitationTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user("owner", password="testpass")
        self.invitee = user_model.objects.create_user("invitee", password="testpass")
        self.another = user_model.objects.create_user("another", password="testpass")
        self.team = Team.objects.create(owner=self.owner, name="Alpha Team")
        TeamMembership.objects.create(
            team=self.team,
            user=self.owner,
            role=TeamMembership.Role.OWNER,
        )

    def test_owner_invite_creates_pending_invitation(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("totp:team_add_member", args=[self.team.id]),
            {"identifier": self.invitee.username, "role": TeamMembership.Role.MEMBER},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(
            TeamMembership.objects.filter(team=self.team, user=self.invitee).exists()
        )
        invitation = TeamInvitation.objects.get(team=self.team, invitee=self.invitee)
        self.assertEqual(invitation.status, TeamInvitation.Status.PENDING)

    def test_invitee_can_accept_invitation(self):
        invitation = TeamInvitation.objects.create(
            team=self.team,
            inviter=self.owner,
            invitee=self.invitee,
            role=TeamMembership.Role.MEMBER,
        )
        self.client.force_login(self.invitee)
        response = self.client.post(
            reverse("totp:team_invitation_accept", args=[invitation.id])
        )
        self.assertEqual(response.status_code, 302)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, TeamInvitation.Status.ACCEPTED)
        self.assertTrue(
            TeamMembership.objects.filter(team=self.team, user=self.invitee).exists()
        )

    def test_invitee_can_decline_invitation(self):
        invitation = TeamInvitation.objects.create(
            team=self.team,
            inviter=self.owner,
            invitee=self.invitee,
            role=TeamMembership.Role.MEMBER,
        )
        self.client.force_login(self.invitee)
        response = self.client.post(
            reverse("totp:team_invitation_decline", args=[invitation.id])
        )
        self.assertEqual(response.status_code, 302)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, TeamInvitation.Status.DECLINED)
        self.assertFalse(
            TeamMembership.objects.filter(team=self.team, user=self.invitee).exists()
        )

    def test_owner_can_cancel_invitation(self):
        invitation = TeamInvitation.objects.create(
            team=self.team,
            inviter=self.owner,
            invitee=self.invitee,
            role=TeamMembership.Role.MEMBER,
        )
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("totp:team_invitation_cancel", args=[invitation.id])
        )
        self.assertEqual(response.status_code, 302)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, TeamInvitation.Status.CANCELLED)
