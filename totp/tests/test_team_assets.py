from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from totp.models import Team, TeamAsset, TeamMembership, TOTPEntry
from totp.utils import encrypt_str


class TeamAssetTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user("asset_owner", password="testpass", email="owner@example.com")
        self.admin = User.objects.create_user("asset_admin", password="testpass", email="admin@example.com")
        self.member = User.objects.create_user("asset_member", password="testpass", email="member@example.com")
        self.team = Team.objects.create(owner=self.owner, name="Assets Team")
        TeamMembership.objects.create(team=self.team, user=self.owner, role=TeamMembership.Role.OWNER)
        TeamMembership.objects.create(team=self.team, user=self.admin, role=TeamMembership.Role.ADMIN)
        TeamMembership.objects.create(team=self.team, user=self.member, role=TeamMembership.Role.MEMBER)
        self.entry = TOTPEntry.objects.create(
            user=self.owner,
            team=self.team,
            name="AWS Root",
            secret_encrypted=encrypt_str("JBSWY3DPEHPK3PXP"),
        )

    def test_member_can_view_assets(self):
        asset = TeamAsset.objects.create(team=self.team, name="AWS", description="cloud")
        self.client.force_login(self.member)
        res = self.client.get(reverse("totp:team_assets", args=[self.team.id]))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "资产目录")
        self.assertContains(res, asset.name)

        res2 = self.client.get(reverse("totp:team_asset_detail", args=[self.team.id, asset.id]))
        self.assertEqual(res2.status_code, 200)
        self.assertContains(res2, asset.name)

    def test_member_cannot_create_asset(self):
        self.client.force_login(self.member)
        res = self.client.get(reverse("totp:team_asset_create", args=[self.team.id]))
        self.assertEqual(res.status_code, 404)

    def test_admin_can_create_and_assign_entries(self):
        self.client.force_login(self.admin)
        create_url = reverse("totp:team_asset_create", args=[self.team.id])
        res = self.client.post(
            create_url,
            {
                "name": "PagerDuty",
                "description": "oncall",
                "owners": [str(self.admin.id)],
                "watchers": [str(self.owner.id)],
            },
        )
        self.assertEqual(res.status_code, 302)
        asset = TeamAsset.objects.get(team=self.team, name="PagerDuty")
        self.assertTrue(asset.owners.filter(id=self.admin.id).exists())
        self.assertTrue(asset.watchers.filter(id=self.owner.id).exists())

        assign_url = reverse("totp:team_asset_assign_entries", args=[self.team.id, asset.id])
        res2 = self.client.post(assign_url, {"entry_ids": [str(self.entry.id)]})
        self.assertEqual(res2.status_code, 302)
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.asset_id, asset.id)

    def test_admin_cannot_create_duplicate_asset_name(self):
        TeamAsset.objects.create(team=self.team, name="PagerDuty", description="")
        self.client.force_login(self.admin)
        create_url = reverse("totp:team_asset_create", args=[self.team.id])
        res = self.client.post(
            create_url,
            {
                "name": "PagerDuty",
                "description": "duplicate",
            },
        )
        self.assertEqual(res.status_code, 400)
        self.assertContains(res, "已存在同名资产", status_code=400)
        self.assertEqual(
            TeamAsset.objects.filter(team=self.team, name="PagerDuty").count(),
            1,
        )

    def test_team_list_can_filter_by_asset(self):
        asset = TeamAsset.objects.create(team=self.team, name="AWS", description="")
        self.entry.asset = asset
        self.entry.save(update_fields=["asset", "updated_at"])
        self.client.force_login(self.member)
        url = reverse("totp:list") + f"?space=team:{self.team.id}&asset={asset.id}"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "AWS")
        self.assertContains(res, self.entry.name)

        url2 = reverse("totp:list") + f"?space=team:{self.team.id}&asset=0"
        res2 = self.client.get(url2)
        self.assertEqual(res2.status_code, 200)
        self.assertNotContains(res2, self.entry.name)

    def test_update_asset_endpoint(self):
        asset = TeamAsset.objects.create(team=self.team, name="GitHub", description="")
        self.client.force_login(self.admin)
        url = reverse("totp:update_asset", args=[self.entry.id])
        res = self.client.post(url, {"asset_id": str(asset.id)})
        self.assertEqual(res.status_code, 200)
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.asset_id, asset.id)

    def test_add_entry_can_set_asset(self):
        asset = TeamAsset.objects.create(team=self.team, name="Infra", description="")
        self.client.force_login(self.admin)
        url = reverse("totp:add")
        res = self.client.post(
            url,
            {
                "name": "GitLab",
                "team_id": str(self.team.id),
                "asset_id": str(asset.id),
                "group_id": "",
                "secret": "JBSWY3DPEHPK3PXP",
            },
        )
        self.assertEqual(res.status_code, 302)
        entry = TOTPEntry.objects.get(team=self.team, name="GitLab")
        self.assertEqual(entry.asset_id, asset.id)

    def test_removing_member_cleans_asset_roles(self):
        asset = TeamAsset.objects.create(team=self.team, name="PagerDuty", description="")
        asset.owners.add(self.member)
        asset.watchers.add(self.member)
        member_membership = TeamMembership.objects.get(team=self.team, user=self.member)

        self.client.force_login(self.owner)
        url = reverse("totp:team_remove_member", args=[self.team.id, member_membership.id])
        res = self.client.post(url)

        self.assertEqual(res.status_code, 302)
        asset.refresh_from_db()
        self.assertFalse(asset.owners.filter(id=self.member.id).exists())
        self.assertFalse(asset.watchers.filter(id=self.member.id).exists())
