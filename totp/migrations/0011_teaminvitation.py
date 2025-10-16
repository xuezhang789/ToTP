import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("totp", "0010_team_shared_entries"),
    ]

    operations = [
        migrations.CreateModel(
            name="TeamInvitation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role", models.CharField(choices=[("owner", "拥有者"), ("admin", "管理员"), ("member", "成员")], default="member", max_length=16)),
                ("status", models.CharField(choices=[("pending", "待确认"), ("accepted", "已接受"), ("declined", "已拒绝"), ("cancelled", "已取消")], db_index=True, default="pending", max_length=16)),
                ("message", models.CharField(blank=True, max_length=200)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("responded_at", models.DateTimeField(blank=True, null=True)),
                ("invitee", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="team_invitations", to=settings.AUTH_USER_MODEL)),
                ("inviter", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="sent_team_invitations", to=settings.AUTH_USER_MODEL)),
                ("team", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="invitations", to="totp.team")),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="teaminvitation",
            constraint=models.UniqueConstraint(condition=models.Q(status="pending"), fields=("team", "invitee"), name="uniq_pending_team_invitation"),
        ),
    ]
