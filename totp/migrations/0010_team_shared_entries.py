from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ("totp", "0009_remove_backup_models"),
    ]

    operations = [
        migrations.CreateModel(
            name="Team",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=80)),
                ("created_at", models.DateTimeField(db_index=True, auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="owned_totp_teams",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "团队",
                "verbose_name_plural": "团队",
                "unique_together": {("owner", "name")},
            },
        ),
        migrations.CreateModel(
            name="TeamMembership",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "role",
                    models.CharField(
                        choices=[
                            ("owner", "拥有者"),
                            ("admin", "管理员"),
                            ("member", "成员"),
                        ],
                        default="member",
                        max_length=16,
                    ),
                ),
                ("joined_at", models.DateTimeField(auto_now_add=True)),
                (
                    "team",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="memberships",
                        to="totp.team",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="totp_team_memberships",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "团队成员",
                "verbose_name_plural": "团队成员",
                "unique_together": {("team", "user")},
            },
        ),
        migrations.AddField(
            model_name="totpentry",
            name="team",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="entries",
                to="totp.team",
            ),
        ),
        migrations.RemoveConstraint(
            model_name="totpentry",
            name="uniq_active_totp_entry",
        ),
        migrations.AddConstraint(
            model_name="totpentry",
            constraint=models.UniqueConstraint(
                condition=Q(("is_deleted", False), ("team__isnull", True)),
                fields=("user", "name"),
                name="uniq_active_personal_totp_entry",
            ),
        ),
        migrations.AddConstraint(
            model_name="totpentry",
            constraint=models.UniqueConstraint(
                condition=Q(("is_deleted", False), ("team__isnull", False)),
                fields=("team", "name"),
                name="uniq_active_team_totp_entry",
            ),
        ),
        migrations.AddIndex(
            model_name="totpentry",
            index=models.Index(
                fields=["team", "name", "is_deleted"],
                name="totpentry_team_name_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="totpentry",
            index=models.Index(
                fields=["team", "created_at"],
                name="totpentry_team_created_idx",
            ),
        ),
    ]
