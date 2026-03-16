from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("totp", "0016_onetimelink_note"),
    ]

    operations = [
        migrations.CreateModel(
            name="TeamAsset",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=80)),
                ("description", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "team",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="assets", to="totp.team"),
                ),
                (
                    "owners",
                    models.ManyToManyField(blank=True, related_name="totp_team_asset_owners", to=settings.AUTH_USER_MODEL),
                ),
                (
                    "watchers",
                    models.ManyToManyField(blank=True, related_name="totp_team_asset_watchers", to=settings.AUTH_USER_MODEL),
                ),
            ],
            options={
                "ordering": ["name"],
                "indexes": [
                    models.Index(fields=["team", "name"], name="totp_teamas_team_id_4cdb14_idx"),
                    models.Index(fields=["team", "created_at"], name="totp_teamas_team_id_182e8f_idx"),
                ],
                "unique_together": {("team", "name")},
            },
        ),
        migrations.AddField(
            model_name="totpentry",
            name="asset",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="entries",
                to="totp.teamasset",
            ),
        ),
    ]

