from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("totp", "0011_teaminvitation"),
    ]

    operations = [
        migrations.CreateModel(
            name="TOTPEntryAudit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("action", models.CharField(choices=[("created", "创建"), ("renamed", "重命名"), ("group_changed", "分组调整"), ("trashed", "移入回收站"), ("restored", "恢复"), ("deleted", "永久删除")], max_length=32)),
                ("old_value", models.CharField(blank=True, max_length=128)),
                ("new_value", models.CharField(blank=True, max_length=128)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=models.SET_NULL, related_name="totp_audits", to=settings.AUTH_USER_MODEL)),
                ("entry", models.ForeignKey(on_delete=models.CASCADE, related_name="audits", to="totp.totpentry")),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
