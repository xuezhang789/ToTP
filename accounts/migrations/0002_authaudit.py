from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_user_email_ci_unique"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AuthAudit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("action", models.CharField(choices=[("login", "登录"), ("reauth", "二次确认"), ("logout", "退出登录")], db_index=True, max_length=24)),
                ("method", models.CharField(choices=[("password", "密码"), ("google", "Google"), ("session", "会话")], db_index=True, max_length=24)),
                ("status", models.CharField(choices=[("success", "成功"), ("failed", "失败"), ("blocked", "已拦截"), ("rate_limited", "已限流")], db_index=True, max_length=16)),
                ("identifier", models.CharField(blank=True, max_length=255)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=255)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name="auth_audits", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["user", "created_at"], name="accounts_au_user_id_899fd2_idx"),
                    models.Index(fields=["action", "created_at"], name="accounts_au_action_52db1e_idx"),
                    models.Index(fields=["status", "created_at"], name="accounts_au_status_5821b4_idx"),
                ],
            },
        ),
    ]
