from django.conf import settings
from django.db import models


class AuthAudit(models.Model):
    """记录认证相关关键操作，便于统一审计与排障。"""

    class Action(models.TextChoices):
        LOGIN = "login", "登录"
        REAUTH = "reauth", "二次确认"
        LOGOUT = "logout", "退出登录"

    class Method(models.TextChoices):
        PASSWORD = "password", "密码"
        GOOGLE = "google", "Google"
        SESSION = "session", "会话"

    class Status(models.TextChoices):
        SUCCESS = "success", "成功"
        FAILED = "failed", "失败"
        BLOCKED = "blocked", "已拦截"
        RATE_LIMITED = "rate_limited", "已限流"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="auth_audits",
    )
    action = models.CharField(max_length=24, choices=Action.choices, db_index=True)
    method = models.CharField(max_length=24, choices=Method.choices, db_index=True)
    status = models.CharField(max_length=16, choices=Status.choices, db_index=True)
    identifier = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["action", "created_at"]),
            models.Index(fields=["status", "created_at"]),
        ]

    def __str__(self):
        subject = self.user_id or self.identifier or "anonymous"
        return f"{self.get_action_display()} {self.get_status_display()} ({subject})"
