from django.conf import settings
from django.db import models
from django.utils import timezone

User = settings.AUTH_USER_MODEL


class Group(models.Model):
    """用户自定义的分组，用于管理多个 TOTP 条目。"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="totp_groups")
    name = models.CharField(max_length=40)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("user", "name"),)
        indexes = [models.Index(fields=["user", "name"])]
        verbose_name = "分组"
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name


class TOTPEntry(models.Model):
    """存储用户的 TOTP 密钥信息。"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="totp_entries")
    group = models.ForeignKey(
        Group, on_delete=models.SET_NULL, null=True, blank=True, related_name="entries"
    )
    name = models.CharField(max_length=64)
    secret_encrypted = models.TextField()
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("user", "name"),)
        indexes = [
            models.Index(fields=["user", "name"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["user", "group"]),
        ]
        verbose_name = "密钥"
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name
