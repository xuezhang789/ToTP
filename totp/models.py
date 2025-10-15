"""TOTP 应用的模型定义。"""
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from .utils import decrypt_str, encrypt_str


User = settings.AUTH_USER_MODEL


class Team(models.Model):
    """团队空间，支持多个成员共享密钥。"""

    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="owned_totp_teams"
    )
    name = models.CharField(max_length=80)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("owner", "name"),)
        verbose_name = "团队"
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name

    def get_membership(self, user):
        """返回指定用户在团队中的成员记录。"""

        if not user or not getattr(user, "is_authenticated", False):
            return None
        memberships = getattr(self, "_prefetched_memberships", None)
        if memberships is not None:
            for membership in memberships:
                if membership.user_id == user.id:
                    return membership
            return None
        return self.memberships.filter(user=user).first()

    def has_member(self, user) -> bool:
        return self.get_membership(user) is not None

    def user_can_manage_entries(self, user) -> bool:
        membership = self.get_membership(user)
        return membership.can_manage_entries if membership else False


class TeamMembership(models.Model):
    """团队成员关系。"""

    class Role(models.TextChoices):
        OWNER = "owner", "拥有者"
        ADMIN = "admin", "管理员"
        MEMBER = "member", "成员"

        @classmethod
        def manager_roles(cls):
            return {cls.OWNER, cls.ADMIN}

    team = models.ForeignKey(
        Team, on_delete=models.CASCADE, related_name="memberships"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="totp_team_memberships"
    )
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.MEMBER)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("team", "user"),)
        verbose_name = "团队成员"
        verbose_name_plural = verbose_name

    def __str__(self):
        return f"{self.user} @ {self.team} ({self.get_role_display()})"

    @property
    def can_manage_entries(self) -> bool:
        return self.role in self.Role.manager_roles()

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


class ActiveTOTPEntryManager(models.Manager):
    """仅返回未被删除（不在回收站）的密钥对象。"""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)

    def for_user(self, user):
        """返回用户可访问的个人与团队条目。"""

        return (
            self.get_queryset()
            .filter(Q(user=user) | Q(team__memberships__user=user))
            .distinct()
        )


class AllTOTPEntryManager(models.Manager):
    """返回包含已删除在内的所有密钥对象。"""

    def get_queryset(self):
        return super().get_queryset()

    def for_user(self, user):
        return (
            self.get_queryset()
            .filter(Q(user=user) | Q(team__memberships__user=user))
            .distinct()
        )


class TOTPEntry(models.Model):
    """存储用户的 TOTP 密钥信息，同时支持回收站机制。"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="totp_entries")
    team = models.ForeignKey(
        Team,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="entries",
    )
    group = models.ForeignKey(
        Group, on_delete=models.SET_NULL, null=True, blank=True, related_name="entries"
    )
    name = models.CharField(max_length=64)
    secret_encrypted = models.TextField()
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    # 回收站相关字段：软删除标记与删除时间
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)

    # 自定义管理器：objects 只返回正常数据，all_objects 返回全部数据
    objects = ActiveTOTPEntryManager()
    all_objects = AllTOTPEntryManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "name"],
                condition=Q(is_deleted=False, team__isnull=True),
                name="uniq_active_personal_totp_entry",
            ),
            models.UniqueConstraint(
                fields=["team", "name"],
                condition=Q(is_deleted=False, team__isnull=False),
                name="uniq_active_team_totp_entry",
            ),
        ]
        indexes = [
            models.Index(fields=["user", "name", "is_deleted"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["user", "group"]),
            models.Index(fields=["user", "is_deleted", "deleted_at"]),
            models.Index(fields=["team", "name", "is_deleted"]),
            models.Index(fields=["team", "created_at"]),
        ]
        verbose_name = "密钥"
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name

    @property
    def is_team_entry(self) -> bool:
        return self.team_id is not None

    def membership_for(self, user):
        if not self.team_id:
            return None
        return self.team.get_membership(user)

    def user_can_view(self, user) -> bool:
        if user is None or not getattr(user, "is_authenticated", False):
            return False
        if self.user_id == user.id:
            return True
        if self.team_id:
            return self.team.has_member(user)
        return False

    def user_can_manage(self, user) -> bool:
        if user is None or not getattr(user, "is_authenticated", False):
            return False
        if self.user_id == user.id:
            return True
        if self.team_id:
            return self.team.user_can_manage_entries(user)
        return False

    @classmethod
    def purge_expired_trash(cls, user=None):
        """清理超过 30 天仍在回收站中的密钥。

        参数:
            user: 可选的用户对象，仅清理该用户可访问的回收站。
        """

        cutoff = timezone.now() - timedelta(days=30)
        qs = cls.all_objects.filter(is_deleted=True, deleted_at__lt=cutoff)
        if user is not None:
            team_ids = TeamMembership.objects.filter(user=user).values_list(
                "team_id", flat=True
            )
            qs = qs.filter(Q(user=user) | Q(team_id__in=team_ids))
        qs.delete()

    @property
    def recycle_remaining_days(self):
        """计算回收站剩余天数，便于在模板中展示友好提示。"""

        if not self.is_deleted or not self.deleted_at:
            return None
        elapsed = timezone.now() - self.deleted_at
        remaining_seconds = 30 * 24 * 60 * 60 - int(elapsed.total_seconds())
        if remaining_seconds <= 0:
            return 0
        # 向上取整，避免出现“还有 0 天”但实际上还有几个小时的情况。
        return (remaining_seconds + 24 * 60 * 60 - 1) // (24 * 60 * 60)


class ActiveOneTimeLinkManager(models.Manager):
    """仅返回仍然有效的一次性访问链接。"""

    def get_queryset(self):
        now = timezone.now()
        return (
            super()
            .get_queryset()
            .filter(
                expires_at__gt=now,
                view_count__lt=models.F("max_views"),
                entry__is_deleted=False,
                revoked_at__isnull=True,
            )
        )


class OneTimeLink(models.Model):
    """供临时共享验证码使用的一次性访问链接。"""

    entry = models.ForeignKey(
        TOTPEntry, on_delete=models.CASCADE, related_name="one_time_links"
    )
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="created_one_time_links"
    )
    token_hash = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField(db_index=True)
    max_views = models.PositiveSmallIntegerField(default=1)
    view_count = models.PositiveSmallIntegerField(default=0)
    first_viewed_at = models.DateTimeField(null=True, blank=True)
    last_viewed_at = models.DateTimeField(null=True, blank=True)
    last_view_ip = models.GenericIPAddressField(null=True, blank=True)
    last_view_user_agent = models.CharField(max_length=256, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager()
    active = ActiveOneTimeLinkManager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["entry", "expires_at"]),
            models.Index(fields=["created_by", "created_at"]),
        ]

    @property
    def is_active(self) -> bool:
        return (
            self.expires_at > timezone.now()
            and self.view_count < self.max_views
            and not self.entry.is_deleted
            and self.revoked_at is None
        )

    def mark_view(self, request=None):
        now = timezone.now()
        if (
            self.view_count >= self.max_views
            or self.expires_at <= now
            or self.revoked_at is not None
        ):
            raise ValueError("link_expired")

        self.view_count += 1
        if self.first_viewed_at is None:
            self.first_viewed_at = now
        self.last_viewed_at = now
        if request is not None:
            self.last_view_ip = _get_client_ip(request)
            ua = request.META.get("HTTP_USER_AGENT", "")
            self.last_view_user_agent = ua[:255]
        self.save(
            update_fields=[
                "view_count",
                "first_viewed_at",
                "last_viewed_at",
                "last_view_ip",
                "last_view_user_agent",
                "updated_at",
            ]
        )

    def invalidate(self):
        """立即设置为失效。"""

        now = timezone.now()
        self.expires_at = now
        self.revoked_at = now
        self.save(update_fields=["expires_at", "revoked_at", "updated_at"])


def _get_client_ip(request):
    forward = request.META.get("HTTP_X_FORWARDED_FOR")
    if forward:
        return forward.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR") or None
