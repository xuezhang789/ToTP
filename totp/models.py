"""TOTP 应用的模型定义。"""
import base64
import json
import hashlib
from datetime import timedelta
from secrets import token_bytes

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone

from .utils import decrypt_str, encrypt_str


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


class ActiveTOTPEntryManager(models.Manager):
    """仅返回未被删除（不在回收站）的密钥对象。"""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class AllTOTPEntryManager(models.Manager):
    """返回包含已删除在内的所有密钥对象。"""

    def get_queryset(self):
        return super().get_queryset()


class TOTPEntry(models.Model):
    """存储用户的 TOTP 密钥信息，同时支持回收站机制。"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="totp_entries")
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
                condition=Q(is_deleted=False),
                name="uniq_active_totp_entry",
            )
        ]
        indexes = [
            models.Index(fields=["user", "name", "is_deleted"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["user", "group"]),
            models.Index(fields=["user", "is_deleted", "deleted_at"]),
        ]
        verbose_name = "密钥"
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.name

    @classmethod
    def purge_expired_trash(cls, user=None):
        """清理超过 30 天仍在回收站中的密钥。

        参数:
            user: 可选的用户对象，仅清理该用户的回收站。
        """

        # 只要有用户访问相关页面，就顺带清理过期数据，避免长期占用存储。
        cutoff = timezone.now() - timedelta(days=30)
        qs = cls.all_objects.filter(is_deleted=True, deleted_at__lt=cutoff)
        if user is not None:
            qs = qs.filter(user=user)
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


class BackupArchiveError(Exception):
    """备份相关操作失败时抛出的异常。"""


class BackupArchive(models.Model):
    """存储用户的加密备份快照。"""

    STORAGE_DB = "db"
    STORAGE_CHOICES = ((STORAGE_DB, "数据库"),)

    ENCRYPTION_USER = "user"
    ENCRYPTION_SYSTEM = "system"
    ENCRYPTION_CHOICES = (
        (ENCRYPTION_USER, "用户密码"),
        (ENCRYPTION_SYSTEM, "系统密钥"),
    )

    DEFAULT_ITERATIONS = 390000

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="backup_archives"
    )
    schedule = models.ForeignKey(
        "BackupSchedule",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="archives",
    )
    name = models.CharField(max_length=80)
    storage = models.CharField(
        max_length=16, choices=STORAGE_CHOICES, default=STORAGE_DB
    )
    encryption = models.CharField(
        max_length=16, choices=ENCRYPTION_CHOICES, default=ENCRYPTION_USER
    )
    encrypted_payload = models.TextField()
    salt = models.CharField(max_length=64, blank=True)
    iterations = models.PositiveIntegerField(default=DEFAULT_ITERATIONS)
    entry_count = models.PositiveIntegerField(default=0)
    size_bytes = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.entry_count} entries)"

    @staticmethod
    def _serialize_snapshot(user):
        entries = []
        for entry in (
            TOTPEntry.objects.filter(user=user, is_deleted=False)
            .select_related("group")
            .order_by("name")
        ):
            entries.append(
                {
                    "name": entry.name,
                    "secret": decrypt_str(entry.secret_encrypted),
                    "group": entry.group.name if entry.group else "",
                    "period": 30,
                    "digits": 6,
                }
            )
        return {
            "version": 1,
            "generated_at": timezone.now().isoformat(),
            "entry_count": len(entries),
            "entries": entries,
        }

    @staticmethod
    def _derive_key(password: str, salt: bytes, iterations: int):
        if not password:
            raise BackupArchiveError("password_required")
        key_bytes = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=32
        )
        return base64.urlsafe_b64encode(key_bytes)

    @classmethod
    def _encrypt_with_password(
        cls, payload_text: str, password: str, iterations: int | None = None
    ):
        iterations = iterations or cls.DEFAULT_ITERATIONS
        salt = token_bytes(16)
        key = cls._derive_key(password, salt, iterations)
        token = Fernet(key).encrypt(payload_text.encode("utf-8"))
        return (
            token.decode("utf-8"),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            iterations,
        )

    @classmethod
    def _decrypt_with_password(cls, payload: str, password: str, salt_b64: str, iterations: int):
        try:
            salt = base64.urlsafe_b64decode(salt_b64.encode("ascii")) if salt_b64 else b""
        except (TypeError, ValueError) as exc:
            raise BackupArchiveError("invalid_salt") from exc
        if not salt:
            raise BackupArchiveError("invalid_salt")
        key = cls._derive_key(password, salt, iterations)
        try:
            data = Fernet(key).decrypt(payload.encode("utf-8"))
        except InvalidToken as exc:  # pragma: no cover - 异常路径
            raise BackupArchiveError("invalid_password") from exc
        return data.decode("utf-8")

    @staticmethod
    def _encrypt_with_system(payload_text: str) -> str:
        return encrypt_str(payload_text)

    @staticmethod
    def _decrypt_with_system(payload: str) -> str:
        return decrypt_str(payload)

    @classmethod
    def create_manual(cls, user, name: str, password: str):
        snapshot = cls._serialize_snapshot(user)
        if snapshot["entry_count"] == 0:
            raise BackupArchiveError("empty")
        default_name = timezone.now().strftime("手动备份 %Y-%m-%d %H:%M")
        safe_name = (name or default_name)[:80]
        payload_text = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
        token, salt, iterations = cls._encrypt_with_password(payload_text, password)
        archive = cls.objects.create(
            user=user,
            name=safe_name,
            encryption=cls.ENCRYPTION_USER,
            encrypted_payload=token,
            salt=salt,
            iterations=iterations,
            entry_count=snapshot["entry_count"],
            size_bytes=len(token.encode("utf-8")),
        )
        return archive

    @classmethod
    def create_system(cls, schedule, name: str, snapshot: dict):
        payload_text = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
        token = cls._encrypt_with_system(payload_text)
        archive = cls.objects.create(
            user=schedule.user,
            schedule=schedule,
            name=name[:80],
            encryption=cls.ENCRYPTION_SYSTEM,
            encrypted_payload=token,
            entry_count=snapshot["entry_count"],
            size_bytes=len(token.encode("utf-8")),
        )
        return archive

    def decrypt_payload(self, password: str | None = None) -> dict:
        if self.encryption == self.ENCRYPTION_USER:
            if password is None:
                raise BackupArchiveError("password_required")
            text = self._decrypt_with_password(
                self.encrypted_payload, password, self.salt, self.iterations
            )
        else:
            text = self._decrypt_with_system(self.encrypted_payload)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - 数据损坏
            raise BackupArchiveError("corrupted") from exc

    def restore_entries(self, user, mode: str = "replace", password: str | None = None) -> int:
        if mode not in {"replace", "append"}:
            raise ValidationError("invalid_mode")
        payload = self.decrypt_payload(password=password)
        entries = payload.get("entries") or []

        if mode == "replace":
            TOTPEntry.objects.filter(user=user).delete()
            existing = set()
        else:
            existing = set(
                TOTPEntry.objects.filter(user=user).values_list("name", flat=True)
            )

        groups = {g.name: g for g in Group.objects.filter(user=user)}

        created = 0
        for item in entries:
            name = (item.get("name") or "").strip()[:64]
            secret = (item.get("secret") or "").strip()
            group_name = (item.get("group") or "").strip()
            if not name or not secret:
                continue
            if name in existing:
                continue

            group = None
            if group_name:
                group_key = group_name[:40]
                group = groups.get(group_key)
                if group is None:
                    group = Group.objects.create(user=user, name=group_key)
                    groups[group_key] = group

            TOTPEntry.objects.create(
                user=user,
                name=name,
                group=group,
                secret_encrypted=encrypt_str(secret),
            )
            created += 1
            existing.add(name)
        return created


class BackupSchedule(models.Model):
    """用于自动生成备份的计划配置。"""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="backup_schedules"
    )
    name = models.CharField(max_length=80)
    frequency_hours = models.PositiveIntegerField(default=24)
    keep_last = models.PositiveSmallIntegerField(default=5)
    storage = models.CharField(
        max_length=16,
        choices=BackupArchive.STORAGE_CHOICES,
        default=BackupArchive.STORAGE_DB,
    )
    is_active = models.BooleanField(default=True)
    next_run_at = models.DateTimeField()
    last_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["next_run_at"]
        unique_together = (("user", "name"),)

    def __str__(self):
        return f"{self.name}@{self.user}"

    def schedule_next(self, now=None):
        now = now or timezone.now()
        self.next_run_at = now + timedelta(hours=self.frequency_hours)
        self.save(update_fields=["next_run_at", "updated_at"])

    def run(self, now=None):
        now = now or timezone.now()
        snapshot = BackupArchive._serialize_snapshot(self.user)
        self.last_run_at = now
        self.next_run_at = now + timedelta(hours=self.frequency_hours)
        self.save(update_fields=["last_run_at", "next_run_at", "updated_at"])

        if snapshot["entry_count"] == 0:
            return None

        archive_name = f"{self.name or '自动备份'} {now.strftime('%Y-%m-%d %H:%M')}"
        archive = BackupArchive.create_system(self, archive_name, snapshot)
        self.prune_history()
        return archive

    def prune_history(self):
        keep = max(1, self.keep_last)
        qs = self.archives.order_by("-created_at")
        stale = list(qs[keep:])
        if stale:
            BackupArchive.objects.filter(pk__in=[a.pk for a in stale]).delete()


def _get_client_ip(request):
    forward = request.META.get("HTTP_X_FORWARDED_FOR")
    if forward:
        return forward.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR") or None
