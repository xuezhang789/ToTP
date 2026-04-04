from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction


class Command(BaseCommand):
    help = "将 password 为空字符串的账号改为不可用密码（适用于 One Tap 存量数据修复）"

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="实际写入数据库（默认仅 dry-run 输出统计）",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="最多处理多少条（0 表示不限制）",
        )

    def handle(self, *args, **options):
        apply_changes = bool(options.get("apply"))
        limit = int(options.get("limit") or 0)
        blank_password = str()

        User = get_user_model()
        queryset = User.objects.filter(password=blank_password).only(
            "id",
            "username",
            "email",
            "password",
        )
        total = queryset.count()
        if limit > 0:
            queryset = queryset.order_by("id")[:limit]
        target_count = queryset.count()

        self.stdout.write(f"匹配到 password='' 的账号总数：{total}")
        if limit > 0:
            self.stdout.write(f"本次处理上限：{limit}，将处理：{target_count}")
        else:
            self.stdout.write(f"本次将处理：{target_count}")

        if not apply_changes:
            self.stdout.write("dry-run 模式：未写入数据库。使用 --apply 执行实际修复。")
            return

        updated = 0
        with transaction.atomic():
            for user in queryset.iterator(chunk_size=200):
                if user.password:
                    continue
                user.set_unusable_password()
                user.save(update_fields=["password"])
                updated += 1

        self.stdout.write(self.style.SUCCESS(f"已修复账号数：{updated}"))
