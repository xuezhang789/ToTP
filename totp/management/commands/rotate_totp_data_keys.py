from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from totp.models import TOTPEntry
from totp.utils import (
    get_encryption_materials,
    is_encrypted_with_primary,
    rewrap_encrypted_str,
)


class Command(BaseCommand):
    help = "使用当前主数据密钥重新加密已存储的 TOTP 密钥，便于完成主密钥轮换。"

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="实际写入数据库（默认仅做 dry-run 检查）",
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
        materials = get_encryption_materials()
        if not materials:
            raise CommandError("未配置可用的数据加密主密钥，无法执行轮换。")

        queryset = TOTPEntry.all_objects.only("id", "name", "secret_encrypted").order_by("id")
        total = queryset.count()
        if limit > 0:
            queryset = queryset[:limit]
        target_count = queryset.count()

        primary_ready = 0
        needs_rotation = 0
        failures: list[str] = []

        for entry in queryset.iterator(chunk_size=200):
            try:
                if is_encrypted_with_primary(entry.secret_encrypted):
                    primary_ready += 1
                else:
                    rewrap_encrypted_str(entry.secret_encrypted)
                    needs_rotation += 1
            except Exception as exc:
                failures.append(f"id={entry.id} name={entry.name}: {exc}")

        self.stdout.write(f"已检测主密钥候选数：{len(materials)}")
        self.stdout.write(f"密钥总数：{total}")
        self.stdout.write(f"本次检查范围：{target_count}")
        self.stdout.write(f"已使用当前主密钥：{primary_ready}")
        self.stdout.write(f"需要重加密：{needs_rotation}")
        self.stdout.write(f"无法处理：{len(failures)}")

        if failures:
            preview = "\n".join(failures[:10])
            self.stdout.write(self.style.WARNING(f"异常样本：\n{preview}"))
            if apply_changes:
                raise CommandError("存在无法解密的密文，已中止写入。请先修复异常数据后重试。")

        if not apply_changes:
            self.stdout.write("dry-run 模式：未写入数据库。使用 --apply 执行实际轮换。")
            return

        rotated = 0
        with transaction.atomic():
            for entry in queryset.iterator(chunk_size=200):
                new_token, changed = rewrap_encrypted_str(entry.secret_encrypted)
                if not changed:
                    continue
                entry.secret_encrypted = new_token
                entry.save(update_fields=["secret_encrypted"])
                rotated += 1

        self.stdout.write(self.style.SUCCESS(f"已完成重加密：{rotated}"))
