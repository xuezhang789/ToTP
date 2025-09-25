from django.core.management.base import BaseCommand
from django.utils import timezone

from totp.models import BackupSchedule


class Command(BaseCommand):
    help = "执行到期的自动备份计划"

    def handle(self, *args, **options):
        now = timezone.now()
        schedules = (
            BackupSchedule.objects.filter(is_active=True, next_run_at__lte=now)
            .select_related("user")
            .order_by("next_run_at")
        )
        if not schedules.exists():
            self.stdout.write("没有待执行的备份计划。")
            return

        for schedule in schedules:
            try:
                archive = schedule.run(now=now)
            except Exception as exc:  # pragma: no cover - 仅用于日志
                self.stderr.write(self.style.ERROR(f"计划 {schedule.id} 执行失败: {exc}"))
                continue
            if archive:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"[{schedule.user}] 已生成备份 {archive.name} (条目 {archive.entry_count})"
                    )
                )
            else:
                self.stdout.write(
                    f"[{schedule.user}] 没有可备份的密钥，跳过计划 {schedule.id}"
                )
