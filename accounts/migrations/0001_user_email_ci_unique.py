from django.db import migrations
from django.db.models import Count
from django.db.models.functions import Lower


INDEX_NAME = "accounts_user_email_ci_uniq"


def validate_user_email_uniqueness(apps, schema_editor):
    """在创建唯一索引前阻止已有重复邮箱数据进入约束。"""

    User = apps.get_model("auth", "User")
    duplicates = list(
        User.objects.exclude(email="")
        .annotate(email_ci=Lower("email"))
        .values("email_ci")
        .annotate(total=Count("id"))
        .filter(total__gt=1)[:5]
    )
    if not duplicates:
        return

    examples = ", ".join(
        f"{row['email_ci']} x{row['total']}"
        for row in duplicates
    )
    raise RuntimeError(
        "Cannot add case-insensitive unique email index because duplicate user emails already exist: "
        f"{examples}. Resolve the duplicates and re-run migrations."
    )


def create_user_email_unique_index(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor not in {"sqlite", "postgresql"}:
        raise RuntimeError(
            "Unsupported database backend for case-insensitive partial email unique index: "
            f"{vendor}"
        )
    schema_editor.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX_NAME} "
        "ON auth_user (LOWER(email)) WHERE email <> ''"
    )


def drop_user_email_unique_index(apps, schema_editor):
    schema_editor.execute(f"DROP INDEX IF EXISTS {INDEX_NAME}")


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunPython(
            validate_user_email_uniqueness,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunPython(
            create_user_email_unique_index,
            reverse_code=drop_user_email_unique_index,
        ),
    ]
