from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("totp", "0008_restore_backup_models"),
    ]

    operations = [
        migrations.DeleteModel(name="BackupArchive"),
        migrations.DeleteModel(name="BackupSchedule"),
    ]
