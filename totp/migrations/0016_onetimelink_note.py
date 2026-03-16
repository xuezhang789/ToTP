from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("totp", "0015_teamaudit"),
    ]

    operations = [
        migrations.AddField(
            model_name="onetimelink",
            name="note",
            field=models.CharField(blank=True, max_length=120),
        ),
    ]

