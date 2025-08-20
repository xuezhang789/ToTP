from django.apps import AppConfig
class TotpConfig(AppConfig):
    """TOTP 应用配置。"""
    default_auto_field = "django.db.models.BigAutoField"
    name = "totp"
