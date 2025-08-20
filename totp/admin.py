from django.contrib import admin
from .models import Group, TOTPEntry


@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    """分组模型在后台的显示配置。"""

    list_display = ("id", "user", "name", "created_at")
    search_fields = ("name", "user__username")


@admin.register(TOTPEntry)
class TOTPEntryAdmin(admin.ModelAdmin):
    """TOTP 条目模型在后台的显示配置。"""

    list_display = ("id", "user", "name", "group", "created_at")
    search_fields = ("name", "user__username")
    list_filter = ("group", "created_at")
