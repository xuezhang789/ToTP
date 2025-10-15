from django.contrib import admin

from .models import Group, Team, TeamMembership, TOTPEntry


@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    """分组模型在后台的显示配置。"""

    list_display = ("id", "user", "name", "created_at")
    search_fields = ("name", "user__username")


@admin.register(TOTPEntry)
class TOTPEntryAdmin(admin.ModelAdmin):
    """TOTP 条目模型在后台的显示配置。"""

    list_display = ("id", "user", "team", "name", "group", "created_at")
    search_fields = ("name", "user__username", "team__name")
    list_filter = ("team", "group", "created_at")


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    """团队模型后台配置。"""

    list_display = ("id", "name", "owner", "created_at")
    search_fields = ("name", "owner__username")
    autocomplete_fields = ("owner",)


@admin.register(TeamMembership)
class TeamMembershipAdmin(admin.ModelAdmin):
    """团队成员后台配置。"""

    list_display = ("id", "team", "user", "role", "joined_at")
    search_fields = ("team__name", "user__username")
    list_filter = ("role",)
