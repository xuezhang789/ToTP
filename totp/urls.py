from django.urls import path
from . import views, api
app_name = "totp"
# TOTP 功能相关路由
urlpatterns = [
    path("list/", views.list_view, name="list"),
    path("teams/", views.teams_overview, name="teams"),
    path("teams/create/", views.team_create, name="team_create"),
    path(
        "teams/<int:team_id>/members/add/",
        views.team_add_member,
        name="team_add_member",
    ),
    path(
        "teams/<int:team_id>/members/<int:member_id>/role/",
        views.team_update_member_role,
        name="team_member_role",
    ),
    path(
        "teams/<int:team_id>/members/<int:member_id>/remove/",
        views.team_remove_member,
        name="team_remove_member",
    ),
    path(
        "teams/invitations/<int:invitation_id>/accept/",
        views.team_invitation_accept,
        name="team_invitation_accept",
    ),
    path(
        "teams/invitations/<int:invitation_id>/decline/",
        views.team_invitation_decline,
        name="team_invitation_decline",
    ),
    path(
        "teams/invitations/<int:invitation_id>/cancel/",
        views.team_invitation_cancel,
        name="team_invitation_cancel",
    ),
    path("add/", views.add_entry, name="add"),
    path("group/add/", views.add_group, name="add_group"),
    path("group/<int:pk>/rename/", views.rename_group, name="rename_group"),
    path("group/<int:pk>/delete/", views.delete_group, name="delete_group"),
    path("rename/<int:pk>/", views.rename_entry, name="rename_entry"),
    path("update-group/<int:pk>/", views.update_entry_group, name="update_group"),
    path("delete/<int:pk>/", views.delete_entry, name="delete"),
    path("trash/", views.trash_view, name="trash"),
    path("trash/bulk/", views.trash_bulk_action, name="trash_bulk"),
    path("restore/<int:pk>/", views.restore_entry, name="restore"),
    path("import/preview/", views.batch_import_preview, name="batch_import_preview"),
    path("import/apply/", views.batch_import_apply, name="batch_import_apply"),
    path("export/", views.export_entries, name="export"),
    path("export/offline/", views.export_offline_package, name="export_offline"),
    path(
        "share/one-time/audit/",
        views.one_time_link_audit,
        name="one_time_audit",
    ),
    path(
        "share/one-time/<int:pk>/create/",
        views.create_one_time_link,
        name="one_time_create",
    ),
    path(
        "share/one-time/<int:pk>/invalidate/",
        views.invalidate_one_time_link,
        name="one_time_invalidate",
    ),
    path("link/<str:token>/", views.one_time_view, name="one_time_view"),
    path("external/tool/", views.external_totp_tool, name="external_totp_tool"),
    path("external/otp/", views.external_totp, name="external_totp"),
    path("api/tokens/", api.api_tokens, name="api_tokens"),
]
