from django.urls import path
from . import views, api
app_name = "totp"
# TOTP 功能相关路由
urlpatterns = [
    path("list/", views.list_view, name="list"),
    path("add/", views.add_entry, name="add"),
    path("group/add/", views.add_group, name="add_group"),
    path("update-group/<int:pk>/", views.update_entry_group, name="update_group"),
    path("delete/<int:pk>/", views.delete_entry, name="delete"),
    path("trash/", views.trash_view, name="trash"),
    path("restore/<int:pk>/", views.restore_entry, name="restore"),
    path("batch-import/", views.batch_import, name="batch_import"),
    path("export/", views.export_entries, name="export"),
    path("export/offline/", views.export_offline_package, name="export_offline"),
    path("backup/", views.backup_dashboard, name="backup_dashboard"),
    path("backup/create/", views.backup_create, name="backup_create"),
    path("backup/<int:pk>/download/", views.backup_download, name="backup_download"),
    path("backup/<int:pk>/restore/", views.backup_restore, name="backup_restore"),
    path(
        "backup/schedule/update/",
        views.backup_schedule_update,
        name="backup_schedule_update",
    ),
    path(
        "backup/schedule/disable/",
        views.backup_schedule_disable,
        name="backup_schedule_disable",
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
    path("api/tokens/", api.api_tokens, name="api_tokens"),
]
