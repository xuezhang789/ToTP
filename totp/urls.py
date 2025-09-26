from django.urls import path
from . import views, api
app_name = "totp"
# TOTP 功能相关路由
urlpatterns = [
    path("list/", views.list_view, name="list"),
    path("add/", views.add_entry, name="add"),
    path("group/add/", views.add_group, name="add_group"),
    path("group/<int:pk>/rename/", views.rename_group, name="rename_group"),
    path("group/<int:pk>/delete/", views.delete_group, name="delete_group"),
    path("update-group/<int:pk>/", views.update_entry_group, name="update_group"),
    path("delete/<int:pk>/", views.delete_entry, name="delete"),
    path("trash/", views.trash_view, name="trash"),
    path("restore/<int:pk>/", views.restore_entry, name="restore"),
    path("batch-import/", views.batch_import, name="batch_import"),
    path("import/preview/", views.batch_import_preview, name="batch_import_preview"),
    path("import/apply/", views.batch_import_apply, name="batch_import_apply"),
    path("export/", views.export_entries, name="export"),
    path("export/offline/", views.export_offline_package, name="export_offline"),
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
