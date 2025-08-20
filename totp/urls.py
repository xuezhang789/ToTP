from django.urls import path
from . import views, api
app_name = "totp"
# TOTP 功能相关路由
urlpatterns = [
    path("list/", views.list_view, name="list"),
    path("add/", views.add_entry, name="add"),
    path("group/add/", views.add_group, name="add_group"),
    path("delete/<int:pk>/", views.delete_entry, name="delete"),
    path("batch-import/", views.batch_import, name="batch_import"),
    path("api/tokens/", api.api_tokens, name="api_tokens"),
]
