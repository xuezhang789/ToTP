from django.contrib import admin
from django.urls import path, include
from totp import views as totp_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", totp_views.dashboard, name="dashboard"),
    path("totp/", include(("totp.urls", "totp"), namespace="totp")),
    path("auth/", include("accounts.urls")),
    path("manifest.webmanifest", totp_views.pwa_manifest, name="pwa_manifest"),
    path("service-worker.js", totp_views.service_worker, name="service_worker"),
    path("offline/", totp_views.pwa_offline, name="pwa_offline"),
]
