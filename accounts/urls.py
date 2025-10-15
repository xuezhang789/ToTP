from django.urls import path
from . import views

app_name = "accounts"
# 账户相关路由
urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("signup/", views.signup_view, name="signup"),
    path("logout/", views.logout_view, name="logout"),
    path("profile/", views.profile_view, name="profile"),
    path("google/onetap", views.google_onetap, name="google_onetap"),
]
