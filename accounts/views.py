import json
import re
import secrets
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (
    get_user_model,
    login,
    logout,
    update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods, require_POST
from google.auth.transport import requests as grequests
from google.oauth2 import id_token

from project.utils import client_ip
from totp.models import OneTimeLink, TOTPEntry

from . import auth_service
from .forms import PasswordSetForm, PasswordUpdateForm, ProfileForm, password_strength_errors
from .models import AuthAudit

User = get_user_model()

LOGIN_RATE_LIMIT = auth_service.LOGIN_RATE_LIMIT
LOGIN_RATE_WINDOW_SECONDS = auth_service.LOGIN_RATE_WINDOW_SECONDS
SIGNUP_RATE_LIMIT = 5
SIGNUP_RATE_WINDOW_SECONDS = 600
REAUTH_RATE_LIMIT = auth_service.REAUTH_RATE_LIMIT
REAUTH_RATE_WINDOW_SECONDS = auth_service.REAUTH_RATE_WINDOW_SECONDS
LOGIN_IP_RATE_LIMIT = auth_service.LOGIN_IP_RATE_LIMIT
LOGIN_IP_RATE_WINDOW_SECONDS = auth_service.LOGIN_IP_RATE_WINDOW_SECONDS
LOGIN_CHALLENGE_THRESHOLD = auth_service.LOGIN_CHALLENGE_THRESHOLD
LOGIN_CHALLENGE_WINDOW_SECONDS = auth_service.LOGIN_CHALLENGE_WINDOW_SECONDS
LOGIN_CHALLENGE_TTL_SECONDS = auth_service.LOGIN_CHALLENGE_TTL_SECONDS
LOGIN_CHALLENGE_SESSION_KEY = auth_service.LOGIN_CHALLENGE_SESSION_KEY

_rate_limit_increment = auth_service.rate_limit_increment
_rate_limit_allow = auth_service.rate_limit_allow
_reauth_rate_limit_key = auth_service.reauth_rate_limit_key
_auth_int_setting = auth_service.auth_int_setting
_login_total_rate_limit_key = auth_service.login_total_rate_limit_key
_login_failure_rate_limit_key = auth_service.login_failure_rate_limit_key
_clear_login_challenge = auth_service.clear_login_challenge
_ensure_login_challenge = auth_service.ensure_login_challenge
_login_challenge_context = auth_service.login_challenge_context
_record_login_failure = auth_service.record_login_failure
_validate_login_challenge = auth_service.validate_login_challenge


def _next_url(request, fallback="/"):
    """获取登录后应跳转的安全 URL。"""
    nxt = request.GET.get("next") or request.POST.get("next") or fallback
    if url_has_allowed_host_and_scheme(
        nxt,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return nxt
    return fallback


def _append_query_params(url: str, **params) -> str:
    """为 URL 追加或覆盖查询参数。"""

    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key, value in params.items():
        if value is None:
            query.pop(key, None)
        else:
            query[key] = str(value)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(query),
            parts.fragment,
        )
    )


@require_http_methods(["GET", "POST"])
def login_view(request):
    """处理用户登录逻辑。"""
    if request.user.is_authenticated:
        return redirect(_next_url(request))
    nxt = _next_url(request)
    ip = client_ip(request)
    context = {"next": nxt, "logged_out": request.GET.get("logged_out") == "1"}
    context.update(_login_challenge_context(request, ip))
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""
        context["username_value"] = username
        context.update(_login_challenge_context(request, ip))
        total_limit_key = _login_total_rate_limit_key(ip)
        if not _rate_limit_allow(
            total_limit_key,
            limit=_auth_int_setting("AUTH_LOGIN_IP_RATE_LIMIT", LOGIN_IP_RATE_LIMIT),
            window_seconds=_auth_int_setting(
                "AUTH_LOGIN_IP_RATE_WINDOW_SECONDS",
                LOGIN_IP_RATE_WINDOW_SECONDS,
            ),
        ):
            auth_service.audit_auth_event(
                AuthAudit.Action.LOGIN,
                request,
                method=AuthAudit.Method.PASSWORD,
                status=AuthAudit.Status.RATE_LIMITED,
                identifier=username,
                metadata={"scope": "ip"},
            )
            messages.error(request, "登录请求过于频繁，请稍后再试")
            return render(request, "accounts/login.html", context, status=429)
        if context.get("login_challenge_required"):
            if not _validate_login_challenge(request):
                _record_login_failure(ip)
                context.update(_login_challenge_context(request, ip))
                _ensure_login_challenge(request, refresh=True)
                context.update(_login_challenge_context(request, ip))
                auth_service.audit_auth_event(
                    AuthAudit.Action.LOGIN,
                    request,
                    method=AuthAudit.Method.PASSWORD,
                    status=AuthAudit.Status.BLOCKED,
                    identifier=username,
                    metadata={"reason": "challenge_required"},
                )
                messages.error(request, "请先完成安全校验")
                return render(request, "accounts/login.html", context, status=400)
        rl_key = f"auth:login:v1:{ip}:{username.lower()}"
        if not _rate_limit_allow(
            rl_key,
            limit=LOGIN_RATE_LIMIT,
            window_seconds=LOGIN_RATE_WINDOW_SECONDS,
        ):
            auth_service.audit_auth_event(
                AuthAudit.Action.LOGIN,
                request,
                method=AuthAudit.Method.PASSWORD,
                status=AuthAudit.Status.RATE_LIMITED,
                identifier=username,
                metadata={"scope": "identifier"},
            )
            messages.error(request, "尝试次数过多，请稍后再试")
            return render(request, "accounts/login.html", context, status=429)
        user = auth_service.authenticate_identifier(request, username, password)
        if user:
            cache.delete(rl_key)
            cache.delete(_login_failure_rate_limit_key(ip))
            _clear_login_challenge(request)
            auth_service.complete_login(
                request,
                user,
                method=AuthAudit.Method.PASSWORD,
                identifier=username,
            )
            return redirect(_next_url(request))
        _record_login_failure(ip)
        if context.get("login_challenge_required"):
            _ensure_login_challenge(request, refresh=True)
        messages.error(request, "账号或密码错误")
        context.update(_login_challenge_context(request, ip))
    return render(request, "accounts/login.html", context)


@require_http_methods(["GET", "POST"])
def signup_view(request):
    """处理用户注册逻辑。"""
    if request.user.is_authenticated:
        return redirect("/")
    context = {"next": _next_url(request, fallback="/")}
    if request.method == "POST":
        ip = client_ip(request)
        rl_key = f"auth:signup:v1:{ip}"
        if not _rate_limit_allow(
            rl_key,
            limit=SIGNUP_RATE_LIMIT,
            window_seconds=SIGNUP_RATE_WINDOW_SECONDS,
        ):
            messages.error(request, "请求过于频繁，请稍后再试")
            return render(request, "accounts/signup.html", context, status=429)
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        password = request.POST.get("password") or ""
        context.update({"username_value": username, "email_value": email})
        if not username or not password:
            messages.error(request, "用户名与密码必填")
            return render(request, "accounts/signup.html", context, status=400)
        if User.objects.filter(username=username).exists():
            messages.error(request, "用户名已存在")
            return render(request, "accounts/signup.html", context, status=400)
        if email and User.objects.filter(email__iexact=email).exists():
            messages.error(request, "邮箱已存在")
            return render(request, "accounts/signup.html", context, status=400)

        strength_errors = password_strength_errors(password, username=username)
        if strength_errors:
            for msg in strength_errors:
                messages.error(request, msg)
            return render(request, "accounts/signup.html", context, status=400)

        try:
            with transaction.atomic():
                user = User.objects.create_user(username=username, email=email, password=password)
        except IntegrityError:
            if User.objects.filter(username=username).exists():
                messages.error(request, "用户名已存在")
            elif email and User.objects.filter(email__iexact=email).exists():
                messages.error(request, "邮箱已存在")
            else:
                messages.error(request, "创建账号失败，请稍后重试")
            return render(request, "accounts/signup.html", context, status=400)
        login(request, user)
        return redirect(_next_url(request, fallback="/"))
    return render(request, "accounts/signup.html", context)


@require_POST
def logout_view(request):
    """注销当前用户并跳转。"""
    if request.user.is_authenticated:
        auth_service.audit_auth_event(
            AuthAudit.Action.LOGOUT,
            request,
            method=AuthAudit.Method.SESSION,
            status=AuthAudit.Status.SUCCESS,
            user=request.user,
            identifier=request.user.username,
        )
    logout(request)
    messages.success(request, "你已安全退出，可随时重新登录。")
    return redirect(_append_query_params(settings.LOGOUT_REDIRECT_URL, logged_out=1))


@login_required
@require_http_methods(["GET", "POST"])
def reauth_view(request):
    nxt = _next_url(request, fallback="/")
    if request.method == "POST":
        rl_key = _reauth_rate_limit_key(request)
        if not _rate_limit_allow(
            rl_key,
            limit=REAUTH_RATE_LIMIT,
            window_seconds=REAUTH_RATE_WINDOW_SECONDS,
        ):
            auth_service.audit_auth_event(
                AuthAudit.Action.REAUTH,
                request,
                method=AuthAudit.Method.PASSWORD,
                status=AuthAudit.Status.RATE_LIMITED,
                user=request.user,
                identifier=request.user.username,
            )
            messages.error(request, "确认次数过多，请稍后再试")
            return render(
                request,
                "accounts/reauth.html",
                {"next": nxt, "has_password": request.user.has_usable_password()},
                status=429,
            )
        password = request.POST.get("password") or ""
        user = auth_service.authenticate_current_user_password(request, password)
        if user:
            cache.delete(rl_key)
            if not auth_service.complete_reauth(
                request,
                request.user,
                method=AuthAudit.Method.PASSWORD,
                identifier=request.user.username,
            ):
                messages.error(request, "账号当前不可用，请联系管理员")
                return render(
                    request,
                    "accounts/reauth.html",
                    {"next": nxt, "has_password": request.user.has_usable_password()},
                    status=403,
                )
            return redirect(nxt)
        messages.error(request, "密码错误")
    return render(
        request,
        "accounts/reauth.html",
        {"next": nxt, "has_password": request.user.has_usable_password()},
    )


@login_required
@require_http_methods(["POST"])
def reauth_api(request):
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return _json({"ok": False, "error": "invalid_json"}, 400)
    rl_key = _reauth_rate_limit_key(request)
    if not _rate_limit_allow(
        rl_key,
        limit=REAUTH_RATE_LIMIT,
        window_seconds=REAUTH_RATE_WINDOW_SECONDS,
    ):
        auth_service.audit_auth_event(
            AuthAudit.Action.REAUTH,
            request,
            method=AuthAudit.Method.PASSWORD,
            status=AuthAudit.Status.RATE_LIMITED,
            user=request.user,
            identifier=request.user.username,
        )
        return _json({"ok": False, "error": "rate_limited"}, 429)
    password = data.get("password") or ""
    if not password:
        return _json({"ok": False, "error": "missing_password"}, 400)
    if not request.user.has_usable_password():
        return _json({"ok": False, "error": "no_password"}, 400)
    user = auth_service.authenticate_current_user_password(request, password)
    if not user:
        return _json({"ok": False, "error": "wrong_password"}, 403)
    cache.delete(rl_key)
    if not auth_service.complete_reauth(
        request,
        request.user,
        method=AuthAudit.Method.PASSWORD,
        identifier=request.user.username,
    ):
        return _json({"ok": False, "error": "account_disabled"}, 403)
    return _json({"ok": True})


@login_required
@require_http_methods(["POST"])
def reauth_google(request):
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return _json({"ok": False, "error": "invalid_json"}, 400)
    cred = (data.get("credential") or "").strip()
    if not cred:
        auth_service.audit_auth_event(
            AuthAudit.Action.REAUTH,
            request,
            method=AuthAudit.Method.GOOGLE,
            status=AuthAudit.Status.FAILED,
            user=request.user,
            identifier=request.user.email or request.user.username,
            metadata={"reason": "missing_credential"},
        )
        return _json({"ok": False, "error": "missing_credential"}, 400)
    rl_key = _reauth_rate_limit_key(request)
    if not _rate_limit_allow(
        rl_key,
        limit=REAUTH_RATE_LIMIT,
        window_seconds=REAUTH_RATE_WINDOW_SECONDS,
    ):
        auth_service.audit_auth_event(
            AuthAudit.Action.REAUTH,
            request,
            method=AuthAudit.Method.GOOGLE,
            status=AuthAudit.Status.RATE_LIMITED,
            user=request.user,
            identifier=request.user.email or request.user.username,
        )
        return _json({"ok": False, "error": "rate_limited"}, 429)
    try:
        idinfo = id_token.verify_oauth2_token(
            cred, grequests.Request(), settings.GOOGLE_CLIENT_ID
        )
        email = idinfo.get("email") or ""
        email_verified = idinfo.get("email_verified", False)
        if not email or not email_verified:
            auth_service.audit_auth_event(
                AuthAudit.Action.REAUTH,
                request,
                method=AuthAudit.Method.GOOGLE,
                status=AuthAudit.Status.FAILED,
                user=request.user,
                identifier=email,
                metadata={"reason": "email_not_verified"},
            )
            return _json({"ok": False, "error": "email_not_verified"}, 400)
        if not request.user.email or request.user.email.lower() != email.lower():
            auth_service.audit_auth_event(
                AuthAudit.Action.REAUTH,
                request,
                method=AuthAudit.Method.GOOGLE,
                status=AuthAudit.Status.FAILED,
                user=request.user,
                identifier=email,
                metadata={"reason": "email_mismatch"},
            )
            return _json({"ok": False, "error": "email_mismatch"}, 403)
        if not auth_service.complete_reauth(
            request,
            request.user,
            method=AuthAudit.Method.GOOGLE,
            identifier=email,
        ):
            return _json({"ok": False, "error": "account_disabled"}, 403)
        cache.delete(rl_key)
        return _json({"ok": True})
    except ValueError:
        auth_service.audit_auth_event(
            AuthAudit.Action.REAUTH,
            request,
            method=AuthAudit.Method.GOOGLE,
            status=AuthAudit.Status.FAILED,
            user=request.user,
            identifier=request.user.email or request.user.username,
            metadata={"reason": "invalid_token"},
        )
        return _json({"ok": False, "error": "invalid_token"}, 400)


@login_required
@require_http_methods(["GET", "POST"])
def profile_view(request):
    """展示并更新当前用户的个人资料。"""

    user = request.user
    password_requires_old = user.has_usable_password()
    if request.method == "POST" and "password_submit" in request.POST:
        form = ProfileForm(instance=user)
        if password_requires_old:
            password_form = PasswordUpdateForm(user=user, data=request.POST)
        else:
            password_form = PasswordSetForm(user=user, data=request.POST)
        if password_form.is_valid():
            password_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "密码已更新")
            return redirect("accounts:profile")
        messages.error(request, "密码更新失败，请检查提示")
    elif request.method == "POST":
        form = ProfileForm(request.POST, instance=user)
        password_form = (
            PasswordUpdateForm(user=user)
            if password_requires_old
            else PasswordSetForm(user=user)
        )
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
            except IntegrityError:
                form.add_error("email", "该邮箱已被其他账号使用")
                messages.error(request, "请检查填写内容")
                return render(
                    request,
                    "accounts/profile.html",
                    {
                        "form": form,
                        "user_obj": user,
                        "password_form": password_form,
                        "password_requires_old": password_requires_old,
                        "security_alerts": [],
                        "security_summary": {
                            "total_entries": 0,
                            "personal_entries": 0,
                            "team_entries": 0,
                            "active_links": 0,
                            "last_login": user.last_login,
                        },
                    },
                    status=400,
                )
            messages.success(request, "个人资料已更新")
            return redirect("accounts:profile")
        messages.error(request, "请检查填写内容")
    else:
        form = ProfileForm(instance=user)
        password_form = (
            PasswordUpdateForm(user=user)
            if password_requires_old
            else PasswordSetForm(user=user)
        )

    now = timezone.now()
    security_alerts: list[str] = []
    entry_qs = TOTPEntry.objects.for_user(user)
    stale_cutoff = now - timedelta(days=90)
    entry_counts = entry_qs.aggregate(
        total_entries=Count("id", distinct=True),
        personal_entries=Count("id", filter=Q(team__isnull=True), distinct=True),
        stale_entries=Count("id", filter=Q(created_at__lt=stale_cutoff), distinct=True),
    )
    total_entries = entry_counts.get("total_entries") or 0
    personal_entries = entry_counts.get("personal_entries") or 0
    team_entries = total_entries - personal_entries
    active_links = (
        OneTimeLink.active.filter(created_by=user)
        .filter(
            Q(entry__team__isnull=True, entry__user=user)
            | Q(entry__team__isnull=False, entry__team__memberships__user=user)
        )
        .distinct()
        .count()
    )
    if not user.email:
        security_alerts.append("尚未设置邮箱，建议补充邮箱以便账号找回和安全通知。")
    if active_links:
        security_alerts.append(f"当前有 {active_links} 条一次性访问链接仍然有效，请确认是否需要失效。")
    stale_entries = entry_counts.get("stale_entries") or 0
    if stale_entries:
        security_alerts.append(f"{stale_entries} 条密钥已超过 90 天未更新，可考虑定期轮换以提升安全性。")
    if personal_entries == 0 and team_entries == 0:
        security_alerts.append("还没有保存任何密钥，建议添加后再使用导出功能定期备份。")

    security_summary = {
        "total_entries": total_entries,
        "personal_entries": personal_entries,
        "team_entries": team_entries,
        "active_links": active_links,
        "last_login": user.last_login,
    }

    context = {
        "form": form,
        "user_obj": user,
        "password_form": password_form,
        "password_requires_old": password_requires_old,
        "security_alerts": security_alerts,
        "security_summary": security_summary,
    }
    return render(request, "accounts/profile.html", context)


@require_http_methods(["POST"])
def google_onetap(request):
    """处理 Google One Tap 登录回调。"""
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return _json({"ok": False, "error": "invalid_json"}, 400)
    cred = (data.get("credential") or "").strip()
    if not cred:
        auth_service.audit_auth_event(
            AuthAudit.Action.LOGIN,
            request,
            method=AuthAudit.Method.GOOGLE,
            status=AuthAudit.Status.FAILED,
            metadata={"reason": "missing_credential"},
        )
        return _json({"ok": False, "error": "missing_credential"}, 400)
    try:
        # 使用 Google 提供的 SDK 验证前端返回的身份凭证
        idinfo = id_token.verify_oauth2_token(
            cred, grequests.Request(), settings.GOOGLE_CLIENT_ID
        )
        email = idinfo.get("email") or ""
        email_verified = idinfo.get("email_verified", False)
        if not email or not email_verified:
            auth_service.audit_auth_event(
                AuthAudit.Action.LOGIN,
                request,
                method=AuthAudit.Method.GOOGLE,
                status=AuthAudit.Status.FAILED,
                identifier=email,
                metadata={"reason": "email_not_verified"},
            )
            return _json({"ok": False, "error": "email_not_verified"}, 400)
        try:
            user, created = _get_or_create_google_user(email)
        except ValueError as exc:
            auth_service.audit_auth_event(
                AuthAudit.Action.LOGIN,
                request,
                method=AuthAudit.Method.GOOGLE,
                status=AuthAudit.Status.FAILED,
                identifier=email,
                metadata={"reason": str(exc)},
            )
            return _json({"ok": False, "error": str(exc)}, 400)
        except RuntimeError:
            auth_service.audit_auth_event(
                AuthAudit.Action.LOGIN,
                request,
                method=AuthAudit.Method.GOOGLE,
                status=AuthAudit.Status.FAILED,
                identifier=email,
                metadata={"reason": "user_creation_failed"},
            )
            return _json({"ok": False, "error": "user_creation_failed"}, 500)
        if not auth_service.complete_login(
            request,
            user,
            method=AuthAudit.Method.GOOGLE,
            identifier=email,
            metadata={"created": created},
        ):
            return _json({"ok": False, "error": "account_disabled"}, 403)
        if not user.password:
            user.set_unusable_password()
            user.save(update_fields=["password"])
        # 保持邮箱信息最新
        if not user.email:
            user.email = email
            user.save(update_fields=["email"])
        return _json({"ok": True, "created": created})
    except ValueError:
        # 凭证验证失败
        auth_service.audit_auth_event(
            AuthAudit.Action.LOGIN,
            request,
            method=AuthAudit.Method.GOOGLE,
            status=AuthAudit.Status.FAILED,
            metadata={"reason": "invalid_token"},
        )
        return _json({"ok": False, "error": "invalid_token"}, 400)


def _get_or_create_google_user(email: str):
    """按邮箱查找或创建 Google 登录用户，避免用户名碰撞时误绑到其他账号。"""

    users = list(User.objects.filter(email__iexact=email)[:2])
    if len(users) > 1:
        raise ValueError("email_not_unique")
    if users:
        return users[0], False

    for _ in range(6):
        username = _username_from_email(email)
        try:
            with transaction.atomic():
                user = User.objects.create_user(username=username, email=email)
        except IntegrityError:
            # 可能有并发请求刚好抢占了同一用户名；若邮箱已落库则直接复用，
            # 否则重新生成用户名，避免错误登录到碰撞的旧账号。
            users = list(User.objects.filter(email__iexact=email)[:2])
            if len(users) > 1:
                raise ValueError("email_not_unique")
            if users:
                return users[0], False
            continue
        return user, True

    raise RuntimeError("google_user_creation_failed")


def _username_from_email(email: str) -> str:
    """根据邮箱生成唯一的用户名。"""

    base = re.sub(r"[^a-zA-Z0-9_.-]", "", (email.split("@")[0] or "user"))
    base = base[:24] or "user"

    queryset = User.objects.filter(username__startswith=base).only("username")
    if not queryset.filter(username=base).exists():
        return base

    max_suffix = 0
    for username in (
        queryset.exclude(username=base)
        .values_list("username", flat=True)
        .iterator(chunk_size=256)
    ):
        suffix = username[len(base):]
        if suffix.isdigit():
            value = int(suffix)
            if value > max_suffix:
                max_suffix = value

    candidate_suffix = max_suffix + 1
    candidate = f"{base}{candidate_suffix}"
    if not User.objects.filter(username=candidate).exists():
        return candidate

    # 极端情况下存在间隙或高并发冲突，回退到逐步探查，
    # 但因为通常仅需极少次数，整体开销仍远小于一次性加载全部用户名。
    for i in range(candidate_suffix + 1, candidate_suffix + 10000):
        cand = f"{base}{i}"
        if not User.objects.filter(username=cand).exists():
            return cand

    while True:
        rand_suffix = secrets.token_hex(2)
        cand = f"{base}{rand_suffix}"
        if not User.objects.filter(username=cand).exists():
            return cand


def _json(obj, status=200):
    """简化返回 JSON 的辅助函数。"""

    return JsonResponse(obj, status=status)
