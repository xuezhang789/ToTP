from __future__ import annotations

import secrets

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.utils import timezone

from project.utils import client_ip

from .models import AuthAudit

LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW_SECONDS = 300
REAUTH_RATE_LIMIT = 8
REAUTH_RATE_WINDOW_SECONDS = 300
LOGIN_IP_RATE_LIMIT = 40
LOGIN_IP_RATE_WINDOW_SECONDS = 300
LOGIN_CHALLENGE_THRESHOLD = 5
LOGIN_CHALLENGE_WINDOW_SECONDS = 900
LOGIN_CHALLENGE_TTL_SECONDS = 600
LOGIN_CHALLENGE_SESSION_KEY = "auth_login_challenge_v1"


def auth_int_setting(name: str, default: int) -> int:
    return int(getattr(settings, name, default) or default)


def rate_limit_increment(cache_key: str, *, window_seconds: int) -> int:
    if cache.add(cache_key, 1, window_seconds):
        return 1
    try:
        return cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 1, window_seconds)
        return 1


def rate_limit_allow(cache_key: str, *, limit: int, window_seconds: int) -> bool:
    return rate_limit_increment(cache_key, window_seconds=window_seconds) <= limit


def reauth_rate_limit_key(request) -> str:
    return f"auth:reauth:v1:{request.user.pk}:{client_ip(request)}"


def login_total_rate_limit_key(ip: str) -> str:
    return f"auth:login:v2:ip:{ip}"


def login_failure_rate_limit_key(ip: str) -> str:
    return f"auth:login:v2:fail:{ip}"


def clear_login_challenge(request):
    if LOGIN_CHALLENGE_SESSION_KEY in request.session:
        del request.session[LOGIN_CHALLENGE_SESSION_KEY]
        request.session.modified = True


def ensure_login_challenge(request, *, refresh: bool = False):
    now_ts = int(timezone.now().timestamp())
    ttl_seconds = auth_int_setting(
        "AUTH_LOGIN_CHALLENGE_TTL_SECONDS",
        LOGIN_CHALLENGE_TTL_SECONDS,
    )
    stored = request.session.get(LOGIN_CHALLENGE_SESSION_KEY)
    if (
        not refresh
        and isinstance(stored, dict)
        and stored.get("prompt")
        and stored.get("answer")
        and now_ts - int(stored.get("created_at") or 0) <= ttl_seconds
    ):
        return stored

    left = secrets.randbelow(8) + 1
    right = secrets.randbelow(8) + 1
    challenge = {
        "prompt": f"{left} + {right} = ?",
        "answer": str(left + right),
        "created_at": now_ts,
    }
    request.session[LOGIN_CHALLENGE_SESSION_KEY] = challenge
    request.session.modified = True
    return challenge


def login_challenge_context(request, ip: str) -> dict:
    failure_count = int(cache.get(login_failure_rate_limit_key(ip)) or 0)
    threshold = auth_int_setting(
        "AUTH_LOGIN_CHALLENGE_THRESHOLD",
        LOGIN_CHALLENGE_THRESHOLD,
    )
    if failure_count < threshold:
        clear_login_challenge(request)
        return {
            "login_challenge_required": False,
            "login_challenge_prompt": "",
            "login_failure_count": failure_count,
        }
    challenge = ensure_login_challenge(request)
    return {
        "login_challenge_required": True,
        "login_challenge_prompt": challenge["prompt"],
        "login_failure_count": failure_count,
    }


def record_login_failure(ip: str) -> int:
    return rate_limit_increment(
        login_failure_rate_limit_key(ip),
        window_seconds=auth_int_setting(
            "AUTH_LOGIN_CHALLENGE_WINDOW_SECONDS",
            LOGIN_CHALLENGE_WINDOW_SECONDS,
        ),
    )


def validate_login_challenge(request) -> bool:
    stored = request.session.get(LOGIN_CHALLENGE_SESSION_KEY)
    if not isinstance(stored, dict):
        return False
    submitted = (request.POST.get("challenge_answer") or "").strip()
    expected = str(stored.get("answer") or "")
    return bool(submitted) and submitted == expected


def audit_auth_event(
    action: str,
    request,
    *,
    method: str,
    status: str,
    user=None,
    identifier: str = "",
    metadata: dict | None = None,
):
    user_obj = None
    if user is not None and (
        getattr(user, "is_authenticated", False) or getattr(user, "pk", None)
    ):
        user_obj = user
    ip = client_ip(request) if request is not None else "unknown"
    AuthAudit.objects.create(
        user=user_obj,
        action=action,
        method=method,
        status=status,
        identifier=(identifier or "")[:255],
        ip_address=None if ip == "unknown" else ip,
        user_agent=((request.META.get("HTTP_USER_AGENT", "") if request is not None else "")[:255]),
        metadata=metadata or {},
    )


def user_can_authenticate(user) -> bool:
    if user is None:
        return False
    return bool(getattr(user, "is_active", True))


def authenticate_identifier(request, identifier: str, password: str):
    user = authenticate(request, username=identifier, password=password)
    if user is None:
        audit_auth_event(
            AuthAudit.Action.LOGIN,
            request,
            method=AuthAudit.Method.PASSWORD,
            status=AuthAudit.Status.FAILED,
            identifier=identifier,
            metadata={"reason": "bad_credentials"},
        )
    return user


def authenticate_current_user_password(request, password: str):
    user = authenticate(request, username=request.user.username, password=password)
    if user is None:
        audit_auth_event(
            AuthAudit.Action.REAUTH,
            request,
            method=AuthAudit.Method.PASSWORD,
            status=AuthAudit.Status.FAILED,
            user=request.user,
            identifier=request.user.username,
            metadata={"reason": "bad_credentials"},
        )
    return user


def complete_login(request, user, *, method: str, identifier: str = "", metadata: dict | None = None) -> bool:
    if not user_can_authenticate(user):
        audit_auth_event(
            AuthAudit.Action.LOGIN,
            request,
            method=method,
            status=AuthAudit.Status.BLOCKED,
            user=user,
            identifier=identifier,
            metadata={"reason": "account_disabled", **(metadata or {})},
        )
        return False

    login(request, user)
    audit_auth_event(
        AuthAudit.Action.LOGIN,
        request,
        method=method,
        status=AuthAudit.Status.SUCCESS,
        user=user,
        identifier=identifier,
        metadata=metadata,
    )
    return True


def complete_reauth(request, user, *, method: str, identifier: str = "", metadata: dict | None = None) -> bool:
    if not user_can_authenticate(user):
        audit_auth_event(
            AuthAudit.Action.REAUTH,
            request,
            method=method,
            status=AuthAudit.Status.BLOCKED,
            user=user,
            identifier=identifier,
            metadata={"reason": "account_disabled", **(metadata or {})},
        )
        return False

    request.session["reauth_at"] = int(timezone.now().timestamp())
    audit_auth_event(
        AuthAudit.Action.REAUTH,
        request,
        method=method,
        status=AuthAudit.Status.SUCCESS,
        user=user,
        identifier=identifier,
        metadata=metadata,
    )
    return True
