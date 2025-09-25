import json, re
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings

from google.oauth2 import id_token
from google.auth.transport import requests as grequests

User = get_user_model()

COMMON_WEAK_PASSWORDS = {
    "password",
    "123456",
    "123456789",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "12345678",
    "123123",
    "qwertyuiop",
    "letmein",
    "admin",
    "welcome",
    "iloveyou",
    "dragon",
    "monkey",
    "login",
    "000000",
    "1q2w3e4r",
    "zaq12wsx",
}


def _next_url(request, fallback="/"):
    """获取登录后应跳转的 URL。"""
    nxt = request.GET.get("next") or request.POST.get("next") or fallback
    return nxt


def _password_strength_errors(password: str, username: str = ""):
    errors = []
    pwd = password or ""

    if len(pwd) < 8:
        errors.append("密码长度至少需要 8 个字符")

    categories = {
        "upper": bool(re.search(r"[A-Z]", pwd)),
        "lower": bool(re.search(r"[a-z]", pwd)),
        "digit": bool(re.search(r"\d", pwd)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", pwd)),
    }
    if sum(categories.values()) < 3:
        errors.append("密码需至少包含大写字母、小写字母、数字、符号中的三类")

    if re.search(r"\s", pwd):
        errors.append("密码不能包含空白字符")

    if username and username.lower() in pwd.lower():
        errors.append("密码不能包含用户名")

    if pwd.lower() in COMMON_WEAK_PASSWORDS:
        errors.append("密码与常见弱口令一致，请重新设置")

    return errors


@require_http_methods(["GET", "POST"])
def login_view(request):
    """处理用户登录逻辑。"""
    if request.user.is_authenticated:
        return redirect(_next_url(request))
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = (request.POST.get("password") or "").strip()
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect(_next_url(request))
        messages.error(request, "用户名或密码错误")
    return render(request, "accounts/login.html", {})


@require_http_methods(["GET", "POST"])
def signup_view(request):
    """处理用户注册逻辑。"""
    if request.user.is_authenticated:
        return redirect("/")
    context = {}
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        password = (request.POST.get("password") or "").strip()
        context.update({"username_value": username, "email_value": email})
        if not username or not password:
            messages.error(request, "用户名与密码必填")
            return render(request, "accounts/signup.html", context, status=400)
        if User.objects.filter(username=username).exists():
            messages.error(request, "用户名已存在")
            return render(request, "accounts/signup.html", context, status=400)

        strength_errors = _password_strength_errors(password, username=username)
        if strength_errors:
            for msg in strength_errors:
                messages.error(request, msg)
            return render(request, "accounts/signup.html", context, status=400)

        user = User.objects.create_user(username=username, email=email, password=password)
        login(request, user)
        return redirect("/")
    return render(request, "accounts/signup.html", context)


def logout_view(request):
    """注销当前用户并跳转。"""
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


@csrf_exempt
@require_http_methods(["POST"])
def google_onetap(request):
    """处理 Google One Tap 登录回调。"""
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return _json({"ok": False, "error": "invalid_json"}, 400)
    cred = (data.get("credential") or "").strip()
    if not cred:
        return _json({"ok": False, "error": "missing_credential"}, 400)
    try:
        idinfo = id_token.verify_oauth2_token(
            cred, grequests.Request(), settings.GOOGLE_CLIENT_ID
        )
        email = idinfo.get("email") or ""
        email_verified = idinfo.get("email_verified", False)
        name = idinfo.get("name") or ""
        sub = idinfo.get("sub") or ""
        if not email or not email_verified:
            return _json({"ok": False, "error": "email_not_verified"}, 400)
        username = _username_from_email(email)
        user, created = User.objects.get_or_create(
            username=username, defaults={"email": email}
        )
        # 保持邮箱信息最新
        if not user.email:
            user.email = email
            user.save(update_fields=["email"])
        login(request, user)
        return _json({"ok": True, "created": created})
    except ValueError:
        # 凭证验证失败
        return _json({"ok": False, "error": "invalid_token"}, 400)


def _username_from_email(email: str) -> str:
    """根据邮箱生成唯一的用户名。"""
    base = re.sub(r"[^a-zA-Z0-9_.-]", "", (email.split("@")[0] or "user"))
    base = base[:24] or "user"

    # Retrieve all usernames starting with the base prefix once
    existing = set(
        User.objects.filter(username__startswith=base).values_list("username", flat=True)
    )
    if base not in existing:
        return base

    # Find the first free suffix
    for i in range(1, 10000):
        cand = f"{base}{i}"
        if cand not in existing:
            return cand
    return base  # fallback


from django.http import JsonResponse


def _json(obj, status=200):
    """简化返回 JSON 的辅助函数。"""

    return JsonResponse(obj, status=status)
