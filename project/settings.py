import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-me")
DEBUG = _env_bool("DJANGO_DEBUG", True)

_hosts_raw = os.environ.get("DJANGO_ALLOWED_HOSTS", "")
if _hosts_raw.strip():
    ALLOWED_HOSTS = [h.strip() for h in _hosts_raw.split(",") if h.strip()]
else:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]", "testserver"]

TOTP_ENC_KEYS: list[str] = []
_enc_key = os.environ.get("TOTP_ENC_KEY", "").strip()
if _enc_key:
    TOTP_ENC_KEYS.append(_enc_key)
_enc_keys = os.environ.get("TOTP_ENC_KEYS", "").strip()
if _enc_keys:
    TOTP_ENC_KEYS.extend([k.strip() for k in _enc_keys.split(",") if k.strip()])

TOTP_DATA_KEYS: list[str] = []
_data_key = os.environ.get("TOTP_DATA_KEY", "").strip()
if _data_key:
    TOTP_DATA_KEYS.append(_data_key)
_data_keys = os.environ.get("TOTP_DATA_KEYS", "").strip()
if _data_keys:
    TOTP_DATA_KEYS.extend([k.strip() for k in _data_keys.split(",") if k.strip()])
TOTP_DATA_KEY_FILE = os.environ.get("TOTP_DATA_KEY_FILE", "").strip()
TOTP_DATA_KEY_LOADER = os.environ.get("TOTP_DATA_KEY_LOADER", "").strip()
TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK = _env_bool("TOTP_ALLOW_LEGACY_ENCRYPTION_FALLBACK", True)
TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK = _env_bool(
    "TOTP_ALLOW_SECRET_KEY_ENCRYPTION_FALLBACK",
    DEBUG,
)

if not DEBUG:
    if SECRET_KEY.strip() == "dev-secret-key-change-me":
        raise RuntimeError("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is false")
    if "*" in ALLOWED_HOSTS:
        raise RuntimeError("DJANGO_ALLOWED_HOSTS must not contain '*' in production")
    if not (TOTP_DATA_KEYS or TOTP_DATA_KEY_FILE or TOTP_DATA_KEY_LOADER or TOTP_ENC_KEYS):
        raise RuntimeError(
            "TOTP_DATA_KEY/TOTP_DATA_KEYS/TOTP_DATA_KEY_FILE/TOTP_DATA_KEY_LOADER "
            "or legacy TOTP_ENC_KEY/TOTP_ENC_KEYS must be set when DJANGO_DEBUG is false"
        )

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "totp",
    "accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "project.middleware.CSPNonceMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "accounts.context_processors.google_client_id",
                "project.context_processors.csp_nonce",
            ],
        },
    },
]

WSGI_APPLICATION = "project.wsgi.application"

AUTHENTICATION_BACKENDS = [
    "accounts.backends.UsernameOrEmailBackend",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "Asia/Shanghai"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
USE_MANIFEST_STATIC = _env_bool("DJANGO_STATIC_MANIFEST", not DEBUG)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
            if USE_MANIFEST_STATIC
            else "django.contrib.staticfiles.storage.StaticFilesStorage"
        )
    },
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/auth/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/auth/login/"

CSP_ENABLED = _env_bool("DJANGO_CSP", not DEBUG)
CSP_REPORT_ONLY = _env_bool("DJANGO_CSP_REPORT_ONLY", DEBUG)

EXTERNAL_TOOL_ENABLED = _env_bool("TOTP_EXTERNAL_TOOL_ENABLED", DEBUG)
EXTERNAL_TOTP_RATE_LIMIT = int(os.environ.get("TOTP_EXTERNAL_TOTP_RATE_LIMIT", "20"))
EXTERNAL_TOTP_RATE_WINDOW_SECONDS = int(os.environ.get("TOTP_EXTERNAL_TOTP_RATE_WINDOW_SECONDS", "60"))
EXTERNAL_TOTP_RATE_LIMIT_LONG = int(os.environ.get("TOTP_EXTERNAL_TOTP_RATE_LIMIT_LONG", "60"))
EXTERNAL_TOTP_RATE_WINDOW_SECONDS_LONG = int(os.environ.get("TOTP_EXTERNAL_TOTP_RATE_WINDOW_SECONDS_LONG", "600"))
EXTERNAL_TOTP_MAX_BODY_BYTES = int(os.environ.get("TOTP_EXTERNAL_TOTP_MAX_BODY_BYTES", "4096"))
EXTERNAL_TOTP_MAX_SECRET_LENGTH = int(os.environ.get("TOTP_EXTERNAL_TOTP_MAX_SECRET_LENGTH", "256"))
EXTERNAL_TOOL_ALLOW_SECRET_PREFILL = _env_bool("TOTP_EXTERNAL_TOOL_ALLOW_SECRET_PREFILL", False)

AUTH_LOGIN_IP_RATE_LIMIT = int(os.environ.get("AUTH_LOGIN_IP_RATE_LIMIT", "40"))
AUTH_LOGIN_IP_RATE_WINDOW_SECONDS = int(os.environ.get("AUTH_LOGIN_IP_RATE_WINDOW_SECONDS", "300"))
AUTH_LOGIN_CHALLENGE_THRESHOLD = int(os.environ.get("AUTH_LOGIN_CHALLENGE_THRESHOLD", "5"))
AUTH_LOGIN_CHALLENGE_WINDOW_SECONDS = int(os.environ.get("AUTH_LOGIN_CHALLENGE_WINDOW_SECONDS", "900"))
AUTH_LOGIN_CHALLENGE_TTL_SECONDS = int(os.environ.get("AUTH_LOGIN_CHALLENGE_TTL_SECONDS", "600"))

TRUST_X_FORWARDED_FOR = _env_bool("DJANGO_TRUST_X_FORWARDED_FOR", False)

EXPORT_ENCRYPTED_MAX_ENTRIES = int(os.environ.get("TOTP_EXPORT_ENCRYPTED_MAX_ENTRIES", "2000"))
EXPORT_OFFLINE_MAX_ENTRIES = int(os.environ.get("TOTP_EXPORT_OFFLINE_MAX_ENTRIES", "1000"))
IMPORT_MAX_ENTRIES = int(os.environ.get("TOTP_IMPORT_MAX_ENTRIES", "500"))
IMPORT_PREVIEW_TTL_SECONDS = int(os.environ.get("TOTP_IMPORT_PREVIEW_TTL_SECONDS", "900"))

REDIS_URL = os.environ.get("REDIS_URL", "").strip()
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "totp-cache",
        }
    }

SECURE_SSL_REDIRECT = _env_bool("DJANGO_SECURE_SSL_REDIRECT", not DEBUG)
SESSION_COOKIE_SECURE = _env_bool("DJANGO_SESSION_COOKIE_SECURE", not DEBUG)
CSRF_COOKIE_SECURE = _env_bool("DJANGO_CSRF_COOKIE_SECURE", not DEBUG)
SESSION_COOKIE_SAMESITE = os.environ.get("DJANGO_SESSION_COOKIE_SAMESITE", "Lax")
CSRF_COOKIE_SAMESITE = os.environ.get("DJANGO_CSRF_COOKIE_SAMESITE", "Lax")
SESSION_COOKIE_HTTPONLY = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = os.environ.get("DJANGO_X_FRAME_OPTIONS", "DENY")
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_HSTS_SECONDS", "0" if DEBUG else "31536000"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool("DJANGO_HSTS_INCLUDE_SUBDOMAINS", not DEBUG)
SECURE_HSTS_PRELOAD = _env_bool("DJANGO_HSTS_PRELOAD", not DEBUG)
SECURE_REFERRER_POLICY = os.environ.get("DJANGO_SECURE_REFERRER_POLICY", "same-origin")
SECURE_BROWSER_XSS_FILTER = _env_bool("DJANGO_SECURE_BROWSER_XSS_FILTER", True)
DATA_UPLOAD_MAX_MEMORY_SIZE = int(os.environ.get("DJANGO_DATA_UPLOAD_MAX_MEMORY_SIZE", str(2 * 1024 * 1024)))
FILE_UPLOAD_MAX_MEMORY_SIZE = int(os.environ.get("DJANGO_FILE_UPLOAD_MAX_MEMORY_SIZE", str(2 * 1024 * 1024)))

# Google One Tap
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com")
