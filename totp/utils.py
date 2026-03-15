import base64, hashlib, hmac, struct, time
from urllib.parse import urlparse, parse_qs, unquote
from cryptography.fernet import Fernet
from django.conf import settings

_B32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_FERNETS = None


def _derive_fernet_key(material: str) -> bytes:
    digest = hashlib.sha256(material.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _fernets():
    """返回缓存的 Fernet 实例列表，按优先级从高到低。"""

    global _FERNETS
    if _FERNETS is None:
        materials: list[str] = []
        enc_keys = getattr(settings, "TOTP_ENC_KEYS", None) or []
        for k in enc_keys:
            if k and isinstance(k, str):
                materials.append(k)
        materials.append(settings.SECRET_KEY)
        _FERNETS = [Fernet(_derive_fernet_key(m)) for m in materials]
    return _FERNETS


def encrypt_str(s: str) -> str:
    """对字符串进行对称加密。"""
    return _fernets()[0].encrypt(s.encode()).decode()


def decrypt_str(token: str) -> str:
    """解密 ``encrypt_str`` 生成的密文。"""
    last_exc = None
    for f in _fernets():
        try:
            return f.decrypt(token.encode()).decode()
        except Exception as exc:
            last_exc = exc
    if last_exc:
        raise last_exc
    raise ValueError("invalid token")


def parse_otpauth(uri: str):
    """解析 ``otpauth://`` 格式的 URI，返回标签和密钥。"""
    if not uri.lower().startswith("otpauth://totp/"):
        return "", ""
    u = urlparse(uri)
    label = unquote((u.path or "").lstrip("/"))
    secret = parse_qs(u.query).get("secret", [""])[0]
    return label, secret


def _b32_clean(s: str) -> str:
    """去除 Base32 字符串中无效字符。"""
    return "".join(c for c in s if c.isalnum()).upper()


def normalize_google_secret(secret: str) -> str:
    """清理并校验 Google 身份验证器使用的 Base32 密钥。

    返回清理后的密钥；若密钥无效则返回空字符串。
    """
    s = _b32_clean(secret)
    if len(s) < 16 or any(c not in _B32_ALPHABET for c in s):
        return ""
    try:
        # Base32 要求长度为 8 的倍数，不足时补齐填充后检测其合法性
        base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8), casefold=True)
    except Exception:
        return ""
    return s


def totp_code_base32(
    secret_b32: str,
    digits: int = 6,
    period: int = 30,
    timestamp: int | float | None = None,
):
    """根据 Base32 密钥计算当前 TOTP 码及剩余时间。

    可选的 ``timestamp`` 参数允许复用同一时间点，用于批量计算时减少重复的
    ``time.time()`` 调用并保持返回值在一个周期内一致。
    """
    s = _b32_clean(secret_b32)
    key = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8), casefold=True)
    if timestamp is None:
        t = int(time.time())
    else:
        t = int(timestamp)
    counter = t // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % (10 ** digits)
    code = str(code_int).zfill(digits)
    remaining = period - (t % period)
    return code, remaining
