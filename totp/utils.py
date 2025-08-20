import base64, hashlib, hmac, struct, time
from urllib.parse import urlparse, parse_qs, unquote
from cryptography.fernet import Fernet
from django.conf import settings

_FERNET = None


def _fernet():
    """返回基于 ``SECRET_KEY`` 生成的缓存 ``Fernet`` 实例。"""

    global _FERNET
    if _FERNET is None:
        # 直接使用 SECRET_KEY 的哈希作为对称加密密钥
        digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(digest[:32])
        _FERNET = Fernet(key)
    return _FERNET


def encrypt_str(s: str) -> str:
    """对字符串进行对称加密。"""
    return _fernet().encrypt(s.encode()).decode()


def decrypt_str(token: str) -> str:
    """解密 ``encrypt_str`` 生成的密文。"""
    return _fernet().decrypt(token.encode()).decode()


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


def totp_code_base32(secret_b32: str, digits: int = 6, period: int = 30):
    """根据 Base32 密钥计算当前 TOTP 码及剩余时间。"""
    s = _b32_clean(secret_b32)
    key = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8), casefold=True)
    t = int(time.time())
    counter = t // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % (10 ** digits)
    code = str(code_int).zfill(digits)
    remaining = period - (t % period)
    return code, remaining
