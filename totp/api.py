from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.cache import never_cache

from .models import TOTPEntry
from .utils import decrypt_str, totp_code_base32


@login_required
@never_cache
def api_tokens(request):
    """返回所有 TOTP 条目的当前验证码。"""
    items = []
    period = 30
    # 与前端倒计时保持一致：计算距离 30 秒周期结束的剩余秒数
    timestamp = int(timezone.now().timestamp())
    remaining = period - (timestamp % period)

    queryset = TOTPEntry.objects.for_user(request.user).only("id", "secret_encrypted")

    ids_raw = (request.GET.get("ids") or "").strip()
    cache_key = None
    if ids_raw:
        ids: list[int] = []
        seen = set()
        for part in ids_raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                value = int(part)
            except ValueError:
                continue
            if value <= 0 or value in seen:
                continue
            ids.append(value)
            seen.add(value)
        if ids:
            queryset = queryset.filter(id__in=ids)
            cache_key = f"totp:api_tokens:v2:{request.user.id}:{timestamp}:{','.join(str(i) for i in ids)}"
        else:
            return JsonResponse({"remaining": remaining, "items": []})
    else:
        cache_key = f"totp:api_tokens:v2:{request.user.id}:{timestamp}:all"

    cached = cache.get(cache_key) if cache_key else None
    if cached is not None:
        response = JsonResponse(cached)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response

    for entry in queryset.iterator(chunk_size=200):
        secret = decrypt_str(entry.secret_encrypted)
        code, item_remaining = totp_code_base32(
            secret,
            digits=6,
            period=period,
            timestamp=timestamp,
        )
        items.append(
            {
                "id": entry.id,
                "code": code,
                "period": period,
                "remaining": item_remaining,
            }
        )

    payload = {"remaining": remaining, "items": items}
    if cache_key:
        cache.set(cache_key, payload, 2)
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response
