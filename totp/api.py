from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone

from .models import TOTPEntry
from .utils import decrypt_str, totp_code_base32

@login_required
def api_tokens(request):
    """返回所有 TOTP 条目的当前验证码。"""
    items = []
    period = 30
    # 与前端倒计时保持一致：计算距离 30 秒周期结束的剩余秒数
    timestamp = int(timezone.now().timestamp())
    remaining = period - (timestamp % period)

    queryset = TOTPEntry.objects.for_user(request.user).only("id", "secret_encrypted")

    ids_raw = (request.GET.get("ids") or "").strip()
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
        else:
            return JsonResponse({"remaining": remaining, "items": []})

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

    return JsonResponse({"remaining": remaining, "items": items})
