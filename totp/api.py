from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import TOTPEntry
from .utils import decrypt_str, totp_code_base32

@login_required
def api_tokens(request):
    """返回所有 TOTP 条目的当前验证码。"""
    items = []
    # 与前端倒计时保持一致：计算距离 30 秒周期结束的剩余秒数
    remaining = 30 - (int(timezone.now().timestamp()) % 30)
    for eid, secret_enc in TOTPEntry.objects.filter(user=request.user).values_list(
            "id", "secret_encrypted"
    ):
        secret = decrypt_str(secret_enc)
        code, _ = totp_code_base32(secret, digits=6, period=30)
        items.append({"id": eid, "code": code, "period": 30})
    return JsonResponse({"remaining": remaining, "items": items})
