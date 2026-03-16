from django.conf import settings


def client_ip(request) -> str:
    if getattr(settings, "TRUST_X_FORWARDED_FOR", False):
        forward = request.META.get("HTTP_X_FORWARDED_FOR")
        if forward:
            return forward.split(",")[0].strip() or "unknown"
    return request.META.get("REMOTE_ADDR") or "unknown"

