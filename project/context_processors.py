from django.conf import settings


def csp_nonce(request):
    if not getattr(settings, "CSP_ENABLED", False):
        return {"csp_nonce": ""}
    return {"csp_nonce": getattr(request, "csp_nonce", "")}

