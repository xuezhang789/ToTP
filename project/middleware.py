import secrets

from django.conf import settings


class CSPNonceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(settings, "CSP_ENABLED", False):
            request.csp_nonce = secrets.token_urlsafe(16)
        response = self.get_response(request)
        nonce = getattr(request, "csp_nonce", "")
        if getattr(settings, "CSP_ENABLED", False) and nonce:
            parts = [
                "default-src 'self'",
                f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://accounts.google.com https://ssl.gstatic.com",
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
                "img-src 'self' data:",
                "font-src 'self' https://cdn.jsdelivr.net data:",
                "connect-src 'self' https://accounts.google.com",
                "frame-src 'self' https://accounts.google.com",
                "base-uri 'self'",
                "form-action 'self'",
                "object-src 'none'",
                "frame-ancestors 'none'",
            ]
            header_value = "; ".join(parts)
            if getattr(settings, "CSP_REPORT_ONLY", False):
                response["Content-Security-Policy-Report-Only"] = header_value
            else:
                response["Content-Security-Policy"] = header_value
        return response
