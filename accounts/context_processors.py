from django.conf import settings

"""在模板上下文中提供 Google 客户端 ID。"""


def google_client_id(request):
    return {"GOOGLE_CLIENT_ID": getattr(settings, "GOOGLE_CLIENT_ID", "")}
