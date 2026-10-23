from django.http import JsonResponse
from django.urls import path


def ping(request):
    return JsonResponse({"ok": True})


urlpatterns = [path("ping/", ping)]
