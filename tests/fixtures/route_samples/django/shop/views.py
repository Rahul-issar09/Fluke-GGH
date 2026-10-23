from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_GET, require_http_methods

from .models import Order


@require_GET
def order_list(request):
    return JsonResponse({"orders": list(Order.objects.values("id"))})


@require_http_methods(["GET", "DELETE"])
def order_detail(request, order_id):
    order = Order.objects.get(id=order_id)  # no owner check
    return JsonResponse({"id": order.id, "total": order.total})


def invoice(request, number):
    return JsonResponse({"number": number})


class ProfileView(View):
    def get(self, request):
        return JsonResponse({"user": request.user.username})

    def post(self, request):
        return JsonResponse({"saved": True})
