from django.urls import path, re_path

from . import views
from .views import order_detail

urlpatterns = [
    path("orders/", views.order_list),
    path("orders/<int:order_id>/", order_detail),
    re_path(r"^invoices/(?P<number>[0-9]{6})/$", views.invoice),
    path("profile/", views.ProfileView.as_view()),
]
