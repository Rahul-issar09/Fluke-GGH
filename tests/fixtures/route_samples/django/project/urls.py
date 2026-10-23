from django.urls import include, path

urlpatterns = [
    path("api/", include("shop.urls")),
    path("health/", include("shop.health_urls")),
]
