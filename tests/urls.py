from django.contrib import admin
from django.urls import include, path

from tests.settings import HAS_DRF
from tests.testapp import views

urlpatterns = [
    path("nine/", include("nine_django.urls")),
    path("nine/", include("nine_django.adapter.urls")),
    path("dashboard", views.dashboard),
    path("whoami", views.whoami, name="whoami"),
    path("token", views.token),
    path("api/me", views.me),
    path("api/orders", views.orders),
    path("api/orders/write", views.write_orders),
    path("api/async-orders", views.async_orders),
    path("admin/", admin.site.urls),
]

if HAS_DRF:
    from tests.testapp import drf

    urlpatterns += [
        path("drf/me", drf.Me.as_view()),
        path("drf/orders", drf.Orders.as_view()),
        path("drf/scoped", drf.ScopedByAttribute.as_view()),
        path("drf/admin-or-scope", drf.AdminOrScope.as_view()),
        path("drf/scope-missing", drf.ScopeMissing.as_view()),
    ]
