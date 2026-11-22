"""Adapter endpoints. Include them with ``path("nine/", include("nine_django.adapter.urls"))``
and set the adapter URL in the console to ``https://your-app.com/nine``."""

from django.urls import path

from . import views

app_name = "nine_adapter"

urlpatterns = [
    path("authenticate", views.adapter, name="authenticate"),
    path("user", views.adapter, name="user"),
    path("event", views.adapter, name="event"),
]
