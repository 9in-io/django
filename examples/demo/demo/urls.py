import os
from urllib.parse import urlsplit

from django.contrib import admin
from django.urls import include, path

from nine_django import views as nine_views

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("account", views.account, name="account"),
    path("api/me", views.api_me, name="api-me"),
    path("nine/", include("nine_django.urls")),  # /nine/login, /signup, /callback, /logout, /webhook
    path("admin/", admin.site.urls),
]

# Registered another callback URL than /nine/callback? Serve the callback view there too.
callback_path = urlsplit(os.environ.get("NINE_REDIRECT_URI", "")).path.strip("/")
if callback_path and callback_path != "nine/callback":
    urlpatterns.append(path(callback_path, nine_views.callback))
