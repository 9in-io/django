"""Sign-in and webhook routes. Include them with ``path("nine/", include("nine_django.urls"))``:

==================  =========================  =============================================
``nine:login``      ``GET /nine/login``        Starts a sign-in (``?return_to=/path``)
``nine:signup``     ``GET /nine/signup``       Same, on the sign-up form
``nine:callback``   ``GET /nine/callback``     Completes it; register this redirect URL
``nine:logout``     ``GET|POST /nine/logout``  Signs out here and at 9in
``nine:webhook``    ``POST /nine/webhook``     Verified webhooks, sent as Django signals
==================  =========================  =============================================
"""

from django.urls import path

from . import views

app_name = "nine"

urlpatterns = [
    path("login", views.login, name="login"),
    path("signup", views.signup, name="signup"),
    path("callback", views.callback, name="callback"),
    path("logout", views.logout, name="logout"),
    path("webhook", views.webhook, name="webhook"),
]
