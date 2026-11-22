import json
import logging

from django.contrib.auth.decorators import login_required
from django.dispatch import receiver
from django.http import JsonResponse
from django.shortcuts import render

from nine_django import verify_access_token
from nine_django.decorators import require_token
from nine_django.signals import event_received, user_signed_in

logger = logging.getLogger("demo")


def home(request):
    return render(request, "home.html")


@login_required
def account(request):
    token = request.nine.access_token()  # refreshed (and rotated) when it is about to expire
    return render(
        request,
        "account.html",
        {
            "claims": json.dumps(request.nine.claims, indent=2, sort_keys=True),
            "token_claims": json.dumps(verify_access_token(token), indent=2, sort_keys=True) if token else None,
            "identities": request.user.nine_identities.all(),
        },
    )


@require_token
def api_me(request):
    """An API endpoint: send `Authorization: Bearer <access token>`."""
    return JsonResponse({"sub": request.nine.sub, "user": str(request.user), "scope": request.nine.claims.get("scope")})


@receiver(user_signed_in)
def signed_in(sender, user, claims, created, **kwargs):
    logger.info("%s signed in with 9in (%s)", user.get_username(), "new user" if created else "returning")


@receiver(event_received)
def webhook(sender, event_type, event, **kwargs):
    logger.info("9in event %s (%s)", event_type, event["id"])
