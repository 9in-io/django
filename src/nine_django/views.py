"""``/nine/login``, ``/nine/signup``, ``/nine/callback``, ``/nine/logout`` and ``/nine/webhook``."""

from __future__ import annotations

import logging
from typing import Any

import nine
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_variables
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from . import session as nine_session
from .conf import nine_settings
from .signals import user_signed_in
from .webhooks import IN_PROGRESS, process_event, verify_request

__all__ = ["login", "signup", "callback", "logout", "webhook", "start_login"]

logger = logging.getLogger("nine_django")


def _public(view: Any) -> Any:
    """Exempt from Django 5.1+'s LoginRequiredMiddleware: these views are how users sign in."""
    view.login_required = False
    return view


def _error(request: HttpRequest, error: str, description: str | None, status: int) -> HttpResponse:
    """The error page (template ``nine_django/error.html``; override it in your templates)."""
    context = {
        "error": error,
        "description": description or "",
        "status": status,
        "login_url": _login_path(request),
        "home_url": "/",
    }
    try:
        content = render_to_string("nine_django/error.html", context, request=request)
    except TemplateDoesNotExist:
        return HttpResponse(f"Sign-in failed: {error}", status=status, content_type="text/plain; charset=utf-8")
    return HttpResponse(content, status=status)


def _login_path(request: HttpRequest) -> str:
    from django.urls import NoReverseMatch, reverse

    try:
        return reverse(nine_session._namespaced(request, "login"))
    except NoReverseMatch:
        return "/"


def _query_str(request: HttpRequest, name: str, max_length: int = 2048) -> str | None:
    value = request.GET.get(name)
    if not isinstance(value, str) or not value or len(value) > max_length:
        return None
    return value


def start_login(
    request: HttpRequest,
    return_to: str | None = None,
    *,
    screen: str | None = None,
    login_hint: str | None = None,
    prompt: str | None = None,
) -> HttpResponseRedirect:
    """Redirects to 9in's hosted sign-in page (``screen="signup"`` for the sign-up form).

    ``return_to`` is where ``/nine/callback`` sends the user afterwards; only paths on this
    site are kept. Use it from your own views, e.g. to start a sign-in with a login hint.
    """
    from .services import get_web_app_auth

    login = get_web_app_auth().create_login(
        return_to=nine_session.safe_return_to(return_to, request),
        screen=screen,
        prompt=prompt,
        login_hint=login_hint,
        redirect_uri=nine_session.callback_url(request),
        locale=nine_session.ui_locale(),
    )
    nine_session.remember_pending(request, login)
    return HttpResponseRedirect(login.url)


def _login(request: HttpRequest, screen: str | None) -> HttpResponse:
    return_to = _query_str(request, "return_to") or _query_str(request, "next")
    if _query_str(request, "screen") == "signup":
        screen = "signup"
    try:
        return start_login(request, return_to, screen=screen, login_hint=_query_str(request, "login_hint", 320))
    except nine.NineError as error:
        logger.error("Could not start a 9in sign-in: %s", error)
        return _error(request, error.error, "Sign-in is unavailable right now. Please try again in a moment.", 503)


@_public
@never_cache
@require_GET
def login(request: HttpRequest) -> HttpResponse:
    """``GET /nine/login?return_to=/path`` (or ``next=``): starts a sign-in.

    Set ``LOGIN_URL = "nine:login"`` and ``@login_required`` sends signed-out users here.
    ``login_hint`` pre-fills the identifier; ``screen=signup`` opens the sign-up form.
    """
    return _login(request, None)


@_public
@never_cache
@require_GET
def signup(request: HttpRequest) -> HttpResponse:
    """``GET /nine/signup?return_to=/path``: starts a sign-in on the sign-up form."""
    return _login(request, "signup")


@_public
@never_cache
@require_GET
@sensitive_variables("tokens", "pending")
def callback(request: HttpRequest) -> HttpResponse:
    """``GET /nine/callback``: completes the sign-in and signs the local user in.

    Checks ``state`` (single use), ``iss``, PKCE and the ID token through
    :class:`nine.WebAppAuth`, finds or creates the local user (``NineBackend``), cycles the
    session key, logs the user in with ``django.contrib.auth.login`` and keeps the 9in tokens
    in the session.
    """
    from .services import get_web_app_auth

    pending = nine_session.take_pending(request, request.GET.get("state"))
    try:
        tokens = get_web_app_auth().handle_callback(request.GET, pending)
    except nine.NineError as error:
        logger.info("9in sign-in failed: %s", error)
        if error.error == "invalid_state":
            return _error(request, "invalid_state", "This sign-in expired or was already used. Please try again.", 400)
        status = error.status if error.status and 400 <= error.status < 500 else 400
        return _error(request, error.error, error.description, status)

    user = authenticate(request, nine_claims=tokens.claims)
    if user is None:
        _revoke_quietly(tokens)
        return _error(request, "access_denied", "Your account cannot sign in to this site.", 403)

    request.session.cycle_key()
    auth_login(request, user)
    nine_session.store_tokens(request, tokens)
    user_signed_in.send(
        sender=user.__class__,
        request=request,
        user=user,
        claims=dict(tokens.claims),
        tokens=tokens,
        created=bool(getattr(user, "_nine_created", False)),
    )
    destination = nine_session.safe_return_to(tokens.return_to, request) or nine_settings.login_redirect_url
    return HttpResponseRedirect(destination)


@sensitive_variables("tokens")
def _revoke_quietly(tokens: nine.TokenSet | None) -> None:
    if tokens is None or not tokens.refresh_token:
        return
    from .services import get_web_app_auth

    try:
        get_web_app_auth().revoke(tokens.refresh_token, "refresh_token")
    except Exception as error:  # best effort: the 9in logout ends the session anyway
        logger.info("Could not revoke the 9in refresh token: %s", error)


@_public
@never_cache
@require_http_methods(["GET", "POST"])
@sensitive_variables("tokens")
def logout(request: HttpRequest) -> HttpResponse:
    """``GET|POST /nine/logout?return_to=/path``: signs out here and at 9in.

    Revokes the refresh token, ends the Django session (``django.contrib.auth.logout``) and
    redirects to 9in's end-session endpoint, which comes back to ``return_to`` (a path on this
    site) or ``LOGOUT_REDIRECT_URL``. Register that URL as a logout URL of the application.
    """
    from django.contrib.auth import logout as auth_logout
    from django.core.exceptions import ImproperlyConfigured

    from .services import get_web_app_auth

    tokens = nine_session.session_tokens(request)
    raw_return_to = request.POST.get("return_to") or request.GET.get("return_to") or request.GET.get("next")
    destination = nine_session.safe_return_to(raw_return_to, request) or nine_settings.logout_redirect_url
    auth_logout(request)
    _revoke_quietly(tokens)
    try:
        url = get_web_app_auth().logout_url(
            id_token_hint=tokens.id_token if tokens is not None else None,
            post_logout_redirect_uri=nine_session.absolute_url(request, destination),
        )
    except (ImproperlyConfigured, nine.NineError) as error:
        logger.warning("No 9in logout URL (%s): signed out locally only", error)
        url = destination
    return HttpResponseRedirect(url)


@_public
@csrf_exempt
@require_POST
def webhook(request: HttpRequest) -> HttpResponse:
    """``POST /nine/webhook``: verified 9in webhooks, sent as Django signals once per event.

    - First delivery: receivers run, then 204. A receiver exception gives 500, the event id
      is released and 9in delivers it again later.
    - A retry or redelivery of a processed event: 204 without sending the signals again.
    - The same event still being processed by another request: 409, 9in retries later.

    Answer quickly: do slow work in a task queue from your receivers.
    """
    try:
        event = verify_request(request)
    except nine.NineError as error:
        status = error.status or 400
        if status >= 500:
            logger.error("9in webhook refused: %s", error)
        return JsonResponse({"error": error.error}, status=status)
    if process_event(event) == IN_PROGRESS:
        return JsonResponse({"error": "in_progress"}, status=409)
    return HttpResponse(status=204)
