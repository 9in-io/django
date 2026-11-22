"""Sign-in state in the Django session, and ``request.nine``."""

from __future__ import annotations

import dataclasses
import hmac
import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import nine
from django.http import HttpRequest
from django.urls import NoReverseMatch, reverse
from django.utils import translation
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.debug import sensitive_variables

from .conf import nine_settings

__all__ = [
    "PENDING_SESSION_KEY",
    "TOKENS_SESSION_KEY",
    "NineState",
    "safe_return_to",
    "callback_url",
    "session_tokens",
    "store_tokens",
    "fresh_tokens",
]

logger = logging.getLogger("nine_django")

#: Pending sign-ins (PKCE verifier, nonce, return_to), keyed by state; the latest few are kept.
PENDING_SESSION_KEY = "_nine_pending"
#: The signed-in user's 9in tokens (``TokenSet.to_dict()``).
TOKENS_SESSION_KEY = "_nine_tokens"
MAX_PENDING = 5


def safe_return_to(value: Any, request: HttpRequest) -> str | None:
    """``value`` when it is a path on this site (no open redirects), else None."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return None
    if "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    if not url_has_allowed_host_and_scheme(value, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return None
    return value


def _namespaced(request: HttpRequest, name: str) -> str:
    match = getattr(request, "resolver_match", None)
    namespace = match.namespace if match is not None and match.namespace and "nine" in match.namespace else "nine"
    return f"{namespace}:{name}"


def callback_url(request: HttpRequest) -> str:
    """The absolute redirect URI: ``NINE["REDIRECT_URI"]``, or this app's ``/nine/callback``."""
    configured = nine_settings.REDIRECT_URI
    if configured:
        configured = str(configured)
        return configured if "://" in configured else request.build_absolute_uri(configured)
    try:
        path = reverse(_namespaced(request, "callback"))
    except NoReverseMatch:
        path = reverse("nine:callback")
    return request.build_absolute_uri(path)


def absolute_url(request: HttpRequest, url: str) -> str:
    return url if "://" in url else request.build_absolute_uri(url)


def ui_locale() -> str | None:
    locale = nine_settings.LOCALE
    if not locale:
        return None
    if locale == "auto":
        return translation.get_language() or None
    return str(locale)


def remember_pending(request: HttpRequest, login: nine.Login) -> None:
    """Keeps a pending sign-in in the session, keyed by its state (several tabs may sign in at once)."""
    state = (parse_qs(urlsplit(login.url).query).get("state") or [""])[0]
    pending = dict(request.session.get(PENDING_SESSION_KEY) or {})
    pending.pop(state, None)
    pending[state] = dict(login.pending)
    while len(pending) > MAX_PENDING:
        pending.pop(next(iter(pending)))
    request.session[PENDING_SESSION_KEY] = pending


@sensitive_variables("pending", "found")
def take_pending(request: HttpRequest, state: str | None) -> dict[str, Any] | None:
    """Removes and returns the pending sign-in for ``state`` (single use; constant-time compare)."""
    pending = dict(request.session.get(PENDING_SESSION_KEY) or {})
    found = None
    given = (state or "").encode()
    for key in list(pending):
        if given and hmac.compare_digest(key.encode(), given):
            found = pending.pop(key)
    if found is not None:
        request.session[PENDING_SESSION_KEY] = pending
    return found if isinstance(found, dict) else None


def session_tokens(request: HttpRequest) -> nine.TokenSet | None:
    """The 9in tokens kept in the session (as they are; see :func:`fresh_tokens`)."""
    session = getattr(request, "session", None)
    stored = session.get(TOKENS_SESSION_KEY) if session is not None else None
    if not isinstance(stored, Mapping):
        return None
    try:
        return nine.TokenSet.from_dict(stored)
    except Exception:
        logger.warning("Dropping unreadable 9in tokens from the session")
        session.pop(TOKENS_SESSION_KEY, None)
        return None


def store_tokens(request: HttpRequest, tokens: nine.TokenSet) -> None:
    request.session[TOKENS_SESSION_KEY] = tokens.to_dict()


def forget_tokens(request: HttpRequest) -> None:
    session = getattr(request, "session", None)
    if session is not None and TOKENS_SESSION_KEY in session:
        del session[TOKENS_SESSION_KEY]


def sign_out_locally(request: HttpRequest) -> None:
    """Ends the Django session (``django.contrib.auth.logout``), e.g. after 9in revoked the refresh token."""
    from django.contrib.auth import logout

    logout(request)


@sensitive_variables("tokens", "refreshed")
def fresh_tokens(request: HttpRequest, *, leeway: int | None = None, raise_errors: bool = False) -> nine.TokenSet | None:
    """The session's tokens, refreshed (and rotated) when the access token is about to expire.

    - Refreshed tokens are saved in the session (9in rotates refresh tokens: the new one must
      replace the old one).
    - When 9in refuses the refresh token (``invalid_grant``: revoked, the session ended, the
      user was blocked or deleted), the user is signed out of Django and None is returned.
    - Without a refresh token, the tokens are returned until the access token expires.
    - Other failures (9in unreachable) keep the session; they are logged, or raised with
      ``raise_errors``.
    """
    tokens = session_tokens(request)
    if tokens is None:
        return None
    if leeway is None:
        leeway = int(nine_settings.REFRESH_LEEWAY)
    if not tokens.expired(leeway):
        return tokens
    if not tokens.refresh_token:
        return None if tokens.expired(0) else tokens
    from .services import get_web_app_auth

    try:
        refreshed = get_web_app_auth().refresh(tokens)
    except nine.NineError as error:
        if error.error == "invalid_grant":
            logger.info("9in refused the refresh token (%s): signing the user out", error.description or error.error)
            sign_out_locally(request)
            return None
        logger.warning("Could not refresh the 9in tokens: %s", error)
        if raise_errors:
            raise
        return None if tokens.expired(0) else tokens
    if not refreshed.id_token and tokens.id_token:
        # No new ID token in the refresh response: keep the claims of the sign-in.
        refreshed = dataclasses.replace(refreshed, id_token=tokens.id_token, claims=dict(tokens.claims))
    if refreshed.return_to is not None:
        refreshed = dataclasses.replace(refreshed, return_to=None)
    store_tokens(request, refreshed)
    return refreshed


class NineState:
    """``request.nine``: how 9in authenticated this request.

    - ``source``: ``"session"`` (signed in through ``/nine/callback``), ``"bearer"`` (an
      access token checked by ``require_token`` or ``NineTokenAuthentication``) or None.
    - ``claims``: the ID token claims for sessions, the access token claims for bearer
      tokens, ``{}`` otherwise.
    - ``access_token()``: a valid access token for calling your API or 9in (refreshed when
      needed for sessions), or None.
    """

    def __init__(self, request: HttpRequest) -> None:
        self._request = request
        self._bearer: str | None = None
        self._bearer_claims: dict[str, Any] | None = None

    def use_bearer(self, token: str, claims: Mapping[str, Any]) -> None:
        self._bearer = token
        self._bearer_claims = dict(claims)

    @property
    def tokens(self) -> nine.TokenSet | None:
        """The session's :class:`nine.TokenSet` (None for bearer requests and signed-out users)."""
        return None if self._bearer is not None else session_tokens(self._request)

    @property
    def source(self) -> str | None:
        if self._bearer is not None:
            return "bearer"
        return "session" if self.tokens is not None else None

    @property
    def claims(self) -> dict[str, Any]:
        if self._bearer_claims is not None:
            return self._bearer_claims
        tokens = self.tokens
        return dict(tokens.claims) if tokens is not None else {}

    @property
    def sub(self) -> str | None:
        """The 9in user id (or the client id of a machine-to-machine token)."""
        sub = self.claims.get("sub")
        return str(sub) if sub else None

    @property
    def is_authenticated(self) -> bool:
        return self.source is not None

    @property
    def scopes(self) -> set[str]:
        """Scopes granted to the access token (bearer requests, or the session's tokens)."""
        if self._bearer_claims is not None:
            scope = self._bearer_claims.get("scope")
        else:
            tokens = self.tokens
            scope = tokens.scope if tokens is not None else None
        return set(str(scope or "").split())

    def has_scope(self, *scopes: str) -> bool:
        return set(scopes) <= self.scopes

    def access_token(self) -> str | None:
        """A valid access token, refreshing the session's tokens when they are about to expire."""
        if self._bearer is not None:
            return self._bearer
        tokens = fresh_tokens(self._request, raise_errors=True)
        return tokens.access_token if tokens is not None else None

    def __repr__(self) -> str:
        return f"<NineState source={self.source!r} sub={self.sub!r}>"


def nine_state(request: HttpRequest) -> NineState:
    """``request.nine``, creating it when the middleware did not run."""
    state = getattr(request, "nine", None)
    if not isinstance(state, NineState):
        state = NineState(request)
        request.nine = state  # type: ignore[attr-defined]
    return state
