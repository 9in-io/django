"""The 9in SDK objects this app uses, built from the settings once and shared.

They are rebuilt when ``settings.NINE`` or ``CACHES`` change (``override_settings``), or after
:func:`reset`.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar

import nine
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from .cache import DjangoCache
from .conf import nine_settings

__all__ = [
    "get_cache",
    "get_http_client",
    "get_web_app_auth",
    "get_token_verifier",
    "get_management_client",
    "get_adapter",
    "get_adapter_handler",
    "reset",
]

T = TypeVar("T")

_lock = threading.RLock()
_instances: dict[Any, Any] = {}


def reset(**_: Any) -> None:
    """Forgets the shared objects; the next use builds them from the current settings."""
    with _lock:
        _instances.clear()


def _shared(key: Any, build: Callable[[], T]) -> T:
    with _lock:
        if key not in _instances:
            _instances[key] = build()
        return _instances[key]


def _load(value: Any) -> Any:
    """A setting naming an object: the object itself, or its dotted path."""
    return import_string(value) if isinstance(value, str) else value


def get_cache() -> DjangoCache:
    """The configured Django cache (``NINE["CACHE"]``) as a :class:`nine.Cache`."""
    alias = str(nine_settings.CACHE or "default")
    return _shared(("cache", alias), lambda: DjangoCache(alias))


def get_http_client() -> Any:
    """``NINE["HTTP_CLIENT"]`` (an instance, or the dotted path of a class or factory), or None for the SDK default."""

    def build() -> Any:
        value = nine_settings.HTTP_CLIENT
        if value is None:
            return None
        if isinstance(value, str):
            value = import_string(value)
            return value() if callable(value) else value
        return value() if isinstance(value, type) else value

    return _shared("http", build)


def _issuer() -> str:
    issuer = nine_settings.ISSUER
    if not issuer:
        raise ImproperlyConfigured("9in is not configured: set NINE_ISSUER (or NINE['ISSUER']).")
    return str(issuer)


def get_web_app_auth() -> nine.WebAppAuth:
    """The sign-in client (:class:`nine.WebAppAuth`) for this app's application.

    The views pass the redirect URI to each sign-in (it is kept in the pending login), so it
    can be built from the request when ``NINE["REDIRECT_URI"]`` is a path or unset.
    """

    def build() -> nine.WebAppAuth:
        issuer = _issuer()
        client_id = nine_settings.CLIENT_ID
        if not client_id:
            raise ImproperlyConfigured("9in sign-in needs NINE_CLIENT_ID (or NINE['CLIENT_ID']).")
        configured = nine_settings.REDIRECT_URI
        return nine.WebAppAuth(
            issuer,
            str(client_id),
            client_secret=nine_settings.CLIENT_SECRET or None,
            redirect_uri=str(configured) if configured and "://" in str(configured) else None,
            scopes=tuple(nine_settings.SCOPES),
            audience=nine_settings.AUDIENCE or None,
            http=get_http_client(),
            cache=get_cache(),
            allow_insecure_issuer=bool(nine_settings.ALLOW_INSECURE_ISSUER),
        )

    return _shared("web", build)


def get_token_verifier() -> nine.HybridTokenVerifier:
    """The verifier for bearer tokens on your API (:class:`nine.HybridTokenVerifier`).

    Hybrid (revocation-aware) by default when client credentials are configured, local
    otherwise; ``NINE["TOKEN_VERIFICATION"]`` chooses explicitly.
    """

    def build() -> nine.HybridTokenVerifier:
        client_id, client_secret = nine_settings.management_credentials
        mode = nine_settings.TOKEN_VERIFICATION or None
        if mode is not None and mode not in ("local", "hybrid", "introspect"):
            raise ImproperlyConfigured("NINE['TOKEN_VERIFICATION'] must be 'local', 'hybrid' or 'introspect'.")
        return nine.HybridTokenVerifier(
            _issuer(),
            audience=nine_settings.api_audience,
            client_id=client_id,
            client_secret=client_secret,
            mode=mode,
            cache=get_cache(),
            cache_ttl=int(nine_settings.TOKEN_CACHE_TTL),
            secret=nine_settings.API_SECRET or None,
            http=get_http_client(),
            leeway=int(nine_settings.TOKEN_LEEWAY),
            allow_insecure_issuer=bool(nine_settings.ALLOW_INSECURE_ISSUER),
        )

    return _shared("verifier", build)


def get_management_client() -> nine.ManagementClient:
    """The Management API client (:class:`nine.ManagementClient`).

    Uses ``NINE_MANAGEMENT_CLIENT_ID`` / ``NINE_MANAGEMENT_CLIENT_SECRET`` when set, else the
    application's own client ID and secret. The application needs management scopes.
    """

    def build() -> nine.ManagementClient:
        client_id, client_secret = nine_settings.management_credentials
        if not client_id or not client_secret:
            raise ImproperlyConfigured(
                "The 9in Management API needs a confidential application: set NINE_CLIENT_ID and "
                "NINE_CLIENT_SECRET (or NINE_MANAGEMENT_CLIENT_ID and NINE_MANAGEMENT_CLIENT_SECRET)."
            )
        return nine.ManagementClient(
            _issuer(),
            client_id,
            client_secret,
            http=get_http_client(),
            cache=get_cache(),
            allow_insecure_issuer=bool(nine_settings.ALLOW_INSECURE_ISSUER),
        )

    return _shared("management", build)


def get_adapter() -> Any:
    """The adapter answering 9in's ``/authenticate``, ``/user`` and ``/event`` (``NINE["ADAPTER"]``)."""

    def build() -> Any:
        value = _load(nine_settings.ADAPTER)
        return value() if isinstance(value, type) else value

    return _shared("adapter", build)


def get_adapter_handler() -> nine.AdapterHandler:
    """The SDK's :class:`nine.AdapterHandler` over :func:`get_adapter`, with the adapter secret(s)."""

    def build() -> nine.AdapterHandler:
        secrets = nine_settings.adapter_secrets
        if not secrets:
            raise ImproperlyConfigured("The 9in adapter endpoints need NINE_ADAPTER_SECRET (or NINE['ADAPTER_SECRET']).")
        return nine.AdapterHandler(
            secrets if len(secrets) > 1 else secrets[0],
            get_adapter(),
            tolerance=int(nine_settings.ADAPTER_TOLERANCE),
        )

    return _shared("adapter_handler", build)
