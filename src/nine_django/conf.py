"""Settings of 9in for Django.

Every setting is read, in this order, from the ``NINE`` dict in your Django settings, from the
``NINE_<NAME>`` environment variable, and from the default below::

    NINE = {
        "ISSUER": "https://acme.9in.io",       # else NINE_ISSUER
        "SCOPES": ["openid", "profile", "email", "offline_access", "orders:read"],
    }

Values are read when they are used, so ``override_settings(NINE={...})`` works in tests.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from django.conf import global_settings, settings

__all__ = ["nine_settings", "DEFAULTS", "ENVIRONMENT"]

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

#: Settings and their defaults (when neither ``NINE`` nor the environment sets them).
DEFAULTS: dict[str, Any] = {
    # The application registered for this site (Applications → Regular Web App).
    "ISSUER": None,
    "CLIENT_ID": None,
    "CLIENT_SECRET": None,
    # Absolute URL, or a path on this site; None: this app's /nine/callback.
    "REDIRECT_URI": None,
    "SCOPES": ("openid", "profile", "email", "offline_access"),
    # API identifier to request access tokens for (the `aud` of the user's access token).
    "AUDIENCE": None,
    # Language of the hosted pages (ui_locales): None follows the browser, "auto" uses the
    # active Django language, or a fixed tag such as "de".
    "LOCALE": None,
    # Plain http is accepted for localhost, *.localhost and loopback addresses only.
    "ALLOW_INSECURE_ISSUER": False,
    # Where /nine/callback goes without a return_to (None: LOGIN_REDIRECT_URL when you set
    # it, else "/") and where /nine/logout sends users after 9in (None: LOGOUT_REDIRECT_URL,
    # else "/"). Register the logout one as a logout URL of the application.
    "LOGIN_REDIRECT_URL": None,
    "LOGOUT_REDIRECT_URL": None,
    # Seconds before the access token expires when the middleware refreshes it.
    "REFRESH_LEEWAY": 60,
    # Local users (see nine_django.backends.NineBackend).
    "CREATE_USERS": True,
    "LINK_BY_EMAIL": True,
    "LINK_ADAPTER_USERS": None,  # None: when ADAPTER_SECRET is set
    "UPDATE_USERS": True,
    "USER_FIELDS": {"email": "email", "first_name": "given_name", "last_name": "family_name"},
    # Bearer tokens on your API (require_token, NineTokenAuthentication).
    "API_AUDIENCE": None,  # None: AUDIENCE
    "TOKEN_VERIFICATION": None,  # "local" | "hybrid" | "introspect"; None: hybrid with a client secret
    "API_SECRET": None,  # shared secret of an HS256/384/512 key in the key library
    "TOKEN_CACHE_TTL": 300,
    "TOKEN_LEEWAY": 30,
    # A separate machine-to-machine application for the Management API and introspection.
    "MANAGEMENT_CLIENT_ID": None,
    "MANAGEMENT_CLIENT_SECRET": None,
    # Webhooks at /nine/webhook.
    "WEBHOOK_SECRET": None,
    "WEBHOOK_SECRET_PREVIOUS": None,
    "WEBHOOK_TOLERANCE": 300,
    "WEBHOOK_DEDUPE": True,
    "WEBHOOK_DEDUPE_TTL": 3 * 24 * 3600,
    "WEBHOOK_PATH": None,  # the path 9in posts to, when a proxy rewrites it
    # Your own user database (nine_django.adapter.urls).
    "ADAPTER_SECRET": None,
    "ADAPTER_SECRET_PREVIOUS": None,
    "ADAPTER_TOLERANCE": 300,
    "ADAPTER": "nine_django.adapter.DjangoUserAdapter",
    "ADAPTER_IDENTIFIERS": ("email", "username", "phone"),
    "ADAPTER_FIELDS": {},
    "OTP_EMAIL": True,
    "OTP_FROM_EMAIL": None,  # None: DEFAULT_FROM_EMAIL
    # Cache alias for discovery, signing keys, token answers and webhook ids.
    "CACHE": "default",
    # A nine.HttpClient instance, or the dotted path of a class or factory (tests, proxies).
    "HTTP_CLIENT": None,
}

#: Settings that can come from the environment, and how to read them.
ENVIRONMENT: dict[str, str] = {
    "ISSUER": "str",
    "CLIENT_ID": "str",
    "CLIENT_SECRET": "str",
    "REDIRECT_URI": "str",
    "AUDIENCE": "str",
    "ALLOW_INSECURE_ISSUER": "bool",
    "LOGOUT_REDIRECT_URL": "str",
    "API_AUDIENCE": "str",
    "TOKEN_VERIFICATION": "str",
    "API_SECRET": "str",
    "TOKEN_CACHE_TTL": "int",
    "MANAGEMENT_CLIENT_ID": "str",
    "MANAGEMENT_CLIENT_SECRET": "str",
    "WEBHOOK_SECRET": "str",
    "WEBHOOK_SECRET_PREVIOUS": "str",
    "ADAPTER_SECRET": "str",
    "ADAPTER_SECRET_PREVIOUS": "str",
    "CACHE": "str",
}

# Environment variable names that differ from NINE_<setting>.
_ENV_NAMES = {"LOGOUT_REDIRECT_URL": "NINE_LOGOUT_REDIRECT_URI"}


def _from_env(name: str) -> Any:
    kind = ENVIRONMENT.get(name)
    if kind is None:
        return None
    raw = os.environ.get(_ENV_NAMES.get(name, "NINE_" + name))
    if raw is None or raw.strip() == "":
        return None
    raw = raw.strip()
    if kind == "bool":
        lowered = raw.lower()
        return True if lowered in _TRUE else False if lowered in _FALSE else None
    if kind == "int":
        try:
            return int(raw)
        except ValueError:
            return None
    return raw


class NineSettings:
    """Attribute access to the settings: ``nine_settings.ISSUER``."""

    def user_settings(self) -> Mapping[str, Any]:
        value = getattr(settings, "NINE", None) or {}
        if not isinstance(value, Mapping):
            from django.core.exceptions import ImproperlyConfigured

            raise ImproperlyConfigured("settings.NINE must be a dict.")
        return value

    def __getattr__(self, name: str) -> Any:
        if name not in DEFAULTS:
            raise AttributeError(f"Unknown 9in setting: {name}")
        user = self.user_settings()
        if name in user:
            return user[name]
        value = _from_env(name)
        if value is not None:
            return value
        return DEFAULTS[name]

    # Derived values -------------------------------------------------------------------

    @property
    def api_audience(self) -> str | None:
        return self.API_AUDIENCE or self.AUDIENCE or None

    @property
    def management_credentials(self) -> tuple[str | None, str | None]:
        """Client credentials for the Management API and introspection."""
        client_id = self.MANAGEMENT_CLIENT_ID or None
        client_secret = self.MANAGEMENT_CLIENT_SECRET or None
        if client_id and client_secret:
            return client_id, client_secret
        return self.CLIENT_ID or None, self.CLIENT_SECRET or None

    @property
    def webhook_secrets(self) -> list[str]:
        return _secrets(self.WEBHOOK_SECRET, self.WEBHOOK_SECRET_PREVIOUS)

    @property
    def adapter_secrets(self) -> list[str]:
        return _secrets(self.ADAPTER_SECRET, self.ADAPTER_SECRET_PREVIOUS)

    @property
    def login_redirect_url(self) -> str:
        if self.LOGIN_REDIRECT_URL:
            return _resolve_url(self.LOGIN_REDIRECT_URL)
        configured = getattr(settings, "LOGIN_REDIRECT_URL", None)
        if configured and configured != global_settings.LOGIN_REDIRECT_URL:
            return _resolve_url(configured)
        return "/"

    @property
    def logout_redirect_url(self) -> str:
        if self.LOGOUT_REDIRECT_URL:
            return _resolve_url(self.LOGOUT_REDIRECT_URL)
        configured = getattr(settings, "LOGOUT_REDIRECT_URL", None)
        return _resolve_url(configured) if configured else "/"

    @property
    def link_adapter_users(self) -> bool:
        value = self.LINK_ADAPTER_USERS
        return bool(self.adapter_secrets) if value is None else bool(value)


def _secrets(*values: Any) -> list[str]:
    """Secrets from settings: strings (comma-separated for several) or lists."""
    out: list[str] = []
    for value in values:
        if not value:
            continue
        items = value.split(",") if isinstance(value, str) else list(value)
        for item in items:
            item = str(item).strip()
            if item and item not in out:
                out.append(item)
    return out


def _resolve_url(value: Any) -> str:
    """A URL setting that may be a URL pattern name, like LOGIN_REDIRECT_URL."""
    from django.shortcuts import resolve_url

    return str(resolve_url(value))


nine_settings = NineSettings()
