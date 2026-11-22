"""System checks (``manage.py check``) for common setup mistakes."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register
from django.utils.module_loading import import_string

from .conf import nine_settings

_AUTH_MIDDLEWARE = "django.contrib.auth.middleware.AuthenticationMiddleware"
_SESSION_MIDDLEWARE = "django.contrib.sessions.middleware.SessionMiddleware"
_NINE_MIDDLEWARE = "nine_django.middleware.NineMiddleware"


def _is_subclass(path: str, base: type) -> bool:
    try:
        cls = import_string(path)
    except ImportError:
        return False
    return isinstance(cls, type) and issubclass(cls, base)


@register(Tags.security, Tags.compatibility)
def check_settings(app_configs: Any = None, **kwargs: Any) -> list[Any]:
    from .backends import NineBackend
    from .middleware import NineMiddleware

    messages: list[Any] = []
    issuer = nine_settings.ISSUER
    client_id = nine_settings.CLIENT_ID
    sign_in = bool(issuer and client_id)

    if client_id and not issuer:
        messages.append(
            Error(
                "NINE_CLIENT_ID is set but NINE_ISSUER is not.",
                hint="Set NINE_ISSUER to your tenant, e.g. https://acme.9in.io.",
                id="nine_django.E001",
            )
        )

    if issuer:
        try:
            import nine

            nine.normalize_issuer(str(issuer), bool(nine_settings.ALLOW_INSECURE_ISSUER))
        except Exception as error:  # nine.NineError: insecure_issuer, invalid_issuer
            messages.append(
                Error(
                    f"NINE_ISSUER is not usable: {error}",
                    hint="Issuers must use https (http only for localhost). Set NINE_ALLOW_INSECURE_ISSUER=true for other development hosts.",
                    id="nine_django.E002",
                )
            )

    if sign_in:
        backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
        if not any(_is_subclass(path, NineBackend) for path in backends):
            messages.append(
                Error(
                    "nine_django.backends.NineBackend is not in AUTHENTICATION_BACKENDS.",
                    hint='Add "nine_django.backends.NineBackend" so 9in sign-ins become Django logins.',
                    id="nine_django.E003",
                )
            )
        scopes = list(nine_settings.SCOPES or [])
        if "openid" not in scopes:
            messages.append(Error('NINE["SCOPES"] must include "openid".', id="nine_django.E005"))

    middleware = list(getattr(settings, "MIDDLEWARE", None) or [])
    nine_index = next((i for i, path in enumerate(middleware) if _is_subclass(path, NineMiddleware)), None)
    if nine_index is not None:
        auth_index = next((i for i, path in enumerate(middleware) if path == _AUTH_MIDDLEWARE), None)
        if auth_index is None or auth_index > nine_index:
            messages.append(
                Error(
                    "NineMiddleware must come after AuthenticationMiddleware.",
                    hint=f'Put "{_NINE_MIDDLEWARE}" after "{_AUTH_MIDDLEWARE}" in MIDDLEWARE.',
                    id="nine_django.E004",
                )
            )
    elif sign_in:
        messages.append(
            Warning(
                "NineMiddleware is not in MIDDLEWARE: 9in tokens are not refreshed and request.nine is not set.",
                hint=f'Add "{_NINE_MIDDLEWARE}" after "{_AUTH_MIDDLEWARE}".',
                id="nine_django.W001",
            )
        )

    if sign_in and getattr(settings, "SESSION_ENGINE", "") == "django.contrib.sessions.backends.signed_cookies":
        messages.append(
            Warning(
                "Signed-cookie sessions are readable by the browser, and the 9in tokens are kept in the session.",
                hint="Use database, cache or cached_db sessions.",
                id="nine_django.W002",
            )
        )

    try:
        from django.core.cache import caches

        backend = caches[str(nine_settings.CACHE or "default")]
        if type(backend).__name__ == "DummyCache":
            messages.append(
                Warning(
                    f'The cache "{nine_settings.CACHE}" is a DummyCache: signing keys are fetched on every request and webhooks are not de-duplicated.',
                    hint='Set NINE["CACHE"] to a real cache (Redis, Memcached or the database cache when you run several processes).',
                    id="nine_django.W003",
                )
            )
    except Exception as error:
        messages.append(Error(f'The cache "{nine_settings.CACHE}" for 9in is not configured: {error}', id="nine_django.E006"))

    return messages
