"""Official Django SDK for 9in: sign-in with local users, API tokens, webhooks and your own user database.

Built on the 9in Python SDK (``import nine``). The shared, configured SDK objects::

    from nine_django import get_management_client, get_token_verifier, get_web_app_auth
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "get_cache",
    "get_web_app_auth",
    "get_token_verifier",
    "get_management_client",
    "get_adapter",
    "verify_access_token",
]

if TYPE_CHECKING:
    import nine

    from .cache import DjangoCache


def get_cache() -> DjangoCache:
    """The Django cache 9in uses (``NINE["CACHE"]``), as a :class:`nine.Cache`."""
    from .services import get_cache as _get

    return _get()


def get_web_app_auth() -> nine.WebAppAuth:
    """The configured :class:`nine.WebAppAuth` (sign-in, refresh, revoke, userinfo, client credentials)."""
    from .services import get_web_app_auth as _get

    return _get()


def get_token_verifier() -> nine.HybridTokenVerifier:
    """The configured :class:`nine.HybridTokenVerifier` for bearer tokens on your API."""
    from .services import get_token_verifier as _get

    return _get()


def get_management_client() -> nine.ManagementClient:
    """The configured :class:`nine.ManagementClient` (users, sessions, login links)."""
    from .services import get_management_client as _get

    return _get()


def get_adapter() -> Any:
    """The configured adapter (``NINE["ADAPTER"]``, :class:`nine_django.adapter.DjangoUserAdapter` by default)."""
    from .services import get_adapter as _get

    return _get()


def verify_access_token(token: str | None, *, scope: Any = None, audience: Any = None) -> dict[str, Any]:
    """Verifies an access token (or an ``Authorization`` header value) with the configured verifier.

    Returns the claims; raises :class:`nine.InvalidTokenError` or :class:`nine.InsufficientScopeError`.
    """
    kwargs: dict[str, Any] = {}
    if scope:
        kwargs["scope"] = scope
    if audience:
        kwargs["audience"] = audience
    return dict(get_token_verifier().verify(token, **kwargs))
