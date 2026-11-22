"""View decorators for APIs protected with 9in access tokens."""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from typing import Any, TypeVar, overload

import nine
from asgiref.sync import iscoroutinefunction, sync_to_async
from django.http import HttpRequest, HttpResponse

__all__ = ["require_token"]

F = TypeVar("F", bound=Callable[..., Any])


def _check(request: HttpRequest, scope: Any, audience: Any) -> HttpResponse | None:
    from .api import error_response, verify_request

    try:
        verify_request(request, scope=scope, audience=audience)
    except nine.NineError as error:
        return error_response(error, request, scope)
    return None


def _exempt(view: Any) -> Any:
    """Bearer-token views need no CSRF token (no cookies) and authenticate themselves."""
    view.csrf_exempt = True
    view.login_required = False  # Django 5.1+ LoginRequiredMiddleware
    return view


@overload
def require_token(view: F) -> F: ...
@overload
def require_token(
    view: None = None, *, scope: str | Sequence[str] | None = None, audience: str | Sequence[str] | None = None
) -> Callable[[F], F]: ...


def require_token(
    view: Any = None,
    *,
    scope: str | Sequence[str] | None = None,
    audience: str | Sequence[str] | None = None,
) -> Any:
    """Requires a valid 9in access token (``Authorization: Bearer …``) on a view.

    ::

        @require_token(scope="orders:read")
        def orders(request):
            request.user          # your linked user, or a TokenUser (sub, claims)
            request.nine.claims   # the access token claims: sub, client_id, scope, aud…

    Tokens are verified with the configured :class:`nine.HybridTokenVerifier` for
    ``NINE["API_AUDIENCE"]`` (or ``audience=``). A missing or invalid token gets 401
    ``invalid_token``, a token without every ``scope`` 403 ``insufficient_scope``, both with
    a ``WWW-Authenticate`` header. Works on sync and async views; the view is exempt from
    CSRF checks, since the token, not a cookie, authenticates the request.
    """

    def decorator(view_func: F) -> F:
        if iscoroutinefunction(view_func):

            @functools.wraps(view_func)
            async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
                refused = await sync_to_async(_check)(request, scope, audience)
                if refused is not None:
                    return refused
                return await view_func(request, *args, **kwargs)

            return _exempt(async_wrapper)  # type: ignore[no-any-return]

        @functools.wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            refused = _check(request, scope, audience)
            if refused is not None:
                return refused
            return view_func(request, *args, **kwargs)

        return _exempt(wrapper)  # type: ignore[no-any-return]

    if view is not None and callable(view):
        return decorator(view)
    return decorator
