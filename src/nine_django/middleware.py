"""``NineMiddleware``: ``request.nine`` and fresh tokens for signed-in users."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from asgiref.sync import iscoroutinefunction, markcoroutinefunction, sync_to_async
from django.http import HttpRequest, HttpResponse

from .session import TOKENS_SESSION_KEY, NineState, forget_tokens, fresh_tokens

__all__ = ["NineMiddleware"]

logger = logging.getLogger("nine_django")


class NineMiddleware:
    """Keeps the 9in tokens of signed-in users fresh and sets ``request.nine``.

    Put it after ``SessionMiddleware`` and ``AuthenticationMiddleware``::

        MIDDLEWARE = [
            ...,
            "django.contrib.sessions.middleware.SessionMiddleware",
            ...,
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "nine_django.middleware.NineMiddleware",
            ...,
        ]

    For users who signed in through ``/nine/callback``, the access token is refreshed (and
    the rotated refresh token saved) shortly before it expires. When 9in refuses the refresh
    token (signed out everywhere, session revoked, user blocked or deleted), the user is
    signed out of Django too. Works under WSGI and ASGI.
    """

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Callable[[HttpRequest], Any]) -> None:
        self.get_response = get_response
        self._async = iscoroutinefunction(get_response)
        if self._async:
            markcoroutinefunction(self)

    def __call__(self, request: HttpRequest) -> Any:
        if self._async:
            return self.__acall__(request)
        self.process_request(request)
        return self.get_response(request)

    async def __acall__(self, request: HttpRequest) -> HttpResponse:
        # Reading the session and the user touches the database: do it in a thread.
        await sync_to_async(self.process_request)(request)
        response: Awaitable[HttpResponse] = self.get_response(request)
        return await response

    def process_request(self, request: HttpRequest) -> None:
        request.nine = NineState(request)  # type: ignore[attr-defined]
        if self._has_tokens(request):
            self._refresh(request)

    @staticmethod
    def _has_tokens(request: HttpRequest) -> bool:
        session = getattr(request, "session", None)
        return session is not None and TOKENS_SESSION_KEY in session

    @staticmethod
    def _refresh(request: HttpRequest) -> None:
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            # Signed out of Django some other way: the tokens have no owner any more.
            forget_tokens(request)
            return
        try:
            fresh_tokens(request)
        except Exception:
            logger.exception("Could not refresh the 9in tokens")
