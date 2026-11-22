"""Django REST framework authentication and permission classes (needs ``djangorestframework``).

::

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": ["nine_django.rest_framework.NineTokenAuthentication"],
    }

    class OrderList(APIView):
        permission_classes = [HasScope("orders:read")]
"""

from __future__ import annotations

from typing import Any

import nine
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.permissions import BasePermission

__all__ = ["NineTokenAuthentication", "HasScope", "NineUnavailable"]


class NineUnavailable(exceptions.APIException):
    status_code = 503
    default_detail = "The access token could not be checked with 9in."
    default_code = "temporarily_unavailable"


class NineTokenAuthentication(BaseAuthentication):
    """Authenticates ``Authorization: Bearer <9in access token>``.

    Tokens are verified with the configured :class:`nine.HybridTokenVerifier`: signature,
    ``typ: at+jwt``, issuer, expiry and ``NINE["API_AUDIENCE"]``, then revocation (hybrid
    mode, when client credentials are set). ``request.user`` is the linked local user, or a
    :class:`nine_django.api.TokenUser`; ``request.auth`` is the dict of access token claims.
    Requests without a bearer token are left to the other authentication classes.
    """

    keyword = "bearer"

    def authenticate(self, request: Any) -> tuple[Any, dict[str, Any]] | None:
        header = get_authorization_header(request).split()
        if not header or header[0].lower() != self.keyword.encode():
            return None
        if len(header) != 2:
            raise exceptions.AuthenticationFailed(
                "Invalid Authorization header: expected 'Bearer <token>'.", code="invalid_token"
            )
        from .api import verify_request

        try:
            user, claims = verify_request(request._request)
        except nine.InvalidTokenError as error:
            raise exceptions.AuthenticationFailed(error.description or "Invalid token.", code="invalid_token") from error
        except nine.NineError as error:
            if error.status == 401:
                raise exceptions.AuthenticationFailed(error.description or "Invalid token.", code="invalid_token") from error
            raise NineUnavailable() from error
        return user, claims

    def authenticate_header(self, request: Any) -> str:
        return 'Bearer realm="9in"'


class HasScope(BasePermission):
    """Requires scopes on the request's 9in access token (403 ``insufficient_scope`` otherwise).

    ``permission_classes = [HasScope("orders:read", "orders:write")]`` requires every scope
    given; ``permission_classes = [HasScope]`` reads them from the view's ``required_scopes``.
    Composes with DRF's operators: ``[IsAdminUser | HasScope("orders:admin")]``.
    """

    code = "insufficient_scope"

    def __init__(self, *scopes: str) -> None:
        self.scopes = tuple(scopes)

    def __call__(self) -> HasScope:
        # DRF instantiates each entry of permission_classes; an instance stands for itself.
        return self

    def required(self, view: Any) -> list[str]:
        return list(self.scopes) or list(getattr(view, "required_scopes", None) or [])

    @property
    def message(self) -> str:  # type: ignore[override]
        if self.scopes:
            return f"This needs an access token with the scope: {' '.join(self.scopes)}."
        return "The access token lacks a required scope."

    def has_permission(self, request: Any, view: Any) -> bool:
        claims = request.auth if isinstance(request.auth, dict) else None
        if claims is None:
            return False
        required = self.required(view)
        if not required:
            # HasScope with nothing to check is a mistake (a misspelt required_scopes): refuse.
            return False
        granted = set(str(claims.get("scope") or "").split())
        return all(scope in granted for scope in required)
