"""Bearer access tokens on your API: verification, the user behind a token, error responses."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import nine
from django.contrib.auth.models import Group, Permission
from django.db.models.manager import EmptyManager
from django.http import HttpRequest, JsonResponse
from django.views.decorators.debug import sensitive_variables

from .models import NineIdentity
from .session import nine_state

__all__ = ["TokenUser", "verify_request", "user_for_claims", "error_response"]


class TokenUser:
    """``request.user`` for an access token whose 9in user has no local user here.

    Like :class:`~django.contrib.auth.models.AnonymousUser`, but authenticated: ``pk``,
    ``id`` and ``username`` are the token's ``sub`` (a 9in user id, or the client id of a
    machine-to-machine token), ``claims`` the verified access token claims. It has no
    permissions and cannot be saved.
    """

    is_active = True
    is_staff = False
    is_superuser = False
    is_anonymous = False
    is_authenticated = True
    _groups = EmptyManager(Group)
    _user_permissions = EmptyManager(Permission)

    def __init__(self, claims: Mapping[str, Any]) -> None:
        self.claims = dict(claims)
        self.sub = str(self.claims.get("sub") or "")
        self.pk = self.id = self.username = self.sub

    def __str__(self) -> str:
        return self.sub

    def __repr__(self) -> str:
        return f"<TokenUser {self.sub}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TokenUser) and other.sub == self.sub

    def __hash__(self) -> int:
        return hash(("TokenUser", self.sub))

    @property
    def email(self) -> str:
        return str(self.claims.get("email") or "")

    @property
    def scopes(self) -> set[str]:
        return set(str(self.claims.get("scope") or "").split())

    def has_scope(self, *scopes: str) -> bool:
        return set(scopes) <= self.scopes

    def get_username(self) -> str:
        return self.sub

    @property
    def groups(self) -> EmptyManager:
        return self._groups

    @property
    def user_permissions(self) -> EmptyManager:
        return self._user_permissions

    def get_user_permissions(self, obj: Any = None) -> set[str]:
        return set()

    def get_group_permissions(self, obj: Any = None) -> set[str]:
        return set()

    def get_all_permissions(self, obj: Any = None) -> set[str]:
        return set()

    def has_perm(self, perm: str, obj: Any = None) -> bool:
        return False

    def has_perms(self, perm_list: Sequence[str], obj: Any = None) -> bool:
        return False

    def has_module_perms(self, module: str) -> bool:
        return False

    def save(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError("A 9in token user is not stored in the database.")

    def delete(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError("A 9in token user is not stored in the database.")


def user_for_claims(claims: Mapping[str, Any]) -> Any:
    """The local user linked to the token's 9in user, else a :class:`TokenUser`.

    Raises :class:`nine.InvalidTokenError` when the linked user is inactive.
    """
    identity = (
        NineIdentity.objects.select_related("user")
        .filter(issuer=str(claims.get("iss") or ""), sub=str(claims.get("sub") or ""))
        .first()
    )
    if identity is None:
        return TokenUser(claims)
    if not getattr(identity.user, "is_active", True):
        raise nine.InvalidTokenError("the user is inactive")
    return identity.user


@sensitive_variables("header", "token")
def verify_request(
    request: HttpRequest,
    *,
    scope: str | Sequence[str] | None = None,
    audience: str | Sequence[str] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Verifies the request's ``Authorization: Bearer`` token and returns ``(user, claims)``.

    Sets ``request.user`` and ``request.nine`` (source ``"bearer"``). Raises
    :class:`nine.InvalidTokenError` (401), :class:`nine.InsufficientScopeError` (403) or
    another :class:`nine.NineError` (9in unreachable during introspection).
    """
    from .services import get_token_verifier

    header = request.headers.get("Authorization")
    kwargs: dict[str, Any] = {}
    if scope:
        kwargs["scope"] = scope
    if audience:
        kwargs["audience"] = audience
    claims = dict(get_token_verifier().verify(header, **kwargs))
    user = user_for_claims(claims)
    token = header.split(None, 1)[1].strip() if header and " " in header.strip() else (header or "")
    nine_state(request).use_bearer(token, claims)
    request.user = user
    request._nine_bearer_claims = claims  # type: ignore[attr-defined]
    return user, claims


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def error_response(error: nine.NineError, request: HttpRequest | None = None, scope: Any = None) -> JsonResponse:
    """The JSON response for a refused bearer token (RFC 6750)."""
    if isinstance(error, nine.InsufficientScopeError) or error.error == "insufficient_scope":
        required = " ".join([scope] if isinstance(scope, str) else list(scope or []))
        response = JsonResponse(
            {"error": "insufficient_scope", "error_description": error.description or "insufficient scope"}, status=403
        )
        challenge = 'Bearer realm="9in", error="insufficient_scope"'
        if required:
            challenge += f', scope="{_quote(required)}"'
        response["WWW-Authenticate"] = challenge
        return response
    if isinstance(error, nine.InvalidTokenError) or error.status == 401:
        has_header = bool(request is not None and request.headers.get("Authorization"))
        if not has_header:
            response = JsonResponse(
                {"error": "invalid_token", "error_description": "Send a valid 9in access token: Authorization: Bearer <token>."},
                status=401,
            )
            response["WWW-Authenticate"] = 'Bearer realm="9in"'
            return response
        description = error.description or "invalid token"
        response = JsonResponse({"error": "invalid_token", "error_description": description}, status=401)
        response["WWW-Authenticate"] = f'Bearer realm="9in", error="invalid_token", error_description="{_quote(description)}"'
        return response
    # 9in could not be reached (introspection) or another server-side problem.
    return JsonResponse(
        {"error": error.error or "server_error", "error_description": error.description or "token verification failed"},
        status=503,
    )
