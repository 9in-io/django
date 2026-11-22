"""The authentication backend that turns a 9in sign-in into a local Django user."""

from __future__ import annotations

import logging
import secrets
from collections.abc import Mapping
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest
from django.utils import timezone

from .conf import nine_settings
from .models import NineIdentity

__all__ = ["NineBackend"]

logger = logging.getLogger("nine_django")


class NineBackend(ModelBackend):
    """Signs in the local user linked to a 9in user, linking or creating one the first time.

    ``/nine/callback`` calls ``django.contrib.auth.authenticate(request, nine_claims=claims)``
    with the verified ID token claims. The user is found, in this order:

    1. by a :class:`~nine_django.models.NineIdentity` (``iss`` + ``sub``) from an earlier sign-in;
    2. for users of your own database (adapter), by the adapter id 9in keeps for them
       (``LINK_ADAPTER_USERS``, on when ``ADAPTER_SECRET`` is set; needs the Management API);
    3. by email, only when 9in says it is verified (``LINK_BY_EMAIL``) and one user has it;
    4. otherwise a new user is created (``CREATE_USERS``) with an unusable password.

    Inactive users are refused. ``UPDATE_USERS`` copies ``USER_FIELDS`` from the claims on
    every sign-in. Subclass it and list your class in ``AUTHENTICATION_BACKENDS`` to change
    any step (``find_user_to_link``, ``create_user``, ``user_fields``…). Everything else
    (``get_user``, permissions) is :class:`~django.contrib.auth.backends.ModelBackend`.
    """

    def authenticate(  # type: ignore[override]
        self, request: HttpRequest | None, nine_claims: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        if not nine_claims or not nine_claims.get("sub") or not nine_claims.get("iss"):
            return None
        user = self.get_or_create_user(dict(nine_claims), request)
        if user is None or not self.user_can_authenticate(user):
            return None
        return user

    # Steps ------------------------------------------------------------------------------

    def get_or_create_user(self, claims: dict[str, Any], request: HttpRequest | None = None) -> Any:
        issuer, sub = str(claims["iss"]), str(claims["sub"])
        identity = NineIdentity.objects.select_related("user").filter(issuer=issuer, sub=sub).first()
        created = False
        if identity is not None:
            user = identity.user
        else:
            user = self.find_user_to_link(claims, request)
            if user is None:
                if not nine_settings.CREATE_USERS:
                    logger.info("9in sign-in of %s refused: no local user and CREATE_USERS is off", sub)
                    return None
                user = self.create_user(claims, request)
                created = True
            identity = self.link(user, issuer, sub)
            user = identity.user
        if nine_settings.UPDATE_USERS and not created:
            self.update_user(user, claims)
        NineIdentity.objects.filter(pk=identity.pk).update(last_login_at=timezone.now())
        user._nine_created = created
        return user

    def link(self, user: Any, issuer: str, sub: str) -> NineIdentity:
        """Creates the identity; a concurrent first sign-in of the same 9in user wins the race."""
        try:
            with transaction.atomic():
                return NineIdentity.objects.create(user=user, issuer=issuer, sub=sub)
        except IntegrityError:
            return NineIdentity.objects.select_related("user").get(issuer=issuer, sub=sub)

    def find_user_to_link(self, claims: dict[str, Any], request: HttpRequest | None = None) -> Any:
        """An existing local user for a 9in user signing in here for the first time, or None."""
        user = None
        if nine_settings.link_adapter_users:
            user = self.find_adapter_user(claims)
        if user is None and nine_settings.LINK_BY_EMAIL:
            user = self.find_user_by_email(claims)
        return user

    def find_adapter_user(self, claims: dict[str, Any]) -> Any:
        """The local user behind an adapter user: 9in keeps your id as an ``adapter`` identity."""
        from .services import get_adapter, get_management_client

        try:
            found = get_management_client().get_user(str(claims["sub"]))
        except Exception as error:  # no credentials, no management scope, 9in unreachable…
            logger.warning("Could not look up 9in user %s for adapter linking: %s", claims.get("sub"), error)
            return None
        found = found if isinstance(found, Mapping) else {}
        user_record = found.get("user")
        identities = (
            found.get("identities") or (user_record.get("identities") if isinstance(user_record, Mapping) else None) or []
        )
        subjects = [
            str(identity.get("subject"))
            for identity in identities
            if isinstance(identity, Mapping) and identity.get("connection") == "adapter" and identity.get("subject")
        ]
        if not subjects:
            return None
        adapter = get_adapter()
        finder = getattr(adapter, "get_django_user", None)
        for subject in subjects:
            user = finder(subject) if finder else self._user_by_pk(subject)
            if user is not None:
                return user
        return None

    def find_user_by_email(self, claims: dict[str, Any]) -> Any:
        email = claims.get("email")
        if not email or claims.get("email_verified") is not True:
            return None
        UserModel = get_user_model()
        field = UserModel.get_email_field_name()
        matches = list(UserModel._default_manager.filter(**{f"{field}__iexact": str(email)})[:2])
        if len(matches) == 1:
            return matches[0]
        if matches:
            logger.warning("9in sign-in of %s not linked by email: several local users have that email", claims["sub"])
        return None

    def create_user(self, claims: dict[str, Any], request: HttpRequest | None = None) -> Any:
        UserModel = get_user_model()
        username_field = UserModel.USERNAME_FIELD
        values = self.user_fields(claims)
        # Unique values another user already has (an email, say) are left out rather than failing.
        for name in [n for n in values if n != username_field]:
            if self._taken(name, values[name]):
                values.pop(name)
        if not values.get(username_field) or self._taken(username_field, values[username_field]):
            values[username_field] = self.make_username(claims)
        user = UserModel(**values)
        user.set_unusable_password()
        try:
            with transaction.atomic():
                user.save()
        except IntegrityError:
            # A concurrent sign-up took a unique value: fall back to a random username only.
            user = UserModel(**{username_field: self._random_username(claims)})
            user.set_unusable_password()
            user.save()
        return user

    def update_user(self, user: Any, claims: dict[str, Any]) -> None:
        values = self.user_fields(claims)
        changed = [name for name, value in values.items() if getattr(user, name, None) != value]
        if not changed:
            return
        original = {name: getattr(user, name, None) for name in changed}
        for name in changed:
            setattr(user, name, values[name])
        try:
            with transaction.atomic():
                user.save(update_fields=changed)
        except IntegrityError:
            for name, value in original.items():
                setattr(user, name, value)
            logger.warning("Could not update user %s from 9in claims (a unique field is taken)", user.pk)

    def user_fields(self, claims: Mapping[str, Any]) -> dict[str, Any]:
        """Model field values from ``USER_FIELDS`` (field → claim name, or callable(claims)).

        Claims the token does not carry are left out, and so are fields the model lacks. The
        ``email`` claim is only copied when 9in says it is verified.
        """
        UserModel = get_user_model()
        values: dict[str, Any] = {}
        email_verified = claims.get("email_verified") is True
        for field_name, source in dict(nine_settings.USER_FIELDS or {}).items():
            if source == "email" and not email_verified:
                continue  # an address 9in has not verified is never copied
            try:
                field = UserModel._meta.get_field(field_name)
            except FieldDoesNotExist:
                continue
            if callable(source):
                value = source(claims)
            elif isinstance(source, str) and source in claims:
                value = claims[source]
            else:
                continue
            if value is None and not getattr(field, "null", False):
                if not getattr(field, "empty_strings_allowed", False):
                    continue
                value = ""
            max_length = getattr(field, "max_length", None)
            if isinstance(value, str) and max_length:
                value = value[:max_length]
            values[field_name] = value
        return values

    @staticmethod
    def _taken(field_name: str, value: Any) -> bool:
        """True when ``field_name`` is unique and another user already has ``value``."""
        UserModel = get_user_model()
        field = UserModel._meta.get_field(field_name)
        if value in (None, "") or not (field.unique or field_name == UserModel.USERNAME_FIELD):
            return False
        lookup = f"{field_name}__iexact" if isinstance(value, str) else field_name
        return UserModel._default_manager.filter(**{lookup: value}).exists()

    def _random_username(self, claims: Mapping[str, Any]) -> str:
        UserModel = get_user_model()
        max_length = getattr(UserModel._meta.get_field(UserModel.USERNAME_FIELD), "max_length", None) or 150
        return f"{str(claims.get('sub') or 'nine')[: max_length - 9]}-{secrets.token_hex(4)}"

    def make_username(self, claims: Mapping[str, Any]) -> str:
        """A free username: the verified email, the 9in username, or the 9in user id."""
        UserModel = get_user_model()
        field = UserModel._meta.get_field(UserModel.USERNAME_FIELD)
        max_length = getattr(field, "max_length", None) or 150
        manager = UserModel._default_manager
        email = claims.get("email") if claims.get("email_verified") is True else None
        for candidate in (email, claims.get("preferred_username"), claims.get("sub")):
            candidate = str(candidate or "").strip()
            if candidate and len(candidate) <= max_length:
                if not manager.filter(**{f"{UserModel.USERNAME_FIELD}__iexact": candidate}).exists():
                    return candidate
        return self._random_username(claims)

    @staticmethod
    def _user_by_pk(value: str) -> Any:
        UserModel = get_user_model()
        try:
            return UserModel._default_manager.filter(pk=value).first()
        except (ValueError, TypeError, ValidationError):
            return None
