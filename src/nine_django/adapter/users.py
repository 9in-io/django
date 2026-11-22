"""``DjangoUserAdapter``: answers 9in's adapter calls from your Django user model."""

from __future__ import annotations

import datetime
import logging
from collections.abc import Callable, Mapping
from typing import Any

import nine
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.views.decorators.debug import sensitive_variables

from ..conf import nine_settings
from ..signals import otp_requested, send_event

__all__ = ["DjangoUserAdapter"]

logger = logging.getLogger("nine_django")

# Values of AdapterUser fields that are booleans in the protocol.
_FLAGS = ("email_verified", "phone_number_verified", "blocked")


def _full_name(user: Any) -> str | None:
    name = user.get_full_name() if hasattr(user, "get_full_name") else ""
    return name or None


def _blocked(user: Any) -> bool:
    return not getattr(user, "is_active", True)


class DjangoUserAdapter(nine.Adapter):
    """The adapter over ``AUTH_USER_MODEL``.

    - ``/authenticate``: finds users by email or username (case-insensitive) or phone, checks
      the password with ``user.check_password()`` (Django upgrades old hashes then), and
      answers ``blocked`` for inactive users. Unknown users and wrong passwords get the same
      answer, in about the same time.
    - ``/user``: finds a user by id (the primary key) or identifier.
    - ``/event``: ``otp.requested`` codes go out by email with ``send_mail`` (``OTP_EMAIL``);
      every event is sent as a Django signal (``otp_requested``, ``user_updated``…, with
      ``sender=AdapterEvent``). Send SMS codes from an ``otp_requested`` receiver.

    The user object 9in stores comes from :attr:`fields`, which ``NINE["ADAPTER_FIELDS"]``
    overrides: claim → attribute name (``"profile__phone"`` follows relations), a callable
    taking the user, or None to leave the claim out::

        NINE = {"ADAPTER_FIELDS": {
            "phone_number": "profile__phone",
            "email_verified": lambda user: user.emailaddress_set.filter(verified=True).exists(),
        }}

    Subclass it for anything else and set ``NINE["ADAPTER"]`` to your class.
    """

    # Configuration --------------------------------------------------------------------

    def get_user_model(self) -> Any:
        return get_user_model()

    def get_queryset(self) -> Any:
        """The users 9in may sign in (override to exclude some)."""
        return self.get_user_model()._default_manager.all()

    @property
    def fields(self) -> dict[str, str | Callable[[Any], Any] | None]:
        UserModel = self.get_user_model()
        email_field = UserModel.get_email_field_name()
        username_field = UserModel.USERNAME_FIELD
        defaults: dict[str, str | Callable[[Any], Any] | None] = {
            "id": "pk",
            "email": email_field if _has_field(UserModel, email_field) else None,
            "email_verified": None,
            "phone_number": None,
            "phone_number_verified": None,
            "username": username_field if username_field != email_field else None,
            "name": _full_name,
            "given_name": "first_name" if _has_field(UserModel, "first_name") else None,
            "family_name": "last_name" if _has_field(UserModel, "last_name") else None,
            "picture": None,
            "locale": None,
            "zoneinfo": None,
            "birthdate": None,
            "blocked": _blocked,
            "metadata": None,
        }
        defaults.update(dict(nine_settings.ADAPTER_FIELDS or {}))
        return defaults

    # The adapter protocol ---------------------------------------------------------------

    @sensitive_variables("password")
    def authenticate(self, identifier: Mapping[str, Any], password: str) -> Any:
        users = self.find_users(identifier)
        hashed = False
        for user in users:
            if not password or not user.has_usable_password():
                continue
            hashed = True
            if self.check_password(user, password):
                return self.BLOCKED if self.is_blocked(user) else self.to_adapter_user(user)
        if not hashed:
            # Hash anyway, so unknown users and users without a password take as long as a wrong password.
            self.get_user_model()().set_password(password or "")
        return self.INVALID

    def find_user(self, query: Mapping[str, Any]) -> Any:
        if query.get("id") is not None:
            user = self.get_django_user(str(query["id"]))
        else:
            identifier = query.get("identifier")
            users = self.find_users(identifier if isinstance(identifier, Mapping) else {})
            user = users[0] if users else None
        return self.to_adapter_user(user) if user is not None else None

    def on_event(self, event: Mapping[str, Any]) -> None:
        if event.get("event_type") == "otp.requested":
            data = event.get("data")
            self.send_otp(data if isinstance(data, Mapping) else {})
        send_event(event, source="adapter")

    # Lookups -------------------------------------------------------------------------

    def lookup(self, identifier_type: str) -> str | None:
        """The ORM lookup for an identifier type (``email``, ``username``, ``phone``), or None."""
        if identifier_type not in tuple(nine_settings.ADAPTER_IDENTIFIERS or ()):
            return None
        claim = "phone_number" if identifier_type == "phone" else identifier_type
        source = self.fields.get(claim)
        if not isinstance(source, str) or source == "pk":
            return None
        return f"{source}__iexact" if identifier_type in ("email", "username") else source

    def find_users(self, identifier: Mapping[str, Any]) -> list[Any]:
        """Users matching ``{"type", "value"}`` (several when emails are not unique)."""
        value = str(identifier.get("value") or "").strip()
        lookup = self.lookup(str(identifier.get("type") or ""))
        if not value or lookup is None:
            return []
        try:
            return list(self.get_queryset().filter(**{lookup: value}).order_by("pk")[:10])
        except (ValueError, TypeError, ValidationError):
            return []

    def get_django_user(self, user_id: str) -> Any:
        """The user with this adapter id (the primary key, or the ``id`` field's attribute)."""
        source = self.fields.get("id")
        field = source if isinstance(source, str) else "pk"
        try:
            return self.get_queryset().filter(**{field: user_id}).first()
        except (ValueError, TypeError, ValidationError):
            return None

    @sensitive_variables("password")
    def check_password(self, user: Any, password: str) -> bool:
        if not password or not user.has_usable_password():
            return False
        return bool(user.check_password(password))

    def is_blocked(self, user: Any) -> bool:
        return bool(self.value(user, "blocked"))

    # The user object -----------------------------------------------------------------

    def value(self, user: Any, claim: str) -> Any:
        source = self.fields.get(claim)
        if source is None:
            return None
        if callable(source):
            return source(user)
        value: Any = user
        for part in str(source).split("__"):
            value = getattr(value, part, None)
            if value is None:
                return None
        return value() if callable(value) else value

    def to_adapter_user(self, user: Any) -> nine.AdapterUser:
        """The user object 9in stores (claims with OIDC names; ``id`` is your id)."""
        data: dict[str, Any] = {}
        for claim in self.fields:
            value = self.value(user, claim)
            if value is None:
                continue
            if claim == "id":
                value = str(value)
            elif claim in _FLAGS:
                value = bool(value)
            elif isinstance(value, datetime.datetime):
                value = value.date().isoformat() if claim == "birthdate" else value.isoformat()
            elif isinstance(value, datetime.date):
                value = value.isoformat()
            elif claim not in ("metadata",) and not isinstance(value, (str, int, float, bool, dict, list)):
                value = str(value)
            if claim == "metadata" and not isinstance(value, Mapping):
                continue
            if isinstance(value, str) and value == "" and claim != "id":
                continue
            data[claim] = value
        return nine.AdapterUser(data)

    # One-time codes ------------------------------------------------------------------

    def send_otp(self, data: Mapping[str, Any]) -> None:
        """Delivers an ``otp.requested`` code: email with ``send_mail``; SMS through your receiver."""
        channel = data.get("channel")
        if channel == "email" and nine_settings.OTP_EMAIL:
            from .otp import send_otp_email

            send_otp_email(data)
        elif channel == "sms" and not otp_requested.has_listeners():
            logger.warning("9in asked for an SMS code, but no receiver of nine_django.signals.otp_requested sends SMS")


def _has_field(model: Any, name: str) -> bool:
    try:
        model._meta.get_field(name)
    except Exception:
        return False
    return True
