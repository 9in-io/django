"""Django signals for 9in events.

Every verified event (webhooks at ``/nine/webhook`` and adapter events at ``/nine/event``) is
sent twice: on the signal named after its type (``user.created`` → :data:`user_created`, dots
become underscores) and on :data:`event_received`. Receivers get these keyword arguments:

- ``event``: the whole event, ``{id, event_type, created_at, tenant, environment, data}``
  for webhooks and ``{id, event_type, created_at, data}`` for adapter events (snake_case,
  ISO 8601 UTC times, exactly as 9in sent it);
- ``event_type`` and ``data`` (``event["data"]``);
- ``source``: ``"webhook"`` or ``"adapter"``.

``sender`` is :class:`Webhook` or :class:`AdapterEvent`, so ``@receiver(user_updated,
sender=Webhook)`` listens to one source only. An exception in a receiver makes the webhook
answer 500, and 9in delivers it again later.

::

    from django.dispatch import receiver
    from nine_django.signals import user_created

    @receiver(user_created)
    def welcome(sender, event, data, **kwargs):
        send_welcome_email(data["user"]["email"])
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any

from django.dispatch import Signal

__all__ = [
    "Webhook",
    "AdapterEvent",
    "event_received",
    "user_signed_in",
    "signal_for",
    "send_event",
    "EVENT_TYPES",
    "user_created",
    "user_updated",
    "user_deleted",
    "user_password_changed",
    "user_login",
    "user_login_failed",
    "user_sessions_revoked",
    "user_mfa_enabled",
    "user_mfa_disabled",
    "session_revoked",
    "token_revoked",
    "webhook_test",
    "otp_requested",
]


class Webhook:
    """``sender`` of signals for events received at ``/nine/webhook``."""


class AdapterEvent:
    """``sender`` of signals for events received at the adapter's ``/nine/event``."""


#: Every event, after its own signal.
event_received = Signal()

#: A user signed in to this site through ``/nine/callback``. Arguments: ``request``, ``user``
#: (the local Django user), ``claims`` (verified ID token claims), ``tokens``
#: (:class:`nine.TokenSet`) and ``created`` (True when the local user was created now).
user_signed_in = Signal()

# Webhook event types (https://9in.io/docs/reference/webhook-events/).
user_created = Signal()
user_updated = Signal()  # also an adapter event: data has user_id (your id) and fields
user_deleted = Signal()
user_password_changed = Signal()  # also an adapter event
user_login = Signal()
user_login_failed = Signal()
user_sessions_revoked = Signal()
user_mfa_enabled = Signal()
user_mfa_disabled = Signal()
session_revoked = Signal()
token_revoked = Signal()
webhook_test = Signal()
# Adapter event: a one-time code to deliver (data: user_id, channel, to, code, purpose, expires_at).
otp_requested = Signal()

_signals: dict[str, Signal] = {
    "user.created": user_created,
    "user.updated": user_updated,
    "user.deleted": user_deleted,
    "user.password_changed": user_password_changed,
    "user.login": user_login,
    "user.login_failed": user_login_failed,
    "user.sessions_revoked": user_sessions_revoked,
    "user.mfa_enabled": user_mfa_enabled,
    "user.mfa_disabled": user_mfa_disabled,
    "session.revoked": session_revoked,
    "token.revoked": token_revoked,
    "webhook.test": webhook_test,
    "otp.requested": otp_requested,
}
_lock = threading.Lock()

#: The event types with a signal of their own above.
EVENT_TYPES = tuple(_signals)


def signal_for(event_type: str) -> Signal:
    """The signal for an event type, also for types newer than this package."""
    with _lock:
        signal = _signals.get(event_type)
        if signal is None:
            signal = _signals[event_type] = Signal()
        return signal


def send_event(event: Mapping[str, Any], source: str = "webhook") -> None:
    """Sends ``event`` on its own signal, then on :data:`event_received`."""
    event = dict(event)
    event_type = str(event.get("event_type") or "")
    data = event.get("data")
    kwargs = {
        "event": event,
        "event_type": event_type,
        "data": data if isinstance(data, Mapping) else {},
        "source": source,
    }
    sender = AdapterEvent if source == "adapter" else Webhook
    if event_type:
        signal_for(event_type).send(sender=sender, **kwargs)
    event_received.send(sender=sender, **kwargs)
