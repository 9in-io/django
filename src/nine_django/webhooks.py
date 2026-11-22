"""Processing of verified webhooks: revocations, de-duplication and signals."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import nine
from django.http import HttpRequest

from .conf import nine_settings
from .signals import send_event

__all__ = ["verify_request", "process_event", "evict_tokens", "PROCESSED", "DUPLICATE", "IN_PROGRESS"]

logger = logging.getLogger("nine_django")

PROCESSED = "processed"
DUPLICATE = "duplicate"
IN_PROGRESS = "in_progress"


def verify_request(request: HttpRequest) -> dict[str, Any]:
    """Verifies the ``9in-signature`` of a webhook request and returns the event.

    The signature covers the raw body and the path 9in posted to (``request.path``, or
    ``NINE["WEBHOOK_PATH"]`` behind a proxy that rewrites it), and must be at most
    ``WEBHOOK_TOLERANCE`` seconds old. Raises :class:`nine.SignatureError`.
    """
    secrets = nine_settings.webhook_secrets
    if not secrets:
        raise nine.NineError("webhook_not_configured", "Set NINE_WEBHOOK_SECRET to receive webhooks.", 500)
    event = nine.verify_webhook(
        secrets if len(secrets) > 1 else secrets[0],
        request.body,
        request.headers.get("9in-signature"),
        str(nine_settings.WEBHOOK_PATH or request.path),
        method=request.method or "POST",
        tolerance=int(nine_settings.WEBHOOK_TOLERANCE),
    )
    if not isinstance(event, Mapping) or not event.get("id") or not event.get("event_type"):
        raise nine.NineError("invalid_event", "The webhook body is not a 9in event.", 400)
    return dict(event)


def evict_tokens(event: Mapping[str, Any]) -> None:
    """Drops cached token answers the event makes stale (hybrid verification).

    ``token.revoked``, ``session.revoked`` and the ``user.*`` events that end access take
    effect at once for bearer tokens on this app. Errors are logged, not raised: a
    misconfigured verifier must not make 9in retry the webhook forever.
    """
    if not nine_settings.ISSUER:
        return
    try:
        from .services import get_token_verifier

        get_token_verifier().handle_event(event)
    except Exception:
        logger.exception("Could not apply 9in event %s to the token cache", event.get("id"))


def process_event(event: Mapping[str, Any]) -> str:
    """Evicts stale token answers, then sends the event's signals once per event id.

    Returns ``"processed"``, ``"duplicate"`` (already processed: retries and redeliveries) or
    ``"in_progress"`` (another request is processing it right now: answer 409). When a
    receiver raises, the id is released and the exception propagates, so 9in retries.
    """
    evict_tokens(event)

    def dispatch() -> None:
        send_event(event, source="webhook")

    if not nine_settings.WEBHOOK_DEDUPE:
        dispatch()
        return PROCESSED
    from .services import get_cache

    deduplicator = nine.EventDeduplicator(get_cache(), ttl=int(nine_settings.WEBHOOK_DEDUPE_TTL), claim_ttl=300)
    return str(deduplicator.process(str(event["id"]), dispatch))
