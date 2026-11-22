"""One-time codes from ``otp.requested`` adapter events, by email."""

from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.dateparse import parse_datetime

from ..conf import nine_settings

__all__ = ["send_otp_email", "otp_context"]


def otp_context(data: Mapping[str, Any]) -> dict[str, Any]:
    purpose = str(data.get("purpose") or "login")
    expires_at = data.get("expires_at")
    expires = parse_datetime(expires_at) if isinstance(expires_at, str) else None
    minutes = None
    if expires is not None:
        remaining = (expires - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        minutes = max(1, round(remaining / 60)) if remaining > 0 else None
    return {
        "code": str(data.get("code") or ""),
        "purpose": purpose,
        "purpose_label": "Password reset" if purpose == "password_reset" else "Sign-in",
        "to": str(data.get("to") or ""),
        "user_id": data.get("user_id"),
        "expires_at": expires,
        "expires_in_minutes": minutes,
    }


def send_otp_email(data: Mapping[str, Any]) -> None:
    """Sends the code with ``send_mail``.

    Templates (override them in your own templates folder): ``nine_django/otp_email_subject.txt``,
    ``nine_django/otp_email.txt`` and ``nine_django/otp_email.html``.
    """
    to = str(data.get("to") or "").strip()
    if not to:
        return
    context = otp_context(data)
    subject = " ".join(render_to_string("nine_django/otp_email_subject.txt", context).split())
    text = render_to_string("nine_django/otp_email.txt", context)
    html = render_to_string("nine_django/otp_email.html", context)
    send_mail(
        subject,
        text,
        nine_settings.OTP_FROM_EMAIL or settings.DEFAULT_FROM_EMAIL,
        [to],
        html_message=html,
    )
