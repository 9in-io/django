"""``python manage.py nine_login_link <user>``: a single-use 9in sign-in link."""

from __future__ import annotations

from typing import Any

import nine
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError, CommandParser


class Command(BaseCommand):
    help = (
        "Creates a single-use 9in sign-in link for a user, through the Management API. "
        "<user> is a 9in user id (usr_…), an email address, or the username of a local user "
        "who has signed in with 9in."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("user", help="9in user id, email address, or local username")
        parser.add_argument("--return-to", dest="return_to", help="A registered redirect URL of one of your applications")
        parser.add_argument("--ttl", type=int, default=600, help="Lifetime in seconds (default 600)")

    def handle(self, *args: Any, **options: Any) -> None:
        from ...services import get_management_client

        try:
            management = get_management_client()
            user_id = self.resolve(management, str(options["user"]).strip())
            link = management.create_login_link(user_id, return_to=options.get("return_to") or None, ttl_seconds=options["ttl"])
        except ImproperlyConfigured as error:
            raise CommandError(str(error)) from error
        except nine.NineError as error:
            raise CommandError(error.description or error.error) from error
        self.stdout.write(str(link["url"]))
        if link.get("expires_at"):
            self.stderr.write(f"Expires {link['expires_at']}")

    def resolve(self, management: Any, value: str) -> str:
        """The 9in user id for a 9in id, an email address or a local username."""
        if "@" in value:
            try:
                found = management.find_user_by_email(value)
            except nine.NineError as error:
                if error.status != 404:
                    raise
                found = None
            record = found.get("user", found) if isinstance(found, dict) else None
            if not record or not record.get("id"):
                raise CommandError(
                    f"No 9in user with the email {value}. Users of your own database exist in 9in after their first sign-in."
                )
            return str(record["id"])
        if value.startswith("usr_"):
            return value
        UserModel = get_user_model()
        local = UserModel._default_manager.filter(**{UserModel.USERNAME_FIELD: value}).first()
        if local is not None:
            identity = local.nine_identities.order_by("-last_login_at", "-created_at").first()
            if identity is None:
                raise CommandError(f"The local user {value} has not signed in with 9in yet.")
            return identity.sub
        return value
