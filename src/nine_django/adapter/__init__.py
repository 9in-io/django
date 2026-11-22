"""Keep users in your Django database: 9in's adapter protocol v2.

``path("nine/", include("nine_django.adapter.urls"))`` serves ``POST /nine/authenticate``,
``/nine/user`` and ``/nine/event``; set the adapter URL in the console to
``https://your-app.com/nine`` and ``NINE_ADAPTER_SECRET`` to its secret.
"""

from .users import DjangoUserAdapter

__all__ = ["DjangoUserAdapter"]
