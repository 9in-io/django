"""The adapter endpoints: signature checks, routing and response signing are the SDK's."""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_variables

__all__ = ["adapter"]


@csrf_exempt
@never_cache
@sensitive_variables()  # innermost, so the view's own locals are hidden
def adapter(request: HttpRequest) -> HttpResponse:
    """``POST /nine/authenticate``, ``/nine/user`` and ``/nine/event`` (signed both ways).

    The path checked against the signature is ``request.path``: the path 9in called,
    ``FORCE_SCRIPT_NAME`` included.
    """
    from ..services import get_adapter_handler

    headers = {name.lower(): value for name, value in request.headers.items()}
    result = get_adapter_handler().handle(request.method or "GET", request.path, headers, request.body)
    response = HttpResponse(result.body, status=result.status)
    for name, value in (result.headers or {}).items():
        response[name] = value
    return response


adapter.login_required = False  # type: ignore[attr-defined]  # Django 5.1+ LoginRequiredMiddleware
