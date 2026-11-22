from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse

from nine_django.decorators import require_token


@login_required
def dashboard(request):
    return HttpResponse(f"hello {request.user.get_username()} sub={request.nine.sub} source={request.nine.source}")


def whoami(request):
    nine = request.nine
    return JsonResponse(
        {
            "authenticated": request.user.is_authenticated,
            "user": request.user.get_username() if request.user.is_authenticated else None,
            "source": nine.source,
            "sub": nine.sub,
        }
    )


def token(request):
    return JsonResponse({"access_token": request.nine.access_token()})


@require_token
def me(request):
    return JsonResponse(
        {
            "sub": request.nine.sub,
            "source": request.nine.source,
            "user": str(request.user),
            "user_class": type(request.user).__name__,
            "client_id": request.nine.claims.get("client_id"),
        }
    )


@require_token(scope="orders:read")
def orders(request):
    return JsonResponse({"orders": [], "sub": request.nine.sub})


@require_token(scope=["orders:read", "orders:write"])
def write_orders(request):
    return JsonResponse({"ok": True}, status=201)


@require_token(scope="orders:read")
async def async_orders(request):
    return JsonResponse({"orders": [], "sub": request.nine.sub, "async": True})
