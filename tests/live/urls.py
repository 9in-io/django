from django.http import HttpResponse, JsonResponse
from django.urls import include, path

from nine_django.decorators import require_token


def dashboard(request):
    if not request.user.is_authenticated:
        return HttpResponse(status=401)
    return HttpResponse(f"hello {request.user.email}")


@require_token(scope="read:things")
def things(request):
    return JsonResponse({"sub": request.nine.sub, "client_id": request.nine.claims.get("client_id"), "user": str(request.user)})


@require_token
def opaque(request):
    return JsonResponse({"sub": request.nine.sub})


urlpatterns = [
    path("nine/", include("nine_django.urls")),
    path("dashboard", dashboard),
    path("api/things", things),
    path("api/opaque", opaque),
    # Replays of 9in's adapter calls set SCRIPT_NAME to the receiver's base path.
    path("", include("nine_django.adapter.urls")),
]
