from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from nine_django.rest_framework import HasScope


class Me(APIView):
    def get(self, request):
        return Response({"sub": request.auth["sub"], "user": str(request.user), "user_class": type(request.user).__name__})


class Orders(APIView):
    permission_classes = [IsAuthenticated, HasScope("orders:read")]

    def get(self, request):
        return Response({"orders": []})

    def post(self, request):
        return Response({"ok": True}, status=201)


class ScopedByAttribute(APIView):
    permission_classes = [HasScope]
    required_scopes = ["orders:write"]

    def get(self, request):
        return Response({"ok": True})


class ScopeMissing(APIView):
    permission_classes = [HasScope]  # no required_scopes: refused

    def get(self, request):
        return Response({"ok": True})


class AdminOrScope(APIView):
    permission_classes = [IsAdminUser | HasScope("orders:admin")]

    def get(self, request):
        return Response({"ok": True})
