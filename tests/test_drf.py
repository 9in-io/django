"""Django REST framework: NineTokenAuthentication and HasScope."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from nine_django.models import NineIdentity

pytest.importorskip("rest_framework")
pytestmark = pytest.mark.django_db


def bearer(token: str) -> dict[str, str]:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def test_authenticates_bearer_tokens(client, tenant, nine_config):
    response = client.get("/drf/me", **bearer(tenant.access_token("usr_api", scope="orders:read")))
    assert response.status_code == 200
    assert response.json() == {"sub": "usr_api", "user": "usr_api", "user_class": "TokenUser"}


def test_linked_local_user(client, tenant, nine_config):
    user = get_user_model().objects.create_user("drf-user")
    NineIdentity.objects.create(user=user, issuer=tenant.issuer, sub="usr_api")
    response = client.get("/drf/me", **bearer(tenant.access_token("usr_api")))
    assert response.json()["user"] == "drf-user"


def test_no_token(client, nine_config):
    response = client.get("/drf/me")
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == 'Bearer realm="9in"'


def test_invalid_tokens(client, tenant, nine_config):
    for header in ["Bearer not-a-token", "Bearer", "Bearer a b", f"Bearer {tenant.access_token(aud='https://other.test')}"]:
        response = client.get("/drf/me", HTTP_AUTHORIZATION=header)
        assert response.status_code == 401, header
        assert response.json()["detail"]


def test_other_schemes_are_left_to_other_authenticators(client, nine_config):
    assert client.get("/drf/me", HTTP_AUTHORIZATION="Token abc").status_code == 401


def test_has_scope(client, tenant, nine_config):
    assert client.get("/drf/orders", **bearer(tenant.access_token(scope="orders:read"))).status_code == 200
    response = client.get("/drf/orders", **bearer(tenant.access_token(scope="profile")))
    assert response.status_code == 403
    assert "orders:read" in response.json()["detail"]
    assert client.post("/drf/orders", **bearer(tenant.access_token(scope="orders:read"))).status_code == 201, (
        "no CSRF for bearer tokens"
    )


def test_has_scope_from_the_view(client, tenant, nine_config):
    assert client.get("/drf/scoped", **bearer(tenant.access_token(scope="orders:read"))).status_code == 403
    assert client.get("/drf/scoped", **bearer(tenant.access_token(scope="orders:write"))).status_code == 200


def test_has_scope_composes(client, tenant, nine_config):
    assert client.get("/drf/admin-or-scope", **bearer(tenant.access_token(scope="orders:admin"))).status_code == 200
    assert client.get("/drf/admin-or-scope", **bearer(tenant.access_token(scope="orders:read"))).status_code == 403
    admin = get_user_model().objects.create_user("admin", is_staff=True)
    NineIdentity.objects.create(user=admin, issuer=tenant.issuer, sub="usr_admin")
    assert client.get("/drf/admin-or-scope", **bearer(tenant.access_token("usr_admin"))).status_code == 200


def test_revoked_tokens_after_the_webhook(client, tenant, nine_config):
    from tests.test_webhooks import post_event

    token = tenant.access_token("usr_api", scope="orders:read", sid="sid_drf")
    assert client.get("/drf/orders", **bearer(token)).status_code == 200
    tenant.revoke_session("sid_drf")
    post_event(client, "session.revoked", {"sid": "sid_drf", "user": {"id": "usr_api"}})
    assert client.get("/drf/orders", **bearer(token)).status_code == 401


def test_9in_unreachable(client, tenant, nine_config):
    tenant.fail_introspection = True
    assert client.get("/drf/orders", **bearer(tenant.access_token(scope="orders:read"))).status_code == 503


def test_has_scope_without_scopes_refuses(client, tenant, nine_config):
    assert client.get("/drf/scope-missing", **bearer(tenant.access_token(scope="orders:read orders:write"))).status_code == 403
