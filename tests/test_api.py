"""@require_token, hybrid verification with the Django cache, and the user behind a token."""

from __future__ import annotations

import json
import time

import nine
import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.test import AsyncClient, Client

from nine_django import verify_access_token
from nine_django.api import TokenUser
from nine_django.models import NineIdentity
from tests.fake_tenant import ASYMMETRIC, SYMMETRIC, b64url

pytestmark = pytest.mark.django_db


def aget(client, *args, **kwargs):
    async def run():
        return await client.get(*args, **kwargs)

    return async_to_sync(run)()


User = get_user_model()


def bearer(token: str) -> dict[str, str]:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def test_missing_token(client, nine_config):
    response = client.get("/api/orders")
    assert response.status_code == 401
    assert response["WWW-Authenticate"] == 'Bearer realm="9in"'
    assert response.json()["error"] == "invalid_token"


@pytest.mark.parametrize("alg", ASYMMETRIC)
def test_accepts_every_asymmetric_algorithm(client, tenant, nine_config, alg):
    token = tenant.access_token("usr_api", scope="orders:read", alg=alg)
    response = client.get("/api/orders", **bearer(token))
    assert response.status_code == 200, response.content
    assert response.json() == {"orders": [], "sub": "usr_api"}


@pytest.mark.parametrize("alg", SYMMETRIC)
def test_accepts_hmac_tokens_with_the_api_secret(client, tenant, configure, alg):
    token = tenant.access_token("usr_api", scope="orders:read", alg=alg)
    configure(TOKEN_VERIFICATION="local")
    assert client.get("/api/orders", **bearer(token)).status_code == 401, "no secret configured"
    configure(TOKEN_VERIFICATION="local", API_SECRET=tenant.hmac_secret.decode())
    assert client.get("/api/orders", **bearer(token)).status_code == 200


def test_insufficient_scope(client, tenant, nine_config):
    token = tenant.access_token("usr_api", scope="orders:read")
    response = client.post("/api/orders/write", **bearer(token))
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"
    assert response["WWW-Authenticate"] == 'Bearer realm="9in", error="insufficient_scope", scope="orders:read orders:write"'
    both = tenant.access_token("usr_api", scope="orders:read orders:write")
    assert client.post("/api/orders/write", **bearer(both)).status_code == 201, "exempt from CSRF"


@pytest.mark.parametrize(
    "case",
    [
        "wrong audience",
        "expired",
        "not yet valid",
        "id token",
        "alg none",
        "tampered",
        "wrong issuer",
        "unknown kid",
        "garbage",
        "basic auth",
    ],
)
def test_refuses_bad_tokens(client, tenant, nine_config, case):
    now = int(time.time())
    if case == "wrong audience":
        token = tenant.access_token(scope="orders:read", aud="https://other.test")
    elif case == "expired":
        token = tenant.access_token(scope="orders:read", ttl=-120)
    elif case == "not yet valid":
        token = tenant.access_token(scope="orders:read", nbf=now + 600)
    elif case == "id token":
        token = tenant.id_token("usr_api", None, aud=tenant.audience, scope="orders:read")
    elif case == "alg none":
        head = b64url(json.dumps({"alg": "none", "typ": "at+jwt"}).encode())
        body = b64url(
            json.dumps(
                {"iss": tenant.issuer, "sub": "x", "aud": tenant.audience, "exp": now + 60, "scope": "orders:read"}
            ).encode()
        )
        token = f"{head}.{body}."
    elif case == "tampered":
        token = tenant.access_token(scope="orders:read")
        token = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    elif case == "wrong issuer":
        token = tenant.access_token(scope="orders:read", iss="https://evil.test")
    elif case == "unknown kid":
        token = tenant.sign(
            {"iss": tenant.issuer, "sub": "x", "aud": tenant.audience, "exp": now + 60, "scope": "orders:read"},
            header={"kid": "k_unknown"},
        )
    elif case == "garbage":
        token = "not-a-token"
    else:
        response = client.get("/api/orders", HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz")
        assert response.status_code == 401
        return
    response = client.get("/api/orders", **bearer(token))
    assert response.status_code == 401, (case, response.content)
    assert response.json()["error"] == "invalid_token"
    assert response["WWW-Authenticate"].startswith('Bearer realm="9in", error="invalid_token"')


def test_alg_must_match_the_jwk(client, tenant, nine_config):
    # Signed by the PS256 key but labelled with the RS256 key's kid.
    token = tenant.sign(
        {"iss": tenant.issuer, "sub": "x", "aud": tenant.audience, "exp": int(time.time()) + 60, "scope": "orders:read"},
        "PS256",
        header={"kid": tenant.keys["RS256"].kid},
    )
    assert client.get("/api/orders", **bearer(token)).status_code == 401


def test_token_user_or_linked_local_user(client, tenant, nine_config):
    token = tenant.access_token("usr_api", scope="orders:read")
    data = client.get("/api/me", **bearer(token)).json()
    assert data == {
        "sub": "usr_api",
        "source": "bearer",
        "user": "usr_api",
        "user_class": "TokenUser",
        "client_id": tenant.client_id,
    }

    local = User.objects.create_user("api-user")
    NineIdentity.objects.create(user=local, issuer=tenant.issuer, sub="usr_api")
    data = client.get("/api/me", **bearer(token)).json()
    assert data["user"] == "api-user" and data["user_class"] == "User"

    local.is_active = False
    local.save()
    assert client.get("/api/me", **bearer(token)).status_code == 401


def test_machine_to_machine_tokens(client, tenant, nine_config):
    token = tenant.access_token(tenant.client_id, scope="orders:read", sid=None)
    data = client.get("/api/me", **bearer(token)).json()
    assert data["sub"] == tenant.client_id and data["user_class"] == "TokenUser"


def test_hybrid_caches_one_introspection_per_token(client, tenant, nine_config):
    token = tenant.access_token("usr_api", scope="orders:read")
    for _ in range(3):
        assert client.get("/api/orders", **bearer(token)).status_code == 200
    assert tenant.count("POST", "/oauth/introspect") == 1


def test_hybrid_refuses_a_revoked_token_once_the_webhook_arrives(client, tenant, nine_config):
    from tests.test_webhooks import post_event

    token = tenant.access_token("usr_api", scope="orders:read")
    jti = json.loads(__import__("base64").urlsafe_b64decode(token.split(".")[1] + "=="))["jti"]
    assert client.get("/api/orders", **bearer(token)).status_code == 200
    tenant.revoke(token)
    assert client.get("/api/orders", **bearer(token)).status_code == 200, "the cached answer stands until 9in says otherwise"
    response = post_event(
        Client(),
        "token.revoked",
        {"token_type": "access_token", "jti": jti, "client_id": tenant.client_id, "sid": "s", "user": None},
    )
    assert response.status_code == 204
    assert client.get("/api/orders", **bearer(token)).status_code == 401


def test_session_revoked_and_user_events_evict(client, tenant, nine_config):
    from tests.test_webhooks import post_event

    a = tenant.access_token("usr_a", scope="orders:read", sid="sid_a")
    b = tenant.access_token("usr_b", scope="orders:read", sid="sid_b")
    for token in (a, b):
        assert client.get("/api/orders", **bearer(token)).status_code == 200
    tenant.revoke_session("sid_a")
    tenant.users["usr_b"] = {"id": "usr_b", "blocked": True}
    post_event(Client(), "session.revoked", {"sid": "sid_a", "user": {"id": "usr_a"}})
    assert client.get("/api/orders", **bearer(a)).status_code == 401
    assert client.get("/api/orders", **bearer(b)).status_code == 200
    post_event(Client(), "user.updated", {"fields": ["blocked"], "user": {"id": "usr_b", "blocked": True}})
    assert client.get("/api/orders", **bearer(b)).status_code == 401


def test_local_mode_does_not_introspect(client, tenant, configure):
    configure(TOKEN_VERIFICATION="local")
    token = tenant.access_token("usr_api", scope="orders:read")
    tenant.revoke(token)
    assert client.get("/api/orders", **bearer(token)).status_code == 200
    assert tenant.count("POST", "/oauth/introspect") == 0


def test_local_mode_without_client_credentials(client, tenant, configure):
    configure(CLIENT_SECRET=None)
    token = tenant.access_token("usr_api", scope="orders:read")
    assert client.get("/api/orders", **bearer(token)).status_code == 200
    assert tenant.count("POST", "/oauth/introspect") == 0
    opaque = tenant.opaque_token("usr_api", scope="orders:read")
    assert client.get("/api/orders", **bearer(opaque)).status_code == 401


def test_introspect_mode_asks_every_time(client, tenant, configure):
    configure(TOKEN_VERIFICATION="introspect")
    token = tenant.access_token("usr_api", scope="orders:read")
    client.get("/api/orders", **bearer(token))
    client.get("/api/orders", **bearer(token))
    assert tenant.count("POST", "/oauth/introspect") == 2
    tenant.revoke(token)
    assert client.get("/api/orders", **bearer(token)).status_code == 401


def test_opaque_tokens_are_introspected(client, tenant, nine_config):
    token = tenant.opaque_token("usr_api", scope="orders:read")
    assert client.get("/api/orders", **bearer(token)).status_code == 200
    assert client.get("/api/orders", **bearer("9in_at_unknown")).status_code == 401
    other_api = tenant.opaque_token("usr_api", scope="orders:read", aud="https://other.test")
    assert client.get("/api/orders", **bearer(other_api)).status_code == 401


def test_9in_unreachable_during_introspection_is_503(client, tenant, nine_config):
    tenant.fail_introspection = True
    token = tenant.access_token("usr_api", scope="orders:read")
    response = client.get("/api/orders", **bearer(token))
    assert response.status_code == 503


def test_management_credentials_are_used_for_introspection(client, tenant, configure):
    configure(CLIENT_SECRET="wrong", MANAGEMENT_CLIENT_ID=tenant.client_id, MANAGEMENT_CLIENT_SECRET=tenant.client_secret)
    token = tenant.access_token("usr_api", scope="orders:read")
    assert client.get("/api/orders", **bearer(token)).status_code == 200


def test_api_audience_setting(client, tenant, configure):
    configure(API_AUDIENCE="https://orders.test")
    assert client.get("/api/orders", **bearer(tenant.access_token(scope="orders:read"))).status_code == 401
    assert (
        client.get("/api/orders", **bearer(tenant.access_token(scope="orders:read", aud="https://orders.test"))).status_code
        == 200
    )


def test_async_views(tenant, nine_config):
    client = AsyncClient()
    token = tenant.access_token("usr_api", scope="orders:read")
    response = aget(client, "/api/async-orders", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"orders": [], "sub": "usr_api", "async": True}
    refused = aget(client, "/api/async-orders", headers={"Authorization": f"Bearer {tenant.access_token(scope='x')}"})
    assert refused.status_code == 403


def test_verify_access_token_helper(tenant, nine_config):
    token = tenant.access_token("usr_api", scope="orders:read")
    assert verify_access_token(token)["sub"] == "usr_api"
    assert verify_access_token(f"Bearer {token}", scope="orders:read")["sub"] == "usr_api"
    with pytest.raises(nine.InsufficientScopeError):
        verify_access_token(token, scope="orders:write")
    with pytest.raises(nine.InvalidTokenError):
        verify_access_token(token, audience="https://other.test")


def test_token_user():
    user = TokenUser({"sub": "usr_1", "scope": "a b", "email": "x@y.test"})
    assert user.is_authenticated and not user.is_anonymous and user.is_active
    assert (user.pk, user.get_username(), str(user), user.email) == ("usr_1", "usr_1", "usr_1", "x@y.test")
    assert user.has_scope("a") and user.has_scope("a", "b") and not user.has_scope("c")
    assert not user.has_perm("auth.view_user") and user.get_all_permissions() == set()
    assert user == TokenUser({"sub": "usr_1"}) and hash(user) == hash(TokenUser({"sub": "usr_1"}))
    with pytest.raises(NotImplementedError):
        user.save()
