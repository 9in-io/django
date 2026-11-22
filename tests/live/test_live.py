"""9in-django against live 9in (opt-in): NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e pytest tests/live

- Sign-in through the package's views and 9in's real hosted pages (sandbox: any password),
  local users, middleware refresh with rotation, logout, local sign-out after revocation.
- Real access tokens through @require_token (hybrid, introspect, local), opaque tokens, client
  credentials.
- Real webhook deliveries replayed through /nine/webhook: signals once, eviction of revoked tokens.
- The Management API and `manage.py nine_login_link` with a managed production user.
- 9in's real adapter calls answered from Django users by DjangoUserAdapter.

Test users: dj-<run>…@sandbox.e2e.test (sandbox) and managed-dj-<run>@e2e.9in.test (production),
deleted at the end through the Management API.
"""

from __future__ import annotations

import base64
import json
import os
import time
from io import StringIO
from typing import Any
from urllib.parse import parse_qs, urlsplit

import nine
import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client

from nine_django import get_management_client, get_web_app_auth, services, signals
from nine_django.models import NineIdentity
from nine_django.session import TOKENS_SESSION_KEY

from . import live

pytestmark = [
    pytest.mark.skipif(os.environ.get("NINE_E2E") != "1", reason="live e2e: set NINE_E2E=1 and NINE_E2E_ENV"),
    pytest.mark.django_db,
]
User = get_user_model()
SCOPES = ["openid", "profile", "email", "offline_access", "read:things"]


def claims_of(jwt: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))


def query_of(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


@pytest.fixture(scope="session", autouse=True)
def cleanup():
    """Deletes this run's users from the sandbox and production at the end."""
    yield
    if os.environ.get("NINE_E2E") != "1" or not live.has("SERVER_CLIENT_SECRET"):
        return
    for issuer in (live.env("SANDBOX_ISSUER"), live.env("ISSUER")):
        client = nine.ManagementClient(issuer, live.env("SERVER_CLIENT_ID"), live.env("SERVER_CLIENT_SECRET"))
        for user in client.list_users(query=live.RUN, limit=100).get("users", []):
            if live.RUN in str(user.get("email") or ""):
                try:
                    client.delete_user(user["id"])
                except nine.NineError as error:
                    if error.status != 404:
                        print(f"could not delete a test user: {error.error}")


@pytest.fixture
def sandbox(settings: Any) -> dict[str, Any]:
    """The confidential "E2E Server" application on the sandbox environment."""
    settings.ROOT_URLCONF = "tests.live.urls"
    settings.NINE = {
        "ISSUER": live.env("SANDBOX_ISSUER"),
        "CLIENT_ID": live.env("SERVER_CLIENT_ID"),
        "CLIENT_SECRET": live.env("SERVER_CLIENT_SECRET"),
        "REDIRECT_URI": live.env("SERVER_REDIRECT_URI"),
        "AUDIENCE": live.env("API_AUDIENCE"),
        "SCOPES": SCOPES,
        "WEBHOOK_SECRET": live.env("WEBHOOK_SECRET"),
    }
    return settings.NINE


@pytest.fixture
def production(settings: Any) -> dict[str, Any]:
    settings.ROOT_URLCONF = "tests.live.urls"
    settings.NINE = {
        "ISSUER": live.env("ISSUER"),
        "CLIENT_ID": live.env("SERVER_CLIENT_ID"),
        "CLIENT_SECRET": live.env("SERVER_CLIENT_SECRET"),
        "REDIRECT_URI": live.env("SERVER_REDIRECT_URI"),
        "AUDIENCE": live.env("API_AUDIENCE"),
        "SCOPES": SCOPES,
        "WEBHOOK_SECRET": live.env("WEBHOOK_SECRET"),
    }
    return settings.NINE


def django_sign_in(client: Client, identifier: str, password: str = "any-password", return_to: str = "/dashboard") -> Any:
    """/nine/login → 9in's hosted page → /nine/callback, through the package's views."""
    start = client.get("/nine/login", {"return_to": return_to})
    assert start.status_code == 302
    authorize = start["Location"]
    assert authorize.startswith(services.get_web_app_auth().issuer + "/oauth/authorize?")
    result = live.sign_in(authorize, live.env("SERVER_REDIRECT_URI"), identifier, password)
    assert result["page"] is None, result["page"]
    callback = query_of(result["callback"])
    assert callback["iss"] == services.get_web_app_auth().issuer
    return client.get("/nine/callback", callback)


def bearer(token: str) -> dict[str, str]:
    return {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def test_sandbox_sign_in_refresh_and_logout(client, sandbox):
    email = f"dj-{live.RUN}@sandbox.e2e.test"
    response = django_sign_in(client, email)
    assert response.status_code == 302 and response["Location"] == "/dashboard"
    user = User.objects.get(email=email)
    identity = NineIdentity.objects.get(user=user)
    assert identity.issuer == live.env("SANDBOX_ISSUER") and identity.sub.startswith("usr_")
    assert client.get("/dashboard").content.decode() == f"hello {email}"

    tokens = client.session[TOKENS_SESSION_KEY]
    assert tokens["claims"]["email"] == email and tokens["claims"]["aud"] == live.env("SERVER_CLIENT_ID")
    assert get_web_app_auth().userinfo(tokens["access_token"])["email"] == email

    # The access token works on the API (hybrid: checked locally, then introspected once).
    ok = client.get("/api/things", **bearer(tokens["access_token"])).json()
    assert ok["sub"] == identity.sub and ok["user"] == user.username
    assert client.get("/api/things", **bearer(tokens["access_token"][:-4] + "AAAA")).status_code == 401
    assert client.get("/api/things", **bearer(tokens["id_token"])).status_code == 401

    # The middleware refreshes before expiry and keeps the rotated refresh token.
    session = client.session
    session[TOKENS_SESSION_KEY] = {**tokens, "expires_at": int(time.time()) + 10}
    session.save()
    assert client.get("/dashboard").status_code == 200
    rotated = client.session[TOKENS_SESSION_KEY]
    assert rotated["refresh_token"] != tokens["refresh_token"]
    assert rotated["access_token"] != tokens["access_token"]
    assert rotated["expires_at"] > int(time.time()) + 60

    logout = client.get("/nine/logout")
    location = logout["Location"]
    assert location.startswith(live.env("SANDBOX_ISSUER") + "/oauth/logout?")
    assert query_of(location)["id_token_hint"] == rotated["id_token"]
    assert client.get("/dashboard").status_code == 401
    with pytest.raises(nine.NineError) as refused:
        get_web_app_auth().refresh(nine.TokenSet.from_dict(rotated))
    assert refused.value.error == "invalid_grant"


def test_sandbox_revocation_signs_the_user_out(client, sandbox):
    email = f"dj-{live.RUN}-revoked@sandbox.e2e.test"
    assert django_sign_in(client, email).status_code == 302
    tokens = client.session[TOKENS_SESSION_KEY]
    get_web_app_auth().revoke(tokens["refresh_token"], "refresh_token")
    session = client.session
    session[TOKENS_SESSION_KEY] = {**tokens, "expires_at": int(time.time())}
    session.save()
    assert client.get("/dashboard").status_code == 401, "9in refused the refresh: signed out here too"


def test_sandbox_webhooks_become_signals_once(client, sandbox, settings):
    email = f"dj-{live.RUN}-hooks@sandbox.e2e.test"
    assert django_sign_in(client, email).status_code == 302
    sub = client.session[TOKENS_SESSION_KEY]["claims"]["sub"]
    created = live.wait_for("webhooks", lambda r: r.get("type") == "user.created" and r.get("userId") == sub)
    login = live.wait_for("webhooks", lambda r: r.get("type") == "user.login" and r.get("userId") == sub)

    calls: list[tuple[str, str]] = []
    for signal, name in (
        (signals.user_created, "user_created"),
        (signals.user_login, "user_login"),
        (signals.event_received, "event_received"),
    ):
        signal.connect(
            lambda sender, event, _n=name, **kw: calls.append((_n, event["id"])), weak=False, dispatch_uid=f"live-{name}"
        )
    try:

        def replay(record: dict[str, Any], body: str | None = None) -> int:
            settings.NINE = {**settings.NINE, "WEBHOOK_PATH": record["path"]}
            raw = record["raw"] if body is None else body
            return (
                Client()
                .post("/nine/webhook", raw, content_type="application/json", HTTP_9IN_SIGNATURE=record["signature"])
                .status_code
            )

        assert replay(created) == 204
        assert replay(login) == 204
        assert replay(login) == 204, "a redelivery is acknowledged"
        assert replay(login, login["raw"].replace("user.login", "user.deleted")) == 401
    finally:
        for name in ("user_created", "user_login", "event_received"):
            getattr(signals, name).disconnect(dispatch_uid=f"live-{name}")
    assert calls == [
        ("user_created", created["id"]),
        ("event_received", created["id"]),
        ("user_login", login["id"]),
        ("event_received", login["id"]),
    ]
    event = json.loads(created["raw"])
    assert event["environment"] == "sandbox" and event["data"]["user"]["email"] == email


def test_hybrid_verification_drops_a_revoked_token_when_the_webhook_arrives(client, sandbox, settings):
    email = f"dj-{live.RUN}-hybrid@sandbox.e2e.test"
    assert django_sign_in(client, email).status_code == 302
    access = client.session[TOKENS_SESSION_KEY]["access_token"]
    jti = claims_of(access)["jti"]
    api = Client()
    assert api.get("/api/things", **bearer(access)).status_code == 200
    get_web_app_auth().revoke(access, "access_token")
    assert api.get("/api/things", **bearer(access)).status_code == 200, "the cached answer stands until 9in says otherwise"
    revoked = live.wait_for(
        "webhooks", lambda r: r.get("type") == "token.revoked" and json.loads(r["raw"]).get("data", {}).get("jti") == jti
    )
    settings.NINE = {**settings.NINE, "WEBHOOK_PATH": revoked["path"]}
    assert (
        Client()
        .post("/nine/webhook", revoked["raw"], content_type="application/json", HTTP_9IN_SIGNATURE=revoked["signature"])
        .status_code
        == 204
    )
    assert api.get("/api/things", **bearer(access)).status_code == 401
    # Introspect mode sees it at once; local mode cannot.
    settings.NINE = {**settings.NINE, "TOKEN_VERIFICATION": "introspect"}
    assert api.get("/api/things", **bearer(access)).status_code == 401
    settings.NINE = {**settings.NINE, "TOKEN_VERIFICATION": "local"}
    assert api.get("/api/things", **bearer(access)).status_code == 200


def test_client_credentials_tokens_on_the_api(sandbox):
    token = get_web_app_auth().client_credentials(audience=live.env("API_AUDIENCE"), scope="read:things")
    data = Client().get("/api/things", **bearer(token["access_token"])).json()
    assert data["client_id"] == live.env("SERVER_CLIENT_ID") and data["user"] == data["sub"]


def test_opaque_tokens_are_introspected(client, production, settings):
    management = get_management_client()
    email = f"managed-dj-{live.RUN}-opaque@e2e.9in.test"
    password = f"Dj-{live.RUN}-Password!"
    management.create_user({"email": email, "password": password, "email_verified": True})
    settings.NINE = {
        **settings.NINE,
        "AUDIENCE": live.env("OPAQUE_API_AUDIENCE"),
        "SCOPES": ["openid", "email", "offline_access"],
    }
    assert django_sign_in(client, email, password).status_code == 302
    access = client.session[TOKENS_SESSION_KEY]["access_token"]
    assert access.startswith("9in_at_")
    assert Client().get("/api/opaque", **bearer(access)).json()["sub"] == client.session[TOKENS_SESSION_KEY]["claims"]["sub"]
    settings.NINE = {**settings.NINE, "TOKEN_VERIFICATION": "local"}
    assert Client().get("/api/opaque", **bearer(access)).status_code == 401


def test_production_management_api_login_links_and_linking(client, production):
    management = get_management_client()
    email = f"managed-dj-{live.RUN}@e2e.9in.test"
    password = f"Dj-{live.RUN}-Password!"
    created = management.create_user(
        {"email": email, "password": password, "name": "Managed Django", "email_verified": True, "metadata": {"run": live.RUN}}
    )
    assert created["email"] == email and created["blocked"] is False
    assert management.find_user_by_email(email.upper())["id"] == created["id"]
    assert management.get_user(created["id"])["user"]["email"] == email
    assert management.update_user(created["id"], {"name": "Renamed Django"})["name"] == "Renamed Django"
    assert management.find_user_by_email(f"nobody-{live.RUN}@e2e.9in.test") is None

    # An existing local user with the same (verified) email is linked, not duplicated.
    local = User.objects.create_user("managed-local", email, "local-password")
    assert django_sign_in(client, email, password).status_code == 302
    assert NineIdentity.objects.get().user == local and User.objects.count() == 1
    sid = client.session[TOKENS_SESSION_KEY]["claims"]["sid"]
    sessions = management.list_user_sessions(created["id"])
    assert sid in [s["sid"] for s in (sessions.get("sessions", sessions) if isinstance(sessions, dict) else sessions)]

    out, err = StringIO(), StringIO()
    call_command("nine_login_link", email, "--return-to", live.env("SERVER_REDIRECT_URI"), "--ttl", "300", stdout=out, stderr=err)
    link = out.getvalue().strip()
    assert link.startswith(live.env("ISSUER") + "/") and err.getvalue().startswith("Expires ")
    assert live.Browser().request("GET", link)[0] == 200, "a GET alone (a mail scanner) does not use the link up"
    call_command("nine_login_link", "managed-local", stdout=StringIO(), stderr=StringIO())

    management.revoke_session(sid)
    access = client.session[TOKENS_SESSION_KEY]["access_token"]
    from django.conf import settings

    settings.NINE = {**settings.NINE, "TOKEN_VERIFICATION": "introspect"}
    assert Client().get("/api/things", **bearer(access)).status_code == 401
    session = client.session
    session[TOKENS_SESSION_KEY] = {**session[TOKENS_SESSION_KEY], "expires_at": int(time.time())}
    session.save()
    assert client.get("/dashboard").status_code == 401, "the 9in session ended: signed out here too"
    management.delete_user(created["id"])
    assert management.find_user_by_email(email) is None


def test_answers_nines_real_adapter_requests_from_django_users(settings):
    alice = User.objects.create_user(
        "alice", "alice@adapter.e2e.test", "Alice-Password-1", first_name="Alice", last_name="Adapter"
    )
    User.objects.create_user("bob", "bob@adapter.e2e.test", "Bob-Password-1", is_active=False)
    settings.ROOT_URLCONF = "tests.live.urls"
    settings.NINE = {"ADAPTER_SECRET": live.env("ADAPTER_SECRET")}

    since = int(time.time() * 1000)
    adapter_auth = nine.WebAppAuth(
        live.env("ADAPTER_ISSUER"), live.env("ADAPTER_SPA_CLIENT_ID"), redirect_uri=live.env("ADAPTER_SPA_REDIRECT_URI")
    )
    wrong = f"dj-{live.RUN}-wrong-password"
    for who, password in (
        ("alice@adapter.e2e.test", "Alice-Password-1"),
        ("alice@adapter.e2e.test", wrong),
        ("bob@adapter.e2e.test", "Bob-Password-1"),
    ):
        live.sign_in(adapter_auth.create_login().url, live.env("ADAPTER_SPA_REDIRECT_URI"), who, password)

    def raw(who: str, needle: str) -> dict[str, Any]:
        return live.wait_for(
            "adapter-raw",
            lambda r: r["at"] >= since and r["path"].endswith("/authenticate") and who in r["body"] and needle in r["body"],
        )

    def replay(record: dict[str, Any], body: str | None = None) -> Any:
        base = record["path"][: -len("/authenticate")]
        return Client().post(
            "/authenticate",
            record["body"] if body is None else body,
            content_type="application/json",
            SCRIPT_NAME=base,
            HTTP_9IN_SIGNATURE=record["signature"],
            HTTP_9IN_REQUEST_ID=record["requestId"],
        )

    ok_record = raw("alice@", "Alice-Password-1")
    ok = replay(ok_record)
    assert ok.status_code == 200
    user = json.loads(ok.content)["user"]
    assert {k: user[k] for k in ("id", "email", "name")} == {
        "id": str(alice.pk),
        "email": "alice@adapter.e2e.test",
        "name": "Alice Adapter",
    }
    assert nine.verify_signature(
        live.env("ADAPTER_SECRET"), ok["9in-signature"], "POST", f"{ok_record['path']}#{ok_record['requestId']}", ok.content
    )
    assert replay(raw("alice@", wrong)).status_code == 401
    assert replay(raw("bob@", "Bob-Password-1")).status_code == 403
    assert replay(ok_record, ok_record["body"].replace("alice@", "bob@")).status_code == 401
