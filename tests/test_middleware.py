"""NineMiddleware: request.nine, refresh with rotation, local sign-out on revocation."""

from __future__ import annotations

import time

import nine
import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import SESSION_KEY
from django.test import AsyncClient

from nine_django.session import TOKENS_SESSION_KEY

pytestmark = pytest.mark.django_db


def aget(client, *args, **kwargs):
    async def run():
        return await client.get(*args, **kwargs)

    return async_to_sync(run)()


def expire(client, seconds_left: int = 0) -> dict:
    session = client.session
    tokens = dict(session[TOKENS_SESSION_KEY])
    tokens["expires_at"] = int(time.time()) + seconds_left
    session[TOKENS_SESSION_KEY] = tokens
    session.save()
    return tokens


def test_anonymous_requests_have_an_empty_state(client, nine_config):
    data = client.get("/whoami").json()
    assert data == {"authenticated": False, "user": None, "source": None, "sub": None}


def test_signed_in_requests_expose_claims(signed_in):
    data = signed_in.get("/whoami").json()
    assert data == {"authenticated": True, "user": "jane@acme.test", "source": "session", "sub": "usr_jane"}


def test_fresh_tokens_are_not_refreshed(signed_in, tenant):
    before = tenant.count("POST", "/oauth/token")
    signed_in.get("/whoami")
    assert tenant.count("POST", "/oauth/token") == before


def test_refreshes_before_expiry_and_keeps_the_rotated_refresh_token(signed_in, tenant):
    old = expire(signed_in, seconds_left=30)  # within the 60 s leeway
    signed_in.get("/whoami")
    new = signed_in.session[TOKENS_SESSION_KEY]
    assert new["refresh_token"] != old["refresh_token"]
    assert new["access_token"] != old["access_token"]
    assert new["expires_at"] > old["expires_at"]
    assert new["claims"]["sub"] == "usr_jane"
    assert tenant.refresh_tokens[old["refresh_token"]]["used_at"] is not None
    # The next request uses the new token without refreshing again.
    count = tenant.count("POST", "/oauth/token")
    signed_in.get("/whoami")
    assert tenant.count("POST", "/oauth/token") == count


def test_refresh_without_a_new_id_token_keeps_the_claims(signed_in, tenant):
    tenant.refresh_returns_id_token = False
    old = expire(signed_in)
    signed_in.get("/whoami")
    new = signed_in.session[TOKENS_SESSION_KEY]
    assert new["refresh_token"] != old["refresh_token"]
    assert new["id_token"] == old["id_token"]
    assert new["claims"]["email"] == "jane@acme.test"


def test_revoked_refresh_token_signs_the_user_out(signed_in, tenant):
    tokens = expire(signed_in)
    tenant.revoke(tokens["refresh_token"])
    data = signed_in.get("/whoami").json()
    assert data["authenticated"] is False and data["source"] is None
    assert SESSION_KEY not in signed_in.session
    assert signed_in.get("/dashboard").status_code == 302


def test_ended_session_signs_the_user_out(signed_in, tenant):
    tokens = expire(signed_in)
    tenant.revoke_session(tokens["claims"]["sid"])
    assert signed_in.get("/whoami").json()["authenticated"] is False


def test_9in_unreachable_keeps_the_session(signed_in, tenant):
    tokens = expire(signed_in, seconds_left=20)
    tenant.fail_token_endpoint = 503
    data = signed_in.get("/whoami").json()
    assert data["authenticated"] is True and data["source"] == "session"
    assert signed_in.session[TOKENS_SESSION_KEY]["refresh_token"] == tokens["refresh_token"]
    # Once 9in is back, the next request refreshes.
    tenant.fail_token_endpoint = None
    signed_in.get("/whoami")
    assert signed_in.session[TOKENS_SESSION_KEY]["refresh_token"] != tokens["refresh_token"]


def test_access_token_refreshes_lazily_and_raises_when_9in_is_down(signed_in, tenant):
    first = signed_in.get("/token").json()["access_token"]
    assert first == signed_in.session[TOKENS_SESSION_KEY]["access_token"]
    tenant.fail_token_endpoint = 503
    expire(signed_in, seconds_left=-10)
    with pytest.raises(nine.NineError):
        signed_in.get("/token")


def test_expired_tokens_without_a_refresh_token_keep_the_django_login(signed_in, tenant):
    session = signed_in.session
    tokens = dict(session[TOKENS_SESSION_KEY])
    tokens["refresh_token"] = None
    tokens["expires_at"] = int(time.time()) - 5
    session[TOKENS_SESSION_KEY] = tokens
    session.save()
    assert signed_in.get("/whoami").json()["authenticated"] is True
    assert signed_in.get("/token").json()["access_token"] is None


def test_tokens_without_a_django_login_are_dropped(signed_in):
    session = signed_in.session
    del session[SESSION_KEY]
    session.save()
    signed_in.get("/whoami")
    assert TOKENS_SESSION_KEY not in signed_in.session


def test_unreadable_tokens_are_dropped(signed_in):
    session = signed_in.session
    session[TOKENS_SESSION_KEY] = {"nonsense": True}
    session.save()
    assert signed_in.get("/whoami").json()["source"] is None
    assert TOKENS_SESSION_KEY not in signed_in.session


def test_refresh_leeway_setting(signed_in, tenant, configure):
    configure(REFRESH_LEEWAY=600)
    before = signed_in.session[TOKENS_SESSION_KEY]["refresh_token"]
    expire(signed_in, seconds_left=300)
    signed_in.get("/whoami")
    assert signed_in.session[TOKENS_SESSION_KEY]["refresh_token"] != before


def test_works_under_asgi(signed_in, tenant):
    client = AsyncClient()
    client.cookies = signed_in.cookies
    data = aget(client, "/whoami").json()
    assert data["source"] == "session" and data["sub"] == "usr_jane"
    assert aget(client, "/api/async-orders").status_code == 401


def test_refresh_under_asgi(signed_in, tenant):
    old = expire(signed_in)
    client = AsyncClient()
    client.cookies = signed_in.cookies
    assert aget(client, "/whoami").json()["authenticated"] is True
    assert signed_in.session[TOKENS_SESSION_KEY]["refresh_token"] != old["refresh_token"]
    tenant.revoke(signed_in.session[TOKENS_SESSION_KEY]["refresh_token"])
    expire(signed_in)
    assert aget(client, "/whoami").json()["authenticated"] is False
