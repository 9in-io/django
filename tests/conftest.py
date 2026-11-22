from __future__ import annotations

import os
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import nine
import pytest
from django.core.cache import cache

from nine_django import services
from tests.fake_tenant import FakeTenant

WEBHOOK_SECRET = "whsec_django_tests"
ADAPTER_SECRET = "adsec_django_tests"


@pytest.fixture(scope="session")
def tenant_server():
    server = FakeTenant().start()
    yield server
    server.stop()


@pytest.fixture
def tenant(tenant_server: FakeTenant) -> FakeTenant:
    tenant_server.reset()
    return tenant_server


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch):
    """No NINE_* variables from the environment, empty caches, fresh SDK objects."""
    for name in list(os.environ):
        if name.startswith("NINE_") and not name.startswith(("NINE_E2E", "NINE_TEST_")):
            monkeypatch.delenv(name)
    cache.clear()
    services.reset()
    nine.clear_caches()
    yield
    services.reset()


@pytest.fixture
def nine_config(tenant: FakeTenant, settings: Any) -> dict[str, Any]:
    """9in settings pointing at the fake tenant (a confidential application)."""
    settings.NINE = {
        "ISSUER": tenant.issuer,
        "CLIENT_ID": tenant.client_id,
        "CLIENT_SECRET": tenant.client_secret,
        "AUDIENCE": tenant.audience,
        "SCOPES": ["openid", "profile", "email", "offline_access", "orders:read"],
        "WEBHOOK_SECRET": WEBHOOK_SECRET,
        "ADAPTER_SECRET": ADAPTER_SECRET,
    }
    return settings.NINE


@pytest.fixture
def configure(settings: Any, nine_config: dict[str, Any]):
    """Changes 9in settings for one test: ``configure(CREATE_USERS=False)``."""

    def change(**overrides: Any) -> None:
        settings.NINE = {**settings.NINE, **overrides}

    return change


def query_of(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def start_login(client: Any, path: str = "/nine/login", **params: str) -> str:
    response = client.get(path + ("?" + urlencode(params) if params else ""))
    assert response.status_code == 302, response.content
    return response["Location"]


def sign_in(
    client: Any,
    tenant: FakeTenant,
    sub: str = "usr_jane",
    *,
    path: str = "/nine/login",
    params: dict[str, str] | None = None,
    **claims: Any,
) -> Any:
    """Signs in through /nine/login → (the hosted page) → /nine/callback; returns the callback response."""
    authorize_url = start_login(client, path, **(params or {}))
    callback = tenant.authorize(authorize_url, sub, **claims)
    return client.get("/nine/callback", callback)


@pytest.fixture
def signed_in(client: Any, tenant: FakeTenant, nine_config: dict[str, Any]) -> Any:
    tenant.add_user(
        "usr_jane", email="jane@acme.test", email_verified=True, given_name="Jane", family_name="Doe", name="Jane Doe"
    )
    response = sign_in(client, tenant, "usr_jane")
    assert response.status_code == 302, response.content
    return client
