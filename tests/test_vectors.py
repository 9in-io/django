"""The reference vectors every 9in SDK must pass (sso-sdk/php/tests/SignatureTest.php, RFC 7636),
checked through the SDK and through this package's adapter endpoint."""

from __future__ import annotations

import json

import nine
import pytest
from django.test import Client

from tests.fake_tenant import pkce_challenge

pytestmark = pytest.mark.django_db

SECRET = "adapter_secret_test"
BODY = '{"identifier":{"type":"email","value":"jane@acme.com"},"password":"hunter2"}'
REQUEST_VECTOR = "t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c"
RESPONSE_VECTOR = "t=1762682400,v1=1b9fb41e87bb256836ea5d5d6600270b77578ffd166d84a2cf35ab9841b3585a"


def test_signature_reference_vectors():
    assert nine.sign_payload(SECRET, "post", "/nine/authenticate", BODY, 1762682400) == REQUEST_VECTOR
    assert nine.sign_payload(SECRET, "POST", "/nine/authenticate#req_123", '{"user":{"id":"42"}}', 1762682400) == RESPONSE_VECTOR
    forever = 10**10
    assert nine.verify_signature(
        SECRET, RESPONSE_VECTOR, "POST", "/nine/authenticate#req_123", '{"user":{"id":"42"}}', tolerance=forever
    )
    assert not nine.verify_signature(
        SECRET, RESPONSE_VECTOR, "POST", "/nine/authenticate#req_124", '{"user":{"id":"42"}}', tolerance=forever
    )


def test_the_adapter_endpoint_accepts_the_reference_request(settings):
    settings.NINE = {"ADAPTER_SECRET": SECRET, "ADAPTER_TOLERANCE": 10**10, "ADAPTER": "tests.test_vectors.JaneAdapter"}
    response = Client().post(
        "/nine/authenticate",
        BODY,
        content_type="application/json",
        HTTP_9IN_SIGNATURE=REQUEST_VECTOR,
        HTTP_9IN_REQUEST_ID="req_123",
    )
    assert response.status_code == 200
    assert json.loads(response.content) == {"user": {"id": "42"}}
    assert nine.verify_signature(SECRET, response["9in-signature"], "POST", "/nine/authenticate#req_123", response.content)
    # The same request, signed for another path or with another secret, is refused.
    settings.NINE = {**settings.NINE, "ADAPTER_SECRET": "another-secret"}
    refused = Client().post(
        "/nine/authenticate",
        BODY,
        content_type="application/json",
        HTTP_9IN_SIGNATURE=REQUEST_VECTOR,
        HTTP_9IN_REQUEST_ID="req_123",
    )
    assert refused.status_code == 401


def test_the_reference_request_is_too_old_for_the_default_tolerance(settings):
    settings.NINE = {"ADAPTER_SECRET": SECRET, "ADAPTER": "tests.test_vectors.JaneAdapter"}
    response = Client().post(
        "/nine/authenticate",
        BODY,
        content_type="application/json",
        HTTP_9IN_SIGNATURE=REQUEST_VECTOR,
        HTTP_9IN_REQUEST_ID="req_123",
    )
    assert response.status_code == 401


def test_pkce_rfc7636_example():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert nine.code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class JaneAdapter(nine.Adapter):
    def authenticate(self, identifier, password):
        if identifier == {"type": "email", "value": "jane@acme.com"} and password == "hunter2":
            return nine.AdapterUser(id="42")
        return self.INVALID

    def find_user(self, query):
        return None
