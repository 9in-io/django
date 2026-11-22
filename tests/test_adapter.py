"""Adapter endpoints (/nine/authenticate, /nine/user, /nine/event) over real Django users."""

from __future__ import annotations

import datetime
import json
import logging
import secrets
from typing import Any

import nine
import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core import mail
from django.test import Client

from nine_django import signals
from nine_django.adapter import DjangoUserAdapter
from tests.conftest import ADAPTER_SECRET
from tests.testapp.models import Profile

pytestmark = pytest.mark.django_db
User = get_user_model()


def call(
    client: Client,
    endpoint: str,
    payload: Any,
    *,
    secret: str = ADAPTER_SECRET,
    path: str | None = None,
    method: str = "POST",
    body: bytes | None = None,
    request_id: str | None = None,
) -> Any:
    path = path or f"/nine/{endpoint}"
    raw = body if body is not None else json.dumps(payload).encode()
    request_id = request_id or "req_" + secrets.token_hex(6)
    signature = nine.sign_payload(secret, "POST", path, raw)
    response = getattr(client, method.lower())(
        f"/nine/{endpoint}", raw, content_type="application/json", HTTP_9IN_SIGNATURE=signature, HTTP_9IN_REQUEST_ID=request_id
    )
    response.request_id = request_id
    response.path_signed = path
    return response


def body(response: Any) -> dict[str, Any]:
    return json.loads(response.content)


def assert_signed(response: Any) -> None:
    assert nine.verify_signature(
        ADAPTER_SECRET, response["9in-signature"], "POST", f"{response.path_signed}#{response.request_id}", response.content
    )


@pytest.fixture
def alice(nine_config):
    user = User.objects.create_user("alice", "Alice@Example.test", "Alice-Password-1", first_name="Alice", last_name="Adapter")
    Profile.objects.create(user=user, phone="+447700900123", email_confirmed=True)
    return user


@pytest.fixture
def bob(nine_config):
    return User.objects.create_user("bob", "bob@example.test", "Bob-Password-1", is_active=False)


def test_authenticate_returns_the_signed_user(client, alice):
    response = call(
        client, "authenticate", {"identifier": {"type": "email", "value": "alice@example.test"}, "password": "Alice-Password-1"}
    )
    assert response.status_code == 200
    assert body(response) == {
        "user": {
            "id": str(alice.pk),
            "email": "Alice@example.test",
            "username": "alice",
            "name": "Alice Adapter",
            "given_name": "Alice",
            "family_name": "Adapter",
            "blocked": False,
        }
    }
    assert_signed(response)


@pytest.mark.parametrize(
    "identifier,password",
    [
        ({"type": "email", "value": "alice@example.test"}, "wrong"),
        ({"type": "email", "value": "nobody@example.test"}, "Alice-Password-1"),
        ({"type": "email", "value": "alice@example.test"}, ""),
        ({"type": "phone", "value": "+447700900123"}, "Alice-Password-1"),  # no phone field configured
    ],
)
def test_wrong_passwords_and_unknown_users_look_the_same(client, alice, identifier, password):
    response = call(client, "authenticate", {"identifier": identifier, "password": password})
    assert response.status_code == 401
    assert body(response) == {"error": "invalid_credentials"}
    assert_signed(response)


@pytest.mark.parametrize("identifier", [{"type": "email", "value": ""}, {"type": "fax", "value": "alice"}, "alice"])
def test_malformed_requests(client, alice, identifier):
    response = call(client, "authenticate", {"identifier": identifier, "password": "Alice-Password-1"})
    assert response.status_code == 400
    assert_signed(response)


def test_usernames_and_emails_are_case_insensitive(client, alice):
    for identifier in ({"type": "username", "value": "ALICE"}, {"type": "email", "value": " alice@EXAMPLE.test "}):
        assert call(client, "authenticate", {"identifier": identifier, "password": "Alice-Password-1"}).status_code == 200


def test_inactive_users_are_blocked_only_with_the_right_password(client, bob):
    right = call(client, "authenticate", {"identifier": {"type": "username", "value": "bob"}, "password": "Bob-Password-1"})
    assert right.status_code == 403 and body(right) == {"error": "blocked"}
    wrong = call(client, "authenticate", {"identifier": {"type": "username", "value": "bob"}, "password": "nope"})
    assert wrong.status_code == 401


def test_unusable_passwords_never_match(client, nine_config):
    user = User.objects.create_user("sso-only", "sso@example.test")
    assert not user.has_usable_password()
    assert (
        call(client, "authenticate", {"identifier": {"type": "username", "value": "sso-only"}, "password": "!"}).status_code
        == 401
    )


def test_duplicate_emails_pick_the_user_whose_password_matches(client, nine_config):
    User.objects.create_user("first", "same@example.test", "one")
    second = User.objects.create_user("second", "SAME@example.test", "two")
    response = call(client, "authenticate", {"identifier": {"type": "email", "value": "same@example.test"}, "password": "two"})
    assert body(response)["user"]["id"] == str(second.pk)


def test_old_password_hashes_are_upgraded(client, nine_config, settings):
    settings.PASSWORD_HASHERS = [
        "django.contrib.auth.hashers.PBKDF2PasswordHasher",
        "django.contrib.auth.hashers.MD5PasswordHasher",
    ]
    user = User.objects.create(username="legacy", email="legacy@example.test", password=make_password("old-pw", hasher="md5"))
    assert (
        call(client, "authenticate", {"identifier": {"type": "username", "value": "legacy"}, "password": "old-pw"}).status_code
        == 200
    )
    user.refresh_from_db()
    assert user.password.startswith("pbkdf2_sha256$")


def test_field_mapping_and_phone_lookups(client, alice, configure):
    configure(
        ADAPTER_FIELDS={
            "phone_number": "profile__phone",
            "phone_number_verified": lambda user: True,
            "email_verified": "profile__email_confirmed",
            "metadata": lambda user: {"plan": "pro"},
            "birthdate": lambda user: datetime.date(1990, 5, 17),
            "name": None,
        }
    )
    response = call(
        client, "authenticate", {"identifier": {"type": "phone", "value": "+447700900123"}, "password": "Alice-Password-1"}
    )
    assert response.status_code == 200
    user = body(response)["user"]
    assert user["phone_number"] == "+447700900123" and user["phone_number_verified"] is True
    assert user["email_verified"] is True
    assert user["metadata"] == {"plan": "pro"}
    assert user["birthdate"] == "1990-05-17"
    assert "name" not in user


def test_allowed_identifiers(client, alice, configure):
    configure(ADAPTER_IDENTIFIERS=["email"])
    assert (
        call(
            client, "authenticate", {"identifier": {"type": "username", "value": "alice"}, "password": "Alice-Password-1"}
        ).status_code
        == 401
    )
    assert (
        call(
            client,
            "authenticate",
            {"identifier": {"type": "email", "value": "alice@example.test"}, "password": "Alice-Password-1"},
        ).status_code
        == 200
    )


def test_find_user_by_id_and_identifier(client, alice, bob):
    by_id = call(client, "user", {"id": str(alice.pk)})
    assert by_id.status_code == 200 and body(by_id)["user"]["email"] == "Alice@example.test"
    assert_signed(by_id)
    by_identifier = call(client, "user", {"identifier": {"type": "email", "value": "ALICE@example.test"}})
    assert body(by_identifier)["user"]["id"] == str(alice.pk)
    blocked = call(client, "user", {"identifier": {"type": "username", "value": "bob"}})
    assert body(blocked)["user"]["blocked"] is True
    for query in ({"id": "999999"}, {"id": "not-a-number"}, {"identifier": {"type": "email", "value": "nobody@example.test"}}):
        missing = call(client, "user", query)
        assert missing.status_code == 404 and body(missing) == {"error": "not_found"}


def test_otp_codes_are_emailed(client, alice):
    expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    event = {
        "id": "evt_otp1",
        "event_type": "otp.requested",
        "created_at": "2026-11-22T08:00:00.000Z",
        "data": {
            "user_id": str(alice.pk),
            "channel": "email",
            "to": "alice@example.test",
            "code": "482913",
            "purpose": "login",
            "expires_at": expires,
        },
    }
    received = []
    signals.otp_requested.connect(lambda sender, **kw: received.append((sender, kw)), weak=False, dispatch_uid="otp")
    try:
        response = call(client, "event", event)
    finally:
        signals.otp_requested.disconnect(dispatch_uid="otp")
    assert 200 <= response.status_code < 300
    assert len(mail.outbox) == 1
    message = mail.outbox[0]
    assert message.to == ["alice@example.test"]
    assert message.subject == "Sign-in code: 482913"
    assert "482913" in message.body and "10 minutes" in message.body
    assert "482913" in message.alternatives[0][0]
    assert message.from_email == "noreply@app.test"
    assert received[0][0] is signals.AdapterEvent
    assert received[0][1]["source"] == "adapter" and received[0][1]["data"]["code"] == "482913"


def test_password_reset_codes_and_from_address(client, alice, configure):
    configure(OTP_FROM_EMAIL="Acme <login@acme.test>")
    event = {
        "id": "evt_otp2",
        "event_type": "otp.requested",
        "created_at": "2026-11-22T08:00:00.000Z",
        "data": {"user_id": "1", "channel": "email", "to": "a@example.test", "code": "111222", "purpose": "password_reset"},
    }
    call(client, "event", event)
    assert mail.outbox[0].subject == "Password reset code: 111222"
    assert mail.outbox[0].from_email == "Acme <login@acme.test>"


def test_otp_email_can_be_turned_off(client, alice, configure):
    configure(OTP_EMAIL=False)
    event = {
        "id": "evt_otp3",
        "event_type": "otp.requested",
        "created_at": "2026-11-22T08:00:00.000Z",
        "data": {"channel": "email", "to": "a@example.test", "code": "1"},
    }
    assert call(client, "event", event).status_code < 300
    assert mail.outbox == []


def test_sms_codes_go_to_your_receiver(client, alice, caplog):
    event = {
        "id": "evt_sms",
        "event_type": "otp.requested",
        "created_at": "2026-11-22T08:00:00.000Z",
        "data": {"channel": "sms", "to": "+447700900123", "code": "999000"},
    }
    with caplog.at_level(logging.WARNING, logger="nine_django"):
        call(client, "event", event)
    assert "SMS" in caplog.text and mail.outbox == []
    sent = []
    signals.otp_requested.connect(lambda **kw: sent.append(kw["data"]["code"]), weak=False, dispatch_uid="sms")
    try:
        caplog.clear()
        call(client, "event", event)
    finally:
        signals.otp_requested.disconnect(dispatch_uid="sms")
    assert sent == ["999000"] and "SMS" not in caplog.text


def test_adapter_events_are_signals(client, alice):
    received = []
    signals.user_updated.connect(lambda sender, **kw: received.append((sender, kw["data"])), weak=False, dispatch_uid="upd")
    try:
        event = {
            "id": "evt_u",
            "event_type": "user.updated",
            "created_at": "2026-11-22T08:00:00.000Z",
            "data": {"user_id": str(alice.pk), "fields": ["name"]},
        }
        assert call(client, "event", event).status_code < 300
    finally:
        signals.user_updated.disconnect(dispatch_uid="upd")
    assert received == [(signals.AdapterEvent, {"user_id": str(alice.pk), "fields": ["name"]})]


def test_refuses_bad_signatures_and_methods(client, alice):
    payload = {"identifier": {"type": "username", "value": "alice"}, "password": "Alice-Password-1"}
    assert call(client, "authenticate", payload, secret="wrong").status_code == 401
    assert call(client, "authenticate", payload, path="/elsewhere/authenticate").status_code == 401
    raw = json.dumps(payload).encode()
    signature = nine.sign_payload(ADAPTER_SECRET, "POST", "/nine/authenticate", raw)
    tampered = client.post(
        "/nine/authenticate",
        raw.replace(b"alice", b"bob"),
        content_type="application/json",
        HTTP_9IN_SIGNATURE=signature,
        HTTP_9IN_REQUEST_ID="r",
    )
    assert tampered.status_code == 401
    unsigned = client.post("/nine/authenticate", raw, content_type="application/json")
    assert unsigned.status_code == 401
    assert client.get("/nine/user").status_code == 405


def test_rotated_adapter_secrets(client, alice, configure):
    configure(ADAPTER_SECRET="adsec_new", ADAPTER_SECRET_PREVIOUS=ADAPTER_SECRET)
    payload = {"id": str(alice.pk)}
    assert call(client, "user", payload, secret=ADAPTER_SECRET).status_code == 200
    response = call(client, "user", payload, secret="adsec_new")
    assert response.status_code == 200


def test_force_script_name_is_part_of_the_signed_path(alice, settings):
    settings.FORCE_SCRIPT_NAME = "/auth"
    client = Client()
    response = call(client, "user", {"id": str(alice.pk)}, path="/auth/nine/user")
    assert response.status_code == 200


def test_custom_adapter_class(client, configure):
    configure(ADAPTER="tests.test_adapter.StaticAdapter")
    response = call(client, "authenticate", {"identifier": {"type": "email", "value": "x@y.test"}, "password": "pw"})
    assert body(response)["user"] == {"id": "static-1", "email": "x@y.test"}


def test_not_configured(settings):
    settings.NINE = {}
    response = call(Client(raise_request_exception=False), "user", {"id": "1"})
    assert response.status_code == 500


class StaticAdapter(DjangoUserAdapter):
    def authenticate(self, identifier: Any, password: str) -> Any:
        return nine.AdapterUser(id="static-1", email=identifier["value"]) if password == "pw" else self.INVALID


def test_users_without_a_password_take_as_long_as_a_wrong_password(client, nine_config, monkeypatch):
    User.objects.create_user("sso-user", "sso@example.test")
    from django.contrib.auth.base_user import AbstractBaseUser

    calls = []
    original = AbstractBaseUser.set_password
    monkeypatch.setattr(AbstractBaseUser, "set_password", lambda self, raw: (calls.append(1), original(self, raw))[1])
    response = call(client, "authenticate", {"identifier": {"type": "username", "value": "sso-user"}, "password": "guess"})
    assert response.status_code == 401
    assert calls == [1], "a dummy hash is computed"
