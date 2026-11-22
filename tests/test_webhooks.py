"""/nine/webhook: signatures, process-once with the Django cache, signals."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

import nine
import pytest
from django.test import Client

from nine_django import signals
from tests.conftest import WEBHOOK_SECRET

pytestmark = pytest.mark.django_db


def make_event(
    event_type: str = "user.created", data: dict[str, Any] | None = None, event_id: str | None = None
) -> dict[str, Any]:
    return {
        "id": event_id or "evt_" + secrets.token_hex(8),
        "event_type": event_type,
        "created_at": "2026-11-22T08:00:00.000Z",
        "tenant": "tnt_test",
        "environment": "production",
        "data": data if data is not None else {"user": {"id": "usr_1", "email": "jane@acme.test"}},
    }


def post_event(
    client: Client,
    event_type: str = "user.created",
    data: dict[str, Any] | None = None,
    *,
    event: dict[str, Any] | None = None,
    secret: str = WEBHOOK_SECRET,
    path: str = "/nine/webhook",
    timestamp: int | None = None,
    body: bytes | None = None,
) -> Any:
    event = event or make_event(event_type, data)
    raw = body if body is not None else json.dumps(event).encode()
    signature = nine.sign_payload(secret, "POST", path, raw, timestamp)
    return client.post("/nine/webhook", raw, content_type="application/json", HTTP_9IN_SIGNATURE=signature)


class Recorder:
    def __init__(self, *sigs: Any) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.sigs = sigs or (signals.event_received,)
        for signal in self.sigs:
            signal.connect(self._make(signal), weak=False, dispatch_uid=f"rec-{id(self)}-{id(signal)}")

    def _make(self, signal: Any):
        def receive(sender: Any, **kwargs: Any) -> None:
            self.calls.append((self._name(signal), {"sender": sender, **kwargs}))

        return receive

    @staticmethod
    def _name(signal: Any) -> str:
        for name in dir(signals):
            if getattr(signals, name) is signal:
                return name
        return "?"

    def close(self) -> None:
        for signal in self.sigs:
            signal.disconnect(dispatch_uid=f"rec-{id(self)}-{id(signal)}")


@pytest.fixture
def recorder():
    made: list[Recorder] = []

    def make(*sigs: Any) -> Recorder:
        r = Recorder(*sigs)
        made.append(r)
        return r

    yield make
    for r in made:
        r.close()


def test_verified_events_send_their_signal_then_the_catch_all(client, nine_config, recorder):
    rec = recorder(signals.user_created, signals.user_deleted, signals.event_received)
    event = make_event("user.created")
    response = post_event(client, event=event)
    assert response.status_code == 204
    assert [name for name, _ in rec.calls] == ["user_created", "event_received"]
    kwargs = rec.calls[0][1]
    assert kwargs["sender"] is signals.Webhook
    assert kwargs["event"] == event
    assert kwargs["event_type"] == "user.created"
    assert kwargs["data"] == event["data"]
    assert kwargs["source"] == "webhook"


@pytest.mark.parametrize("event_type", signals.EVENT_TYPES)
def test_every_event_type_has_a_signal(client, nine_config, recorder, event_type):
    signal = signals.signal_for(event_type)
    assert getattr(signals, event_type.replace(".", "_")) is signal
    rec = recorder(signal)
    assert post_event(client, event_type, {"user": None}).status_code == 204
    assert len(rec.calls) == 1


def test_unknown_event_types(client, nine_config, recorder):
    rec = recorder(signals.event_received)
    future = signals.signal_for("user.teleported")
    seen = []
    future.connect(lambda **kw: seen.append(kw["event_type"]), weak=False, dispatch_uid="future")
    try:
        assert post_event(client, "user.teleported", {}).status_code == 204
    finally:
        future.disconnect(dispatch_uid="future")
    assert seen == ["user.teleported"] and len(rec.calls) == 1


def test_each_event_is_processed_once(client, nine_config, recorder):
    rec = recorder()
    event = make_event()
    for _ in range(3):
        assert post_event(client, event=event).status_code == 204
    assert len(rec.calls) == 1


def test_a_failing_receiver_releases_the_event_for_the_retry(nine_config, recorder):
    rec = recorder()
    attempts = []

    def flaky(**kwargs: Any) -> None:
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("database down")

    signals.user_created.connect(flaky, weak=False, dispatch_uid="flaky")
    try:
        client = Client(raise_request_exception=False)
        event = make_event()
        assert post_event(client, event=event).status_code == 500
        assert post_event(client, event=event).status_code == 204
        assert post_event(client, event=event).status_code == 204
    finally:
        signals.user_created.disconnect(dispatch_uid="flaky")
    assert len(attempts) == 2
    assert len(rec.calls) == 1, "the catch-all runs once, after the specific receivers succeeded"


def test_a_concurrent_duplicate_gets_409(client, nine_config):
    event = make_event()
    inner: list[int] = []

    def redeliver(**kwargs: Any) -> None:
        if not inner:
            inner.append(post_event(Client(), event=event).status_code)

    signals.user_created.connect(redeliver, weak=False, dispatch_uid="redeliver")
    try:
        assert post_event(client, event=event).status_code == 204
    finally:
        signals.user_created.disconnect(dispatch_uid="redeliver")
    assert inner == [409]
    response = post_event(client, event=event)
    assert response.status_code == 204


def test_dedupe_can_be_turned_off(client, configure, recorder):
    configure(WEBHOOK_DEDUPE=False)
    rec = recorder()
    event = make_event()
    post_event(client, event=event)
    post_event(client, event=event)
    assert len(rec.calls) == 2


@pytest.mark.parametrize(
    "case", ["wrong secret", "tampered body", "other path", "no signature", "too old", "from the future", "malformed"]
)
def test_refused_signatures(client, nine_config, recorder, case):
    rec = recorder()
    event = make_event()
    raw = json.dumps(event).encode()
    if case == "wrong secret":
        response = post_event(client, event=event, secret="whsec_wrong")
    elif case == "tampered body":
        signature = nine.sign_payload(WEBHOOK_SECRET, "POST", "/nine/webhook", raw)
        response = client.post(
            "/nine/webhook",
            raw.replace(b"user.created", b"user.deleted"),
            content_type="application/json",
            HTTP_9IN_SIGNATURE=signature,
        )
    elif case == "other path":
        response = post_event(client, event=event, path="/elsewhere")
    elif case == "no signature":
        response = client.post("/nine/webhook", raw, content_type="application/json")
    elif case == "too old":
        response = post_event(client, event=event, timestamp=int(time.time()) - 301)
    elif case == "from the future":
        response = post_event(client, event=event, timestamp=int(time.time()) + 301)
    else:
        response = client.post("/nine/webhook", raw, content_type="application/json", HTTP_9IN_SIGNATURE="v1=abc,t=x")
    assert response.status_code == 401, case
    assert response.json() == {"error": "invalid_signature"}
    assert rec.calls == []


def test_not_an_event(client, nine_config):
    response = post_event(client, body=b'{"hello": "world"}')
    assert response.status_code == 400


def test_rotated_secrets(client, configure, recorder):
    rec = recorder()
    configure(WEBHOOK_SECRET="whsec_new", WEBHOOK_SECRET_PREVIOUS=WEBHOOK_SECRET)
    assert post_event(client, secret=WEBHOOK_SECRET).status_code == 204
    assert post_event(client, secret="whsec_new").status_code == 204
    configure(WEBHOOK_SECRET="whsec_a,whsec_b", WEBHOOK_SECRET_PREVIOUS=None)
    assert post_event(client, secret="whsec_b").status_code == 204
    assert post_event(client, secret=WEBHOOK_SECRET).status_code == 401
    assert len(rec.calls) == 3


def test_secret_from_the_environment(client, tenant, settings, monkeypatch):
    settings.NINE = {"ISSUER": tenant.issuer}
    monkeypatch.setenv("NINE_WEBHOOK_SECRET", "whsec_env")
    assert post_event(client, secret="whsec_env").status_code == 204


def test_webhook_path_behind_a_rewriting_proxy(client, configure):
    configure(WEBHOOK_PATH="/hooks/9in")
    assert post_event(client, path="/hooks/9in").status_code == 204
    assert post_event(client).status_code == 401


def test_not_configured(settings):
    settings.NINE = {}
    response = post_event(Client())
    assert response.status_code == 500
    assert response.json() == {"error": "webhook_not_configured"}


def test_works_without_an_issuer(settings, recorder):
    settings.NINE = {"WEBHOOK_SECRET": WEBHOOK_SECRET}
    rec = recorder()
    assert post_event(Client(), "token.revoked", {"jti": "x", "user": None}).status_code == 204
    assert len(rec.calls) == 1


def test_no_csrf_token_needed(nine_config):
    assert post_event(Client(enforce_csrf_checks=True)).status_code == 204
