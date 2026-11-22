"""The browser sign-in: /nine/login, /nine/signup, /nine/callback, /nine/logout, local users."""

from __future__ import annotations

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client

from nine_django.models import NineIdentity
from nine_django.session import PENDING_SESSION_KEY, TOKENS_SESSION_KEY
from nine_django.signals import user_signed_in
from tests.conftest import query_of, sign_in, start_login
from tests.fake_tenant import pkce_challenge

pytestmark = pytest.mark.django_db
User = get_user_model()


def test_login_redirects_to_the_hosted_page_with_pkce_state_and_nonce(client, tenant, nine_config):
    url = start_login(client, return_to="/dashboard")
    assert url.startswith(tenant.issuer + "/oauth/authorize?")
    params = query_of(url)
    assert params["response_type"] == "code"
    assert params["client_id"] == tenant.client_id
    assert params["redirect_uri"] == "http://testserver/nine/callback"
    assert params["scope"] == "openid profile email offline_access orders:read"
    assert params["audience"] == tenant.audience
    assert params["code_challenge_method"] == "S256"
    assert len(params["state"]) >= 20 and len(params["nonce"]) >= 20
    assert "prompt" not in params
    pending = client.session[PENDING_SESSION_KEY][params["state"]]
    assert pkce_challenge(pending["verifier"]) == params["code_challenge"]
    assert pending["return_to"] == "/dashboard"
    assert pending["nonce"] == params["nonce"]


def test_signup_opens_the_sign_up_form(client, tenant, nine_config):
    assert query_of(start_login(client, "/nine/signup"))["prompt"] == "create"
    assert query_of(start_login(client, "/nine/login", screen="signup"))["prompt"] == "create"
    assert "prompt" not in query_of(start_login(client, "/nine/login", screen="bogus"))


def test_login_hint_and_locale(client, tenant, configure):
    params = query_of(start_login(client, login_hint="jane@acme.test"))
    assert params["login_hint"] == "jane@acme.test"
    assert "ui_locales" not in params
    configure(LOCALE="de")
    assert query_of(start_login(client))["ui_locales"] == "de"
    configure(LOCALE="auto")
    from django.utils import translation

    with translation.override("fr"):
        assert query_of(start_login(client))["ui_locales"] == "fr"


def test_full_sign_in_creates_a_local_user_and_logs_in(client, tenant, nine_config):
    tenant.add_user("usr_jane", email="jane@acme.test", email_verified=True, given_name="Jane", family_name="Doe")
    received = []
    user_signed_in.connect(lambda **kw: received.append(kw), weak=False, dispatch_uid="t1")
    try:
        client.get("/whoami")  # a session exists before the sign-in
        before = client.session.session_key
        response = sign_in(client, tenant, "usr_jane", params={"return_to": "/dashboard"})
    finally:
        user_signed_in.disconnect(dispatch_uid="t1")
    assert response.status_code == 302
    assert response["Location"] == "/dashboard"

    user = User.objects.get()
    assert user.username == "jane@acme.test"
    assert (user.email, user.first_name, user.last_name) == ("jane@acme.test", "Jane", "Doe")
    assert not user.has_usable_password()
    identity = NineIdentity.objects.get()
    assert (identity.user, identity.issuer, identity.sub) == (user, tenant.issuer, "usr_jane")
    assert identity.last_login_at is not None

    session = client.session
    assert session.session_key != before, "the session key is cycled at sign-in"
    assert str(session[SESSION_KEY]) == str(user.pk)
    tokens = session[TOKENS_SESSION_KEY]
    assert tokens["refresh_token"].startswith("rt_")
    assert tokens["claims"]["sub"] == "usr_jane"
    assert PENDING_SESSION_KEY not in session or not session[PENDING_SESSION_KEY]

    page = client.get("/dashboard")
    assert page.status_code == 200
    assert page.content.decode() == "hello jane@acme.test sub=usr_jane source=session"

    assert len(received) == 1
    assert received[0]["user"] == user and received[0]["created"] is True
    assert received[0]["claims"]["email"] == "jane@acme.test"
    assert received[0]["tokens"].refresh_token == tokens["refresh_token"]


def test_next_sign_in_reuses_the_identity_and_updates_the_user(client, tenant, nine_config):
    tenant.add_user("usr_jane", email="jane@acme.test", email_verified=True, given_name="Jane")
    sign_in(client, tenant, "usr_jane")
    tenant.users["usr_jane"]["given_name"] = "Janet"
    other = Client()
    assert sign_in(other, tenant, "usr_jane").status_code == 302
    assert User.objects.count() == 1 and NineIdentity.objects.count() == 1
    assert User.objects.get().first_name == "Janet"


def test_update_users_off_keeps_local_fields(client, tenant, configure):
    configure(UPDATE_USERS=False)
    tenant.add_user("usr_jane", email="jane@acme.test", email_verified=True, given_name="Jane")
    sign_in(client, tenant, "usr_jane")
    tenant.users["usr_jane"]["given_name"] = "Janet"
    sign_in(Client(), tenant, "usr_jane")
    assert User.objects.get().first_name == "Jane"


def test_links_an_existing_user_by_verified_email(client, tenant, nine_config):
    existing = User.objects.create_user("jane", "Jane@Acme.test", "local-password")
    tenant.add_user("usr_jane", email="jane@acme.test", email_verified=True)
    assert sign_in(client, tenant, "usr_jane").status_code == 302
    assert User.objects.count() == 1
    assert NineIdentity.objects.get().user == existing
    existing.refresh_from_db()
    assert existing.has_usable_password(), "linking keeps the local password"
    assert client.get("/whoami").json()["user"] == "jane"


def test_does_not_link_by_unverified_email(client, tenant, nine_config):
    existing = User.objects.create_user("jane", "jane@acme.test", "pw")
    tenant.add_user("usr_evil", email="jane@acme.test", email_verified=False)
    assert sign_in(client, tenant, "usr_evil").status_code == 302
    identity = NineIdentity.objects.get()
    assert identity.user != existing
    assert identity.user.username == "usr_evil", "the email is taken as a username, so the 9in id is used"


def test_does_not_link_when_several_users_have_the_email(client, tenant, nine_config):
    User.objects.create_user("a", "jane@acme.test")
    User.objects.create_user("b", "JANE@acme.test")
    tenant.add_user("usr_jane", email="jane@acme.test", email_verified=True)
    sign_in(client, tenant, "usr_jane")
    assert NineIdentity.objects.get().user.username not in ("a", "b")


def test_link_by_email_can_be_turned_off(client, tenant, configure):
    configure(LINK_BY_EMAIL=False)
    existing = User.objects.create_user("jane", "jane@acme.test")
    tenant.add_user("usr_jane", email="jane@acme.test", email_verified=True)
    sign_in(client, tenant, "usr_jane")
    assert NineIdentity.objects.get().user != existing


def test_links_adapter_users_through_the_management_api(client, tenant, nine_config):
    local = User.objects.create_user("alice", "alice@acme.test", "pw")
    tenant.add_user(
        "usr_alice",
        email="alice@acme.test",
        email_verified=False,
        identities=[{"connection": "adapter", "subject": str(local.pk)}],
    )
    assert sign_in(client, tenant, "usr_alice").status_code == 302
    assert NineIdentity.objects.get().user == local
    assert tenant.count("GET", "/api/v1/users/usr_alice") == 1
    # Known now: no second lookup.
    sign_in(Client(), tenant, "usr_alice")
    assert tenant.count("GET", "/api/v1/users/usr_alice") == 1


def test_adapter_linking_is_off_without_an_adapter_secret(client, tenant, configure):
    configure(ADAPTER_SECRET=None)
    local = User.objects.create_user("alice", "alice@acme.test", "pw")
    tenant.add_user("usr_alice", email="alice@acme.test", identities=[{"connection": "adapter", "subject": str(local.pk)}])
    sign_in(client, tenant, "usr_alice")
    assert NineIdentity.objects.get().user != local
    assert tenant.count("GET", "/api/v1/users/usr_alice") == 0


def test_create_users_off_refuses_unknown_users_and_revokes_their_tokens(client, tenant, configure):
    configure(CREATE_USERS=False)
    tenant.add_user("usr_new", email="new@acme.test", email_verified=True)
    response = sign_in(client, tenant, "usr_new")
    assert response.status_code == 403
    assert b"cannot sign in" in response.content
    assert User.objects.count() == 0
    assert SESSION_KEY not in client.session
    assert all(record["revoked"] for record in tenant.refresh_tokens.values())


def test_inactive_users_are_refused(client, tenant, nine_config):
    user = User.objects.create_user("jane", "jane@acme.test", is_active=False)
    NineIdentity.objects.create(user=user, issuer=tenant.issuer, sub="usr_jane")
    assert sign_in(client, tenant, "usr_jane").status_code == 403
    assert SESSION_KEY not in client.session


def test_usernames_do_not_collide(client, tenant, nine_config):
    User.objects.create_user("jane@acme.test")
    tenant.add_user("usr_jane2", email="jane@acme.test", email_verified=False, preferred_username="janed")
    sign_in(client, tenant, "usr_jane2", preferred_username="janed")
    assert NineIdentity.objects.get().user.username == "janed"


def test_user_fields_take_callables(client, tenant, configure):
    configure(
        USER_FIELDS={
            "first_name": lambda claims: claims.get("name", "").split(" ")[0],
            "last_name": "family_name",
            "is_staff": "staff",
        }
    )
    tenant.add_user("usr_jane", email="jane@acme.test", name="Jane Q Doe", family_name="Doe")
    sign_in(client, tenant, "usr_jane")
    user = User.objects.get()
    assert (user.first_name, user.last_name, user.is_staff) == ("Jane", "Doe", False)


def test_unsafe_return_to_values_are_ignored(client, tenant, nine_config):
    for value in ["https://evil.test/", "//evil.test", "/\\evil.test", "javascript:alert(1)", "dashboard", "/ok\nLocation: x"]:
        url = start_login(client, return_to=value)
        assert client.session[PENDING_SESSION_KEY][query_of(url)["state"]]["return_to"] is None, value
    response = sign_in(Client(), tenant, "usr_x", params={"return_to": "https://evil.test/"})
    assert response["Location"] == "/"


def test_next_parameter_and_login_required(client, tenant, nine_config):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert response["Location"] == "/nine/login?next=/dashboard"
    authorize = client.get(response["Location"])["Location"]
    done = client.get("/nine/callback", tenant.authorize(authorize, "usr_jane"))
    assert done["Location"] == "/dashboard"
    assert client.get("/dashboard").status_code == 200


def test_login_redirect_url_setting(client, tenant, configure, settings):
    settings.LOGIN_REDIRECT_URL = "/whoami"
    assert sign_in(client, tenant, "usr_a")["Location"] == "/whoami"
    configure(LOGIN_REDIRECT_URL="/home")
    assert sign_in(Client(), tenant, "usr_b")["Location"] == "/home"


def test_redirect_uri_setting(client, tenant, configure):
    configure(REDIRECT_URI="/custom/callback")
    assert query_of(start_login(client))["redirect_uri"] == "http://testserver/custom/callback"
    configure(REDIRECT_URI="https://app.test/nine/callback")
    url = start_login(client)
    assert query_of(url)["redirect_uri"] == "https://app.test/nine/callback"
    # The token request uses the same redirect URI.
    assert client.get("/nine/callback", tenant.authorize(url, "usr_r")).status_code == 302


def test_https_redirect_uri_behind_a_secure_request(client, tenant, nine_config):
    url = client.get("/nine/login", secure=True)["Location"]
    assert query_of(url)["redirect_uri"] == "https://testserver/nine/callback"


def test_only_the_latest_five_pending_logins_are_kept(client, tenant, nine_config):
    urls = [start_login(client) for _ in range(7)]
    pending = client.session[PENDING_SESSION_KEY]
    assert len(pending) == 5
    assert query_of(urls[0])["state"] not in pending
    # The oldest one is gone: its callback is refused; a recent one works.
    assert client.get("/nine/callback", tenant.authorize(urls[0], "usr_a")).status_code == 400
    assert client.get("/nine/callback", tenant.authorize(urls[-1], "usr_a")).status_code == 302


class TestCallbackRefusals:
    def test_missing_state(self, client, tenant, nine_config):
        url = start_login(client)
        query = tenant.authorize(url, "usr_a")
        del query["state"]
        response = client.get("/nine/callback", query)
        assert response.status_code == 400
        assert b"invalid_state" in response.content
        assert SESSION_KEY not in client.session

    def test_wrong_state(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        response = client.get("/nine/callback", {**query, "state": "forged-state-value-000000"})
        assert response.status_code == 400 and b"invalid_state" in response.content

    def test_state_from_another_browser(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        response = Client().get("/nine/callback", query)
        assert response.status_code == 400 and b"invalid_state" in response.content

    def test_replayed_callback(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        assert client.get("/nine/callback", query).status_code == 302
        replay = client.get("/nine/callback", query)
        assert replay.status_code == 400 and b"invalid_state" in replay.content

    def test_issuer_mismatch(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        response = client.get("/nine/callback", {**query, "iss": "https://evil.test"})
        assert response.status_code == 400 and b"invalid_issuer" in response.content
        assert User.objects.count() == 0

    def test_missing_iss_when_the_server_advertises_it(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        del query["iss"]
        response = client.get("/nine/callback", query)
        assert response.status_code == 400 and b"invalid_issuer" in response.content

    def test_access_denied(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a", error="access_denied")
        response = client.get("/nine/callback", query)
        assert response.status_code == 400
        assert b"access_denied" in response.content and b"Try again" in response.content

    def test_repeated_parameters(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        response = client.get(f"/nine/callback?state={query['state']}&iss={query['iss']}&code={query['code']}&code=other")
        assert response.status_code == 400

    def test_tampered_id_token_nonce(self, client, tenant, nine_config, monkeypatch):
        url = start_login(client)
        query = tenant.authorize(url, "usr_a")
        tenant.codes[query["code"]]["nonce"] = "not-the-nonce"
        response = client.get("/nine/callback", query)
        assert response.status_code in (400, 401)
        assert SESSION_KEY not in client.session

    def test_token_endpoint_failure(self, client, tenant, nine_config):
        query = tenant.authorize(start_login(client), "usr_a")
        tenant.fail_token_endpoint = 503
        response = client.get("/nine/callback", query)
        assert response.status_code == 400
        assert SESSION_KEY not in client.session


def test_logout_revokes_flushes_and_ends_the_9in_session(signed_in, tenant):
    tokens = signed_in.session[TOKENS_SESSION_KEY]
    response = signed_in.get("/nine/logout")
    assert response.status_code == 302
    location = response["Location"]
    assert location.startswith(tenant.issuer + "/oauth/logout?")
    params = query_of(location)
    assert params["id_token_hint"] == tokens["id_token"]
    assert params["post_logout_redirect_uri"] == "http://testserver/"
    assert params["client_id"] == tenant.client_id
    assert tenant.refresh_tokens[tokens["refresh_token"]]["revoked"] is True
    assert SESSION_KEY not in signed_in.session and TOKENS_SESSION_KEY not in signed_in.session
    assert signed_in.get("/whoami").json()["authenticated"] is False


def test_logout_return_to_and_settings(signed_in, tenant, configure):
    response = signed_in.post("/nine/logout", {"return_to": "/bye"})
    assert query_of(response["Location"])["post_logout_redirect_uri"] == "http://testserver/bye"
    response = Client().get("/nine/logout?return_to=https://evil.test/")
    assert query_of(response["Location"])["post_logout_redirect_uri"] == "http://testserver/"
    configure(LOGOUT_REDIRECT_URL="https://app.test/signed-out")
    response = Client().get("/nine/logout")
    assert query_of(response["Location"])["post_logout_redirect_uri"] == "https://app.test/signed-out"
    assert "id_token_hint" not in query_of(response["Location"])


def test_logout_post_needs_a_csrf_token(signed_in, tenant):
    strict = Client(enforce_csrf_checks=True)
    strict.cookies = signed_in.cookies
    assert strict.post("/nine/logout").status_code == 403
    assert signed_in.get("/whoami").json()["authenticated"] is True


def test_logout_still_signs_out_locally_when_9in_is_down(signed_in, tenant):
    tenant.fail_revoke = True
    signed_in.get("/nine/logout")
    assert signed_in.get("/whoami").json()["authenticated"] is False


def test_views_only_answer_their_methods(client, nine_config):
    assert client.post("/nine/login").status_code == 405
    assert client.post("/nine/callback").status_code == 405
    assert client.get("/nine/webhook").status_code == 405


def test_login_is_exempt_from_login_required_middleware(client, tenant, nine_config, settings):
    import django

    if django.VERSION < (5, 1):
        pytest.skip("LoginRequiredMiddleware is Django 5.1+")
    settings.MIDDLEWARE = [*settings.MIDDLEWARE, "django.contrib.auth.middleware.LoginRequiredMiddleware"]
    assert client.get("/whoami")["Location"].startswith("/nine/login")
    response = sign_in(client, tenant, "usr_lr", params={"next": "/whoami"})
    assert response["Location"] == "/whoami"
    assert client.get("/whoami").json()["authenticated"] is True


def test_unverified_emails_are_not_copied(client, tenant, nine_config):
    tenant.add_user("usr_u", email="someone@acme.test", email_verified=False, given_name="Una")
    sign_in(client, tenant, "usr_u")
    user = NineIdentity.objects.get(sub="usr_u").user
    assert (user.email, user.first_name) == ("", "Una")
    tenant.users["usr_u"].update(email="else@acme.test", email_verified=True)
    sign_in(Client(), tenant, "usr_u")
    user.refresh_from_db()
    assert user.email == "else@acme.test"
    tenant.users["usr_u"].update(email="victim@acme.test", email_verified=False)
    sign_in(Client(), tenant, "usr_u")
    user.refresh_from_db()
    assert user.email == "else@acme.test", "an unverified change is not copied"


def test_unique_values_taken_by_another_user_are_left_out(client, tenant, configure):
    configure(USER_FIELDS={"username": "preferred_username", "first_name": "given_name"})
    User.objects.create_user("janed")
    tenant.add_user("usr_j", given_name="Jane")
    response = sign_in(client, tenant, "usr_j", preferred_username="janed")
    assert response.status_code == 302
    user = NineIdentity.objects.get(sub="usr_j").user
    assert user.username == "usr_j" and user.first_name == "Jane"


def test_login_when_9in_is_unreachable(client, configure):
    configure(ISSUER="http://127.0.0.1:9")
    response = client.get("/nine/login")
    assert response.status_code == 503
    assert b"unavailable" in response.content


def test_redirect_settings_accept_url_names(client, tenant, configure):
    configure(LOGIN_REDIRECT_URL="whoami", LOGOUT_REDIRECT_URL="whoami")
    assert sign_in(client, tenant, "usr_n")["Location"] == "/whoami"
    assert query_of(client.get("/nine/logout")["Location"])["post_logout_redirect_uri"] == "http://testserver/whoami"
