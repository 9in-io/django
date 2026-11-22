"""Settings, the cache adapter, system checks, migrations and the nine_login_link command."""

from __future__ import annotations

from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from nine_django import checks, get_management_client, get_token_verifier, get_web_app_auth, services
from nine_django.cache import DjangoCache
from nine_django.conf import nine_settings
from nine_django.models import NineIdentity

User = get_user_model()


class TestSettings:
    def test_defaults(self, settings):
        settings.NINE = {}
        assert nine_settings.ISSUER is None
        assert tuple(nine_settings.SCOPES) == ("openid", "profile", "email", "offline_access")
        assert nine_settings.TOKEN_CACHE_TTL == 300
        assert nine_settings.login_redirect_url == "/" and nine_settings.logout_redirect_url == "/"
        with pytest.raises(AttributeError):
            nine_settings.NOT_A_SETTING  # noqa: B018

    def test_environment_and_the_nine_dict(self, settings, monkeypatch):
        settings.NINE = {}
        monkeypatch.setenv("NINE_ISSUER", "https://acme.9in.io")
        monkeypatch.setenv("NINE_CLIENT_ID", "app_env")
        monkeypatch.setenv("NINE_ALLOW_INSECURE_ISSUER", "true")
        monkeypatch.setenv("NINE_TOKEN_CACHE_TTL", "60")
        monkeypatch.setenv("NINE_LOGOUT_REDIRECT_URI", "https://acme.test/bye")
        monkeypatch.setenv("NINE_AUDIENCE", "")
        assert nine_settings.ISSUER == "https://acme.9in.io"
        assert nine_settings.ALLOW_INSECURE_ISSUER is True
        assert nine_settings.TOKEN_CACHE_TTL == 60
        assert nine_settings.AUDIENCE is None, "empty means unset"
        assert nine_settings.logout_redirect_url == "https://acme.test/bye"
        settings.NINE = {"CLIENT_ID": "app_dict"}
        assert nine_settings.CLIENT_ID == "app_dict", "the NINE dict wins"

    def test_derived_values(self, settings):
        settings.NINE = {
            "AUDIENCE": "https://a",
            "CLIENT_ID": "app",
            "CLIENT_SECRET": "s",
            "WEBHOOK_SECRET": "a, b",
            "WEBHOOK_SECRET_PREVIOUS": "c",
        }
        assert nine_settings.api_audience == "https://a"
        assert nine_settings.management_credentials == ("app", "s")
        assert nine_settings.webhook_secrets == ["a", "b", "c"]
        settings.NINE = {
            **settings.NINE,
            "API_AUDIENCE": "https://b",
            "MANAGEMENT_CLIENT_ID": "m2m",
            "MANAGEMENT_CLIENT_SECRET": "ms",
        }
        assert nine_settings.api_audience == "https://b"
        assert nine_settings.management_credentials == ("m2m", "ms")
        settings.LOGIN_REDIRECT_URL = "/after"
        settings.LOGOUT_REDIRECT_URL = "/bye"
        assert (nine_settings.login_redirect_url, nine_settings.logout_redirect_url) == ("/after", "/bye")

    def test_nine_must_be_a_dict(self, settings):
        settings.NINE = ["nope"]
        with pytest.raises(ImproperlyConfigured):
            nine_settings.ISSUER  # noqa: B018

    def test_services_need_configuration(self, settings):
        settings.NINE = {}
        for get in (get_web_app_auth, get_token_verifier, get_management_client):
            with pytest.raises(ImproperlyConfigured):
                get()

    def test_insecure_issuers_are_refused(self, settings):
        settings.NINE = {"ISSUER": "http://acme.test", "CLIENT_ID": "app"}
        with pytest.raises(Exception) as raised:
            get_web_app_auth()
        assert getattr(raised.value, "error", None) == "insecure_issuer"
        settings.NINE = {"ISSUER": "http://acme.test", "CLIENT_ID": "app", "ALLOW_INSECURE_ISSUER": True}
        assert get_web_app_auth().issuer == "http://acme.test"
        settings.NINE = {"ISSUER": "https://acme.test/", "CLIENT_ID": "app"}
        assert get_web_app_auth().issuer == "https://acme.test"

    def test_services_are_shared_and_rebuilt_when_settings_change(self, settings, tenant):
        settings.NINE = {"ISSUER": tenant.issuer, "CLIENT_ID": "app"}
        first = get_web_app_auth()
        assert get_web_app_auth() is first
        settings.NINE = {"ISSUER": tenant.issuer, "CLIENT_ID": "other"}
        assert get_web_app_auth() is not first and get_web_app_auth().client_id == "other"

    def test_http_client_setting(self, settings, tenant):
        import nine

        client = nine.UrllibHttpClient()
        settings.NINE = {"ISSUER": tenant.issuer, "CLIENT_ID": "app", "HTTP_CLIENT": client}
        assert services.get_http_client() is client
        settings.NINE = {"ISSUER": tenant.issuer, "CLIENT_ID": "app", "HTTP_CLIENT": "nine.UrllibHttpClient"}
        assert isinstance(services.get_http_client(), nine.UrllibHttpClient)

    def test_token_verification_mode_is_checked(self, settings, tenant):
        settings.NINE = {"ISSUER": tenant.issuer, "TOKEN_VERIFICATION": "sometimes"}
        with pytest.raises(ImproperlyConfigured):
            get_token_verifier()


class TestCache:
    def test_protocol(self):
        cache = DjangoCache()
        cache.set("a", {"x": 1}, 60)
        assert cache.get("a") == {"x": 1}
        assert caches["default"].get("nine:a") == {"x": 1}
        assert cache.add("a", 2, 60) is False
        assert cache.add("b", 2, None) is True and cache.get("b") == 2
        cache.delete("a")
        assert cache.get("a") is None
        cache.set("c", 1, 0)
        assert cache.get("c") is None
        assert cache.add("d", 1, 0) is False

    def test_awkward_keys_are_hashed(self):
        cache = DjangoCache()
        for key in ("x" * 300, "with space", "ünïcode", "tab\tkey"):
            cache.set(key, key, 60)
            assert cache.get(key) == key
            assert len(DjangoCache.key(key)) < 250 and " " not in DjangoCache.key(key)

    def test_other_cache_alias(self, settings):
        settings.CACHES = {
            **settings.CACHES,
            "nine": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "other"},
        }
        settings.NINE = {"CACHE": "nine"}
        services.get_cache().set("k", "v", 60)
        assert caches["nine"].get("nine:k") == "v" and caches["default"].get("nine:k") is None


class TestChecks:
    def ids(self) -> list[str]:
        return [message.id for message in checks.check_settings()]

    def test_clean_configuration(self, nine_config):
        assert self.ids() == []

    def test_nothing_configured(self, settings):
        settings.NINE = {}
        assert self.ids() == []

    def test_client_id_without_issuer(self, settings):
        settings.NINE = {"CLIENT_ID": "app"}
        assert "nine_django.E001" in self.ids()

    def test_insecure_issuer(self, settings):
        settings.NINE = {"ISSUER": "http://acme.test", "CLIENT_ID": "app"}
        assert "nine_django.E002" in self.ids()
        settings.NINE = {"ISSUER": "https://acme.test?x=1"}
        assert "nine_django.E002" in self.ids()

    def test_backend_missing(self, nine_config, settings):
        settings.AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
        assert "nine_django.E003" in self.ids()
        settings.AUTHENTICATION_BACKENDS = ["tests.test_misc.MyBackend"]
        assert "nine_django.E003" not in self.ids()

    def test_middleware_order(self, nine_config, settings):
        middleware = [m for m in settings.MIDDLEWARE if "NineMiddleware" not in m]
        settings.MIDDLEWARE = middleware
        assert "nine_django.W001" in self.ids()
        settings.MIDDLEWARE = ["nine_django.middleware.NineMiddleware", *middleware]
        assert "nine_django.E004" in self.ids()

    def test_scopes_need_openid(self, configure):
        configure(SCOPES=["profile"])
        assert "nine_django.E005" in self.ids()

    def test_signed_cookie_sessions(self, nine_config, settings):
        settings.SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
        assert "nine_django.W002" in self.ids()

    def test_dummy_cache(self, nine_config, settings):
        settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}}
        assert "nine_django.W003" in self.ids()

    def test_unknown_cache(self, configure):
        configure(CACHE="missing")
        assert "nine_django.E006" in self.ids()

    def test_manage_py_check(self, nine_config):
        call_command("check", "--fail-level", "WARNING")


from nine_django.backends import NineBackend  # noqa: E402


class MyBackend(NineBackend):
    pass


@pytest.mark.django_db
class TestMigrations:
    def test_models_match_the_migrations(self):
        out = StringIO()
        call_command("makemigrations", "nine_django", "--check", "--dry-run", stdout=out)
        assert "No changes detected" in out.getvalue()

    @pytest.mark.django_db(transaction=True)
    def test_migrates_forwards_and_backwards(self):
        executor = MigrationExecutor(connection)
        executor.migrate([("nine_django", None)])
        assert "nine_django_nineidentity" not in connection.introspection.table_names()
        executor = MigrationExecutor(connection)
        executor.migrate([("nine_django", "0001_initial")])
        assert "nine_django_nineidentity" in connection.introspection.table_names()

    def test_identity_is_unique_per_issuer(self):
        from django.db import IntegrityError, transaction

        user = User.objects.create_user("u")
        NineIdentity.objects.create(user=user, issuer="https://a", sub="usr_1")
        NineIdentity.objects.create(user=user, issuer="https://b", sub="usr_1")
        with pytest.raises(IntegrityError), transaction.atomic():
            NineIdentity.objects.create(user=user, issuer="https://a", sub="usr_1")
        assert str(NineIdentity.objects.first()) == "usr_1 (https://a)"


@pytest.mark.django_db
class TestLoginLinkCommand:
    def run(self, *args: str) -> tuple[str, str]:
        out, err = StringIO(), StringIO()
        call_command("nine_login_link", *args, stdout=out, stderr=err)
        return out.getvalue().strip(), err.getvalue().strip()

    def test_by_9in_id(self, tenant, nine_config):
        tenant.add_user("usr_cli", email="cli@acme.test")
        url, err = self.run("usr_cli", "--return-to", "https://app.test/nine/callback", "--ttl", "300")
        assert url.startswith(tenant.issuer + "/login-link/")
        assert err.startswith("Expires 2026-11-22T09:10:00")
        assert tenant.login_links[0]["user_id"] == "usr_cli"
        assert tenant.login_links[0]["return_to"] == "https://app.test/nine/callback"
        assert tenant.login_links[0]["ttl_seconds"] == 300

    def test_by_email(self, tenant, nine_config):
        tenant.add_user("usr_cli", email="cli@acme.test")
        url, _ = self.run("CLI@acme.test")
        assert tenant.login_links[0]["user_id"] == "usr_cli"
        with pytest.raises(CommandError, match="No 9in user"):
            self.run("nobody@acme.test")

    def test_by_local_username(self, tenant, nine_config):
        user = User.objects.create_user("localjane")
        with pytest.raises(CommandError, match="has not signed in"):
            self.run("localjane")
        NineIdentity.objects.create(user=user, issuer=tenant.issuer, sub="usr_local")
        tenant.add_user("usr_local")
        self.run("localjane")
        assert tenant.login_links[0]["user_id"] == "usr_local"

    def test_errors(self, tenant, nine_config, settings):
        with pytest.raises(CommandError):
            self.run("usr_missing")
        settings.NINE = {"ISSUER": tenant.issuer, "CLIENT_ID": "app"}
        with pytest.raises(CommandError, match="confidential"):
            self.run("usr_x")
