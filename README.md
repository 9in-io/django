9in Django SDK
==============

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official Django SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO.

`9in-django` is built on the [9in Python SDK](https://github.com/9in-io/python-sdk) (`9in`,
`import nine`). It plugs sign-in, API tokens, webhooks and your own user database into Django's
own machinery: users, sessions, `@login_required`, the admin, signals and the cache.

- **Sign users in** at `/nine/login` with the authorization code flow, PKCE, `state`, `nonce` and
  the `iss` check. The ID token is verified against your tenant's keys. Each 9in user signs in
  as a **local Django user**, created or linked on first sign-in, so `request.user`,
  `@login_required` and the admin just work.
- **Keep sessions in step with 9in**: a middleware refreshes the tokens before they expire
  (rotating refresh tokens) and signs the user out here when 9in ends the session.
- **Protect your API** with `@require_token(scope=…)`, or with `NineTokenAuthentication` and
  `HasScope` for Django REST framework. Access tokens are verified locally with every algorithm
  of the key library. In **hybrid** mode revocations take effect at once, with answers cached
  in Django's cache.
- **Receive webhooks** at `/nine/webhook`: verified, processed once per event and sent as
  Django signals.
- **Keep users in your own database**: `/nine/authenticate`, `/nine/user` and `/nine/event` of the
  adapter protocol, answered from your user model. One-time codes are emailed with `send_mail`.
- **Manage users** through the Management API, and create sign-in links with
  `manage.py nine_login_link`.

Requires Python 3.10+ and Django 4.2, 5.2, 6.0 or 6.1 (Django 6 needs Python 3.12+).

```bash
pip install 9in-django            # add [drf] for Django REST framework
```

| Building with | Use |
|---|---|
| Django | `9in-django` (this package) |
| Flask, FastAPI or plain Python | [`9in`](https://github.com/9in-io/python-sdk) |
| JavaScript: browsers, Node, Next.js, React | [`@9in-io/sdk`](https://github.com/9in-io/sdk), [`@9in-io/nextjs`](https://github.com/9in-io/nextjs), [`@9in-io/react`](https://github.com/9in-io/react) |
| PHP or Laravel | [`9in/php-sdk`](https://github.com/9in-io/php-sdk), [`9in/laravel`](https://github.com/9in-io/laravel) |

Guides are at [9in.io/docs](https://9in.io/docs/). Start with
[server-rendered apps](https://9in.io/docs/server-apps/) for how sign-in works.

## Set up

In the 9in console, create the application: **Applications → Create application → Regular Web
App**. Use the callback URL `https://your-app.com/nine/callback` and the logout URL
`https://your-app.com/`, and copy the client ID and secret.

```bash
NINE_ISSUER=https://acme.9in.io          # or your custom login domain; https://acme-sandbox.9in.io to test
NINE_CLIENT_ID=app_…
NINE_CLIENT_SECRET=…
# NINE_AUDIENCE=https://api.acme.com     # access tokens for your own API
```

```python
# settings.py
INSTALLED_APPS = [
    ...,
    "nine_django",
]

MIDDLEWARE = [
    ...,
    "django.contrib.sessions.middleware.SessionMiddleware",
    ...,
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "nine_django.middleware.NineMiddleware",     # after AuthenticationMiddleware
    ...,
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",  # keep it for admin passwords
    "nine_django.backends.NineBackend",
]

LOGIN_URL = "nine:login"                          # @login_required sends users to 9in
```

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    ...,
    path("nine/", include("nine_django.urls")),   # /nine/login, /signup, /callback, /logout, /webhook
]
```

```bash
python manage.py migrate        # creates the NineIdentity table
python manage.py check          # flags common setup mistakes
```

Settings come from `NINE_*` environment variables. A `NINE = {...}` dict in your settings
overrides them; see [Settings](#settings).

## Sign users in

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def dashboard(request):
    request.user          # your Django user
    request.nine.claims   # the verified ID token: sub, email, name, amr…
    request.nine.sub      # the 9in user id (usr_…)
    return render(request, "dashboard.html")
```

```html
<a href="{% url 'nine:login' %}?return_to=/dashboard">Sign in</a>
<a href="{% url 'nine:signup' %}">Create an account</a>     <!-- opens the sign-up form -->
<a href="{% url 'nine:logout' %}">Sign out</a>
```

| Route | |
|---|---|
| `GET /nine/login?return_to=/path` | Starts a sign-in (`next=` works too, so `@login_required` works). `login_hint` pre-fills the identifier. |
| `GET /nine/signup` | The same, on the sign-up form |
| `GET /nine/callback` | Completes it: checks `state` (single use), `iss`, PKCE and the ID token, signs the local user in and cycles the session key |
| `GET` or `POST /nine/logout?return_to=/path` | Revokes the refresh token, ends the Django session, then ends the 9in session and comes back |

`return_to` must be a path on your site, so it can't be used for open redirects.
`/nine/logout` accepts GET so a plain link works, like in the other 9in SDKs. A `POST` from a
form with `{% csrf_token %}` is protected against cross-site requests; use that when another
site signing your users out would matter.
Without one, users land on `LOGIN_REDIRECT_URL` (or `/`). After sign-out they go to
`LOGOUT_REDIRECT_URL` (or `/`), which must be one of the application's logout URLs.

### Local users

On first sign-in, `NineBackend` links the 9in user to a Django user and records the link as a
`NineIdentity` (`iss` + `sub`). It tries these in order:

1. the user already linked to this 9in user;
2. for users of [your own database](#keep-users-in-your-own-database), the local user behind
   the adapter id 9in keeps for them (this needs the Management API);
3. the one local user with the same email, only when 9in says the email is verified;
4. otherwise a new user with an unusable password. Their username is the verified email,
   the 9in username or the 9in user id, whichever is free first.

Inactive users can't sign in. On every sign-in, `email`, `first_name` and `last_name` are
copied from the claims (`USER_FIELDS`). To change any step, subclass `NineBackend`, override
`find_user_to_link`, `create_user` or `update_user`, and list your class in
`AUTHENTICATION_BACKENDS` instead.

```python
from django.dispatch import receiver
from nine_django.signals import user_signed_in

@receiver(user_signed_in)
def on_sign_in(sender, request, user, claims, tokens, created, **kwargs):
    if created:
        Profile.objects.create(user=user, locale=claims.get("locale", "en"))
```

### Tokens in the session

The 9in tokens of a signed-in user are kept in the Django session. `NineMiddleware`
refreshes them shortly before the access token expires. 9in rotates refresh tokens, and the
new one replaces the old one. If 9in refuses the refresh token, the user is signed out here
too. That happens after signing out everywhere, when the session is revoked, or when the user
is blocked or deleted. If 9in can't be reached, the session stays.

```python
import urllib.request

token = request.nine.access_token()     # refreshed when needed; None without 9in tokens
req = urllib.request.Request("https://api.acme.com/orders", headers={"Authorization": f"Bearer {token}"})
```

Use database, cache or `cached_db` sessions. Signed-cookie sessions would put the tokens in
the browser, and `manage.py check` warns about them. Keep `offline_access` in `SCOPES` (it is
there by default) to get a refresh token.

## Protect your API

```python
from nine_django.decorators import require_token

@require_token(scope="orders:read")
def orders(request):
    request.user           # the linked Django user, or a TokenUser (sub, claims) when there is none
    request.nine.claims    # access token claims: sub, client_id, scope, aud…
    ...
```

Tokens must be issued for `NINE_API_AUDIENCE`, which defaults to `NINE_AUDIENCE`.

- A missing or invalid token gets `401 invalid_token`. A token without every scope listed
  gets `403 insufficient_scope`. Both answers carry a `WWW-Authenticate` header.
- The decorator works on sync and async views. Those views are exempt from CSRF checks,
  since the token authenticates the request, not a cookie.
- **Every key-library algorithm** is accepted: RS256/384/512, PS256/384/512, ES256, ES384 and
  EdDSA through your tenant's JWKS, and HS256/384/512 with the API's shared secret in
  `NINE_API_SECRET`.
- Only access tokens (`typ: at+jwt`) are accepted, signed with exactly the key's algorithm.
  Signing keys are cached for 10 minutes, and a new key after a rotation is fetched once.
- `nine_django.verify_access_token(token, scope=...)` runs the same check by hand.

### Revocation: hybrid verification

With `NINE_CLIENT_ID` and `NINE_CLIENT_SECRET` set (or the `NINE_MANAGEMENT_*` pair), tokens
are verified in **hybrid** mode:

- each token is checked locally, then introspected once;
- the answer is cached in Django's cache for at most `NINE_TOKEN_CACHE_TTL` seconds
  (default 300);
- when `/nine/webhook` receives `token.revoked`, `session.revoked` or a `user.*` event, it drops
  the matching answers, so the next request is refused.

Subscribe your webhook endpoint to those events (see [Webhooks](#webhooks)). Opaque access
tokens (`9in_at_…`) are always introspected.

`NINE_TOKEN_VERIFICATION=local` skips introspection, so a revoked token keeps working until it
expires. `introspect` asks 9in on every request. Without client credentials, `local` is used.
If 9in can't be reached during an introspection, the API answers `503`.

### Django REST framework

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["nine_django.rest_framework.NineTokenAuthentication"],
}
```

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from nine_django.rest_framework import HasScope

class Orders(APIView):
    permission_classes = [HasScope("orders:read")]     # or [HasScope] with required_scopes = [...]

    def get(self, request):
        return Response({"sub": request.auth["sub"]})  # request.auth: the access token claims
```

`HasScope` composes with DRF's operators: `[IsAdminUser | HasScope("orders:admin")]`.

## Manage users

```python
from nine_django import get_management_client

management = get_management_client()
user = management.create_user({"email": "jane@acme.com", "email_verified": True, "name": "Jane"})
management.find_user_by_email("jane@acme.com")
management.update_user(user["id"], {"metadata": {"plan": "pro"}})
management.block_user(user["id"])
management.revoke_user_sessions(user["id"])
link = management.create_login_link(user["id"], return_to="https://your-app.com/nine/callback")
```

```bash
python manage.py nine_login_link jane@acme.com --return-to https://your-app.com/nine/callback
```

The command prints a single-use sign-in URL. `<user>` is a 9in user id, an email address, or
the username of a local user who has signed in with 9in.

The application needs management scopes. Set `NINE_MANAGEMENT_CLIENT_ID` and
`NINE_MANAGEMENT_CLIENT_SECRET` to use a separate machine-to-machine application. Field names
are the API's snake_case and times are ISO 8601 UTC, as everywhere in 9in.
`get_web_app_auth().client_credentials(audience=..., scope=...)` gets a token for your app's own
calls to other APIs.

## Keep users in your own database

Keep your Django users and sign them in with 9in. 9in asks your app to check passwords and
look users up through three signed endpoints (the adapter protocol v2).

```python
urlpatterns = [
    ...,
    path("nine/", include("nine_django.urls")),
    path("nine/", include("nine_django.adapter.urls")),   # /nine/authenticate, /nine/user, /nine/event
]
```

In the console, open **Connections → User database → Your server (adapter)**, enter
`https://your-app.com/nine`, then copy the secret:

```bash
NINE_ADAPTER_SECRET=…
# NINE_ADAPTER_SECRET_PREVIOUS=…   # the old one, while you rotate it
```

Requests must be signed with the secret and at most five minutes old. Responses are signed
over the request path and 9in's request id.

`DjangoUserAdapter` answers from `AUTH_USER_MODEL`:

- users are found by email or username, case-insensitively, or by phone when you map one;
- passwords are checked with `check_password()`, and Django upgrades old hashes;
- inactive users get `blocked`. Unknown users and wrong passwords get the same answer, in
  about the same time.

Map more claims, or other fields, with `ADAPTER_FIELDS`. Each entry is an attribute name
(`__` follows relations), a callable taking the user, or `None` to leave the claim out:

```python
NINE = {
    "ADAPTER_FIELDS": {
        "phone_number": "profile__phone",
        "email_verified": lambda user: user.emailaddress_set.filter(verified=True).exists(),
        "metadata": lambda user: {"plan": user.profile.plan},
    },
    "ADAPTER_IDENTIFIERS": ["email", "username", "phone"],
}
```

For anything else, subclass `nine_django.adapter.DjangoUserAdapter`, or write a `nine.Adapter`,
and set `NINE["ADAPTER"]` to its dotted path.

**One-time codes.** 9in creates sign-in and password-reset codes and sends them to
`/nine/event` as `otp.requested`. Email codes are sent with `send_mail` from
`DEFAULT_FROM_EMAIL` (or `OTP_FROM_EMAIL`). Override the templates
`nine_django/otp_email_subject.txt`, `otp_email.txt` and `otp_email.html` to change the
message, or set `"OTP_EMAIL": False` to send codes yourself. Send SMS codes from a receiver:

```python
from django.dispatch import receiver
from nine_django.signals import otp_requested

@receiver(otp_requested)
def send_sms(sender, data, **kwargs):
    if data["channel"] == "sms":
        sms_client.send(to=data["to"], body=f"Your code is {data['code']}")
```

Adapter users exist in 9in after their first sign-in. When they sign in to your Django app
through `/nine/login`, `NineBackend` asks the Management API for the adapter id and signs in
the same Django user. Turn that off with `LINK_ADAPTER_USERS = False`.

## Webhooks

In the console, open **Advanced → Webhooks → Add endpoint** and add
`https://your-app.com/nine/webhook`, then set its signing secret:

```bash
NINE_WEBHOOK_SECRET=whsec_…
```

Each verified event is sent on its own Django signal, then on `event_received`. The signal is
named after the event type, with dots as underscores: `user_created`, `user_updated`,
`user_deleted`, `user_login`, `token_revoked`…

```python
from django.dispatch import receiver
from nine_django.signals import user_created, user_deleted

@receiver(user_created)
def add_contact(sender, event, data, **kwargs):
    crm.add(data["user"]["email"])           # the 9in user: snake_case, ISO 8601 times

@receiver(user_deleted)
def remove_contact(sender, data, **kwargs):
    crm.remove(data["user"]["id"])
```

Receivers get `event` (`{id, event_type, created_at, tenant, environment, data}`),
`event_type`, `data` and `source` (`"webhook"`). The signature is checked over the raw body
and the path, and must be at most five minutes old. Each event is processed **once**:

- a retry or redelivery of a processed event id gets `204` without sending the signals again;
- a retry that arrives while the first delivery is still running gets `409`, and 9in tries
  again later;
- if a receiver raises, the answer is `500`, the id is released and 9in retries.

Event ids are kept for three days in the cache named by `NINE["CACHE"]`. With several
processes, use a shared cache whose `add()` is atomic (Redis, Memcached, the database cache).
Answer quickly and queue slow work. Adapter events (`otp_requested`, `user_updated`…) use the
same signals with `source="adapter"`. `sender` is `nine_django.signals.Webhook` or
`AdapterEvent`.

## Issuers must use https

The issuer must use `https://`. Plain http is accepted for `localhost`, `*.localhost` and
loopback addresses only. Set `NINE_ALLOW_INSECURE_ISSUER=true` for other development hosts,
such as `http://auth:8897` in Docker. Issuers with a query, a fragment or credentials are
refused. `manage.py check` reports these errors before the first request.

## Settings

Each setting is read from `NINE["<NAME>"]`, then the `NINE_<NAME>` environment variable, then
the default.

| Setting | Environment | Default | |
|---|---|---|---|
| `ISSUER` | `NINE_ISSUER` | | Your tenant or login domain |
| `CLIENT_ID`, `CLIENT_SECRET` | `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET` | | The application |
| `REDIRECT_URI` | `NINE_REDIRECT_URI` | this site's `/nine/callback` | Absolute, or a path on this site |
| `SCOPES` | | `openid profile email offline_access` | Add your API's scopes |
| `AUDIENCE` | `NINE_AUDIENCE` | | API to request access tokens for |
| `LOCALE` | | | Language of the hosted pages: a tag such as `"de"`, or `"auto"` for the active Django language |
| `LOGIN_REDIRECT_URL`, `LOGOUT_REDIRECT_URL` | `NINE_LOGOUT_REDIRECT_URI` | Django's, else `/` | |
| `CREATE_USERS`, `LINK_BY_EMAIL`, `UPDATE_USERS` | | `True` | [Local users](#local-users) |
| `LINK_ADAPTER_USERS` | | on with `ADAPTER_SECRET` | |
| `USER_FIELDS` | | email, first and last name | Model field → claim name, or callable(claims) |
| `API_AUDIENCE` | `NINE_API_AUDIENCE` | `AUDIENCE` | Audience of tokens on your API |
| `TOKEN_VERIFICATION` | `NINE_TOKEN_VERIFICATION` | hybrid with a client secret | `local`, `hybrid` or `introspect` |
| `API_SECRET` | `NINE_API_SECRET` | | For HS256/384/512 tokens |
| `TOKEN_CACHE_TTL` | `NINE_TOKEN_CACHE_TTL` | `300` | Seconds a hybrid answer is kept |
| `MANAGEMENT_CLIENT_ID`, `MANAGEMENT_CLIENT_SECRET` | `NINE_MANAGEMENT_CLIENT_ID`, `…_SECRET` | the application's | Management API and introspection |
| `WEBHOOK_SECRET`, `WEBHOOK_SECRET_PREVIOUS` | `NINE_WEBHOOK_SECRET`, `…_PREVIOUS` | | Comma-separated for several |
| `WEBHOOK_DEDUPE`, `WEBHOOK_DEDUPE_TTL` | | `True`, 3 days | |
| `WEBHOOK_PATH` | | the request path | The path 9in posts to, behind a proxy that rewrites it |
| `ADAPTER_SECRET`, `ADAPTER_SECRET_PREVIOUS` | `NINE_ADAPTER_SECRET`, `…_PREVIOUS` | | |
| `ADAPTER` | | `DjangoUserAdapter` | Dotted path of your adapter class |
| `ADAPTER_FIELDS`, `ADAPTER_IDENTIFIERS` | | | [Your own database](#keep-users-in-your-own-database) |
| `OTP_EMAIL`, `OTP_FROM_EMAIL` | | `True`, `DEFAULT_FROM_EMAIL` | |
| `ALLOW_INSECURE_ISSUER` | `NINE_ALLOW_INSECURE_ISSUER` | `False` | |
| `CACHE` | `NINE_CACHE` | `"default"` | Cache alias for keys, token answers and event ids |
| `HTTP_CLIENT` | | urllib, 10 s timeout | A `nine.HttpClient` or its dotted path |

The shared SDK objects are `get_web_app_auth()`, `get_token_verifier()`,
`get_management_client()` and `get_cache()`, all importable from `nine_django`.

## Errors

Errors from 9in are `nine.NineError` (from the Python SDK), with `.error` (the code, such as
`invalid_grant` or `not_found`), `.description` and `.status`. The views turn them into answers:

- a failed sign-in shows `nine_django/error.html` (override it in your templates) with status
  400, or 403 for a user who can't sign in here;
- API views answer JSON `{"error", "error_description"}` with 401, 403 or 503;
- webhooks answer `401 invalid_signature`.

Missing settings raise `ImproperlyConfigured`. Logs go to the `nine_django` logger and never
contain tokens or secrets.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest pytest-django djangorestframework
pytest
```

Every supported Django and Python version: `uvx --with tox-uv tox`. The tests run against a
fake 9in tenant on a local HTTP server. Live tests against real 9in tenants are opt-in:
`NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e pytest tests/live`. A runnable example project
is in [examples/demo](examples/demo).

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in is by [Cubelet Ltd](https://cubelet.co.uk).
