# Changelog

## 0.1.0

The first release of the official Django SDK for 9in, built on the 9in Python SDK (`9in`).

- **Sign-in**: `/nine/login`, `/nine/signup`, `/nine/callback` and `/nine/logout` (include
  `nine_django.urls`). Authorization code flow with PKCE S256, single-use `state`, `nonce`, the
  RFC 9207 `iss` check and a verified ID token. `return_to` and `next` accept same-site paths
  only. Logout revokes the refresh token, ends the Django session and the 9in session.
- **Local users**: `NineBackend` signs each 9in user in as a Django user with
  `django.contrib.auth.login()` (session key cycled). The user is linked through the new
  `NineIdentity` model (`iss` + `sub`, migration included), by the adapter id 9in keeps for
  users of your own database, or by verified email, and created otherwise. `CREATE_USERS`,
  `LINK_BY_EMAIL`, `UPDATE_USERS` and `USER_FIELDS` change this.
- **`NineMiddleware`**: refreshes the session's tokens before they expire and keeps the
  rotated refresh token. It signs the user out when 9in refuses the refresh token, and sets
  `request.nine` (claims, `sub`, `access_token()`). Works under WSGI and ASGI.
- **APIs**: `@require_token(scope=...)` for sync and async views, and
  `nine_django.rest_framework.NineTokenAuthentication` + `HasScope` for Django REST framework.
  Tokens go through `HybridTokenVerifier` with Django's cache: hybrid by default when client
  credentials are set, otherwise `local` or `introspect`. `request.user` is the linked user or a
  `TokenUser`.
- **Webhooks** at `/nine/webhook`: signature check (secret rotation, `WEBHOOK_PATH` behind
  proxies) and eviction of revoked tokens. Each event is processed once with `cache.add`
  (204 / 409 / released on errors) and sent as a Django signal per event type plus
  `event_received`.
- **Your own user database**: `nine_django.adapter.urls` serves `/nine/authenticate`,
  `/nine/user` and `/nine/event`. `DjangoUserAdapter` answers from `AUTH_USER_MODEL`:
  case-insensitive email and username, `check_password()` with hash upgrades, inactive users
  blocked, claims mapped with `ADAPTER_FIELDS`. `otp.requested` codes are emailed with
  `send_mail`; SMS codes go through the `otp_requested` signal.
- `python manage.py nine_login_link <user>` creates single-use sign-in links.
- System checks for the issuer, backend, middleware order, scopes, signed-cookie sessions and
  the cache. Settings come from `NINE_*` environment variables or a `NINE` dict.
- Django 4.2, 5.2, 6.0 and 6.1 on Python 3.10 to 3.14. An example project is in `examples/demo`.
