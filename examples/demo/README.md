# 9in Django demo

A small Django project that signs users in with 9in: local Django users, `@login_required`,
token refresh in the middleware, an API endpoint protected with `@require_token`, and a
webhook receiver that logs every event.

1. In the 9in console, create a **Regular Web App** with the callback URL
   `http://127.0.0.1:8000/nine/callback` and the logout URL `http://127.0.0.1:8000/`.
2. Run it:

   ```bash
   python -m venv .venv && . .venv/bin/activate
   pip install -r requirements.txt
   export NINE_ISSUER=https://acme.9in.io NINE_CLIENT_ID=app_… NINE_CLIENT_SECRET=…
   python manage.py migrate
   python manage.py runserver 127.0.0.1:8000
   ```

3. Open http://127.0.0.1:8000 and sign in. With your tenant's sandbox as the issuer
   (`NINE_ISSUER=https://acme-sandbox.9in.io`), any password signs in and creates a test user.

Optional: `NINE_AUDIENCE=https://api.acme.com` and `DEMO_API_SCOPES="orders:read"` to get access
tokens for your API, and `NINE_WEBHOOK_SECRET` with a webhook endpoint for `/nine/webhook`.
