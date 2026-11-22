"""A fake 9in tenant on a local HTTP server: OIDC discovery, JWKS, the token endpoint (code
with PKCE, refresh with rotation and a 30 s grace, client credentials), userinfo, revoke,
introspection and the parts of the Management API the package uses.

It speaks the wire protocol documented at https://9in.io/docs/reference/ so the real SDK
(``nine``) runs against it over real HTTP.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
ASYMMETRIC = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]
SYMMETRIC = ["HS256", "HS384", "HS512"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_bytes(value: int, length: int | None = None) -> bytes:
    length = length or (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


class Key:
    """A signing key of the fake key library."""

    def __init__(self, alg: str, kid: str | None = None, secret: bytes | None = None) -> None:
        self.alg = alg
        self.kid = kid or f"k_{alg.lower()}"
        self.secret = secret
        if alg.startswith(("RS", "PS")):
            self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif alg == "ES256":
            self.private = ec.generate_private_key(ec.SECP256R1())
        elif alg == "ES384":
            self.private = ec.generate_private_key(ec.SECP384R1())
        elif alg == "EdDSA":
            self.private = ed25519.Ed25519PrivateKey.generate()
        elif alg.startswith("HS"):
            self.private = None
            self.secret = secret or secrets.token_bytes(32)
        else:
            raise ValueError(alg)

    def jwk(self) -> dict[str, Any] | None:
        if self.private is None:
            return None  # HMAC keys are never published
        public = self.private.public_key()
        base = {"kid": self.kid, "alg": self.alg, "use": "sig"}
        if isinstance(public, rsa.RSAPublicKey):
            numbers = public.public_numbers()
            return {**base, "kty": "RSA", "n": b64url(_int_bytes(numbers.n)), "e": b64url(_int_bytes(numbers.e))}
        if isinstance(public, ec.EllipticCurvePublicKey):
            numbers = public.public_numbers()
            size = 32 if self.alg == "ES256" else 48
            return {
                **base,
                "kty": "EC",
                "crv": "P-256" if self.alg == "ES256" else "P-384",
                "x": b64url(_int_bytes(numbers.x, size)),
                "y": b64url(_int_bytes(numbers.y, size)),
            }
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {**base, "kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}

    def sign(self, signing_input: bytes) -> bytes:
        alg = self.alg
        if alg.startswith("HS"):
            return hmac.new(self.secret, signing_input, getattr(hashlib, "sha" + alg[2:])).digest()
        if alg.startswith("RS"):
            return self.private.sign(signing_input, padding.PKCS1v15(), HASHES[alg[2:]]())
        if alg.startswith("PS"):
            h = HASHES[alg[2:]]()
            return self.private.sign(signing_input, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
        if alg.startswith("ES"):
            size = 32 if alg == "ES256" else 48
            der = self.private.sign(signing_input, ec.ECDSA(HASHES[alg[2:]]()))
            r, s = decode_dss_signature(der)
            return _int_bytes(r, size) + _int_bytes(s, size)
        return self.private.sign(signing_input)


def make_jwt(key: Key, claims: dict[str, Any], *, typ: str = "at+jwt", header: dict[str, Any] | None = None) -> str:
    head = {"alg": key.alg, "typ": typ, "kid": key.kid}
    if header:
        head.update(header)
    head = {k: v for k, v in head.items() if v is not None}
    signing_input = f"{b64url(json.dumps(head, separators=(',', ':')).encode())}.{b64url(json.dumps(claims, separators=(',', ':')).encode())}".encode()
    return signing_input.decode() + "." + b64url(key.sign(signing_input))


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


class FakeTenant:
    client_id = "app_django_test"
    client_secret = "s3cret-for-tests"
    audience = "https://api.django.test"

    def __init__(self) -> None:
        self.keys: dict[str, Key] = {alg: Key(alg) for alg in ASYMMETRIC}
        self.hmac_secret = b"0123456789abcdef0123456789abcdef"
        for alg in SYMMETRIC:
            self.keys[alg] = Key(alg, secret=self.hmac_secret)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.tenant = self  # type: ignore[attr-defined]
        self.issuer = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.lock = threading.RLock()
        self.reset()

    # Lifecycle ---------------------------------------------------------------------

    def start(self) -> FakeTenant:
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def reset(self) -> None:
        with self.lock:
            self.codes: dict[str, dict[str, Any]] = {}
            self.refresh_tokens: dict[str, dict[str, Any]] = {}
            self.access_tokens: dict[str, dict[str, Any]] = {}  # jti or opaque token → record
            self.revoked_jtis: set[str] = set()
            self.revoked_sids: set[str] = set()
            self.management_tokens: set[str] = set()
            self.users: dict[str, dict[str, Any]] = {}
            self.login_links: list[dict[str, Any]] = []
            self.requests: list[tuple[str, str]] = []
            self.access_ttl = 3600
            self.refresh_returns_id_token = True
            self.fail_token_endpoint: int | None = None
            self.fail_revoke = False
            self.fail_introspection = False
            self.iss_parameter = True
            self.default_key = "RS256"
            self.token_keys: dict[str, str] = {}  # audience → alg

    def count(self, method: str, path: str) -> int:
        with self.lock:
            return sum(1 for m, p in self.requests if m == method and p == path)

    # Users -------------------------------------------------------------------------

    def add_user(self, sub: str | None = None, **fields: Any) -> dict[str, Any]:
        sub = sub or "usr_" + secrets.token_hex(6)
        user = {
            "id": sub,
            "email": None,
            "email_verified": False,
            "name": None,
            "given_name": None,
            "family_name": None,
            "blocked": False,
            "metadata": {},
            "identities": [],
            "created_at": "2026-11-22T08:00:00.000Z",
        }
        user.update(fields)
        with self.lock:
            self.users[sub] = user
        return user

    # Tokens ------------------------------------------------------------------------

    def sign(
        self, claims: dict[str, Any], alg: str = "RS256", *, typ: str = "at+jwt", header: dict[str, Any] | None = None
    ) -> str:
        return make_jwt(self.keys[alg], claims, typ=typ, header=header)

    def access_token(
        self,
        sub: str = "usr_api",
        scope: str = "",
        aud: str | None = None,
        alg: str = "RS256",
        ttl: int | None = None,
        **extra: Any,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud or self.audience,
            "client_id": extra.pop("client_id", self.client_id),
            "scope": scope,
            "iat": now,
            "exp": now + (ttl if ttl is not None else self.access_ttl),
            "jti": "jti_" + secrets.token_hex(8),
            "sid": extra.pop("sid", "sid_" + secrets.token_hex(6)),
        }
        claims.update(extra)
        token = self.sign(claims, alg)
        with self.lock:
            self.access_tokens[claims["jti"]] = dict(claims)
        return token

    def opaque_token(self, sub: str = "usr_api", scope: str = "", aud: str | None = None, **extra: Any) -> str:
        token = "9in_at_" + secrets.token_urlsafe(24)
        now = int(time.time())
        with self.lock:
            self.access_tokens[token] = {
                "iss": self.issuer,
                "sub": sub,
                "aud": aud or self.audience,
                "client_id": self.client_id,
                "scope": scope,
                "iat": now,
                "exp": now + self.access_ttl,
                "jti": token,
                "sid": extra.get("sid", "sid_" + secrets.token_hex(6)),
                **extra,
            }
        return token

    def id_token(self, sub: str, nonce: str | None, aud: str | None = None, **claims: Any) -> str:
        now = int(time.time())
        body = {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud or self.client_id,
            "azp": aud or self.client_id,
            "iat": now,
            "exp": now + 3600,
            "auth_time": now,
            "amr": ["pwd"],
        }
        if nonce is not None:
            body["nonce"] = nonce
        body.update(claims)
        return self.sign({k: v for k, v in body.items() if v is not None}, self.default_key, typ="JWT")

    # The browser step --------------------------------------------------------------

    def authorize(self, authorize_url: str, sub: str = "usr_jane", *, error: str | None = None, **claims: Any) -> dict[str, str]:
        """What 9in redirects to after the user signs in on the hosted page: the callback's query."""
        parts = urlsplit(authorize_url)
        assert f"{parts.scheme}://{parts.netloc}" == self.issuer and parts.path == "/oauth/authorize", authorize_url
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert params["response_type"] == "code"
        assert params["client_id"] == self.client_id
        assert params["code_challenge_method"] == "S256"
        query: dict[str, str] = {"state": params.get("state", "")}
        if self.iss_parameter:
            query["iss"] = self.issuer
        if error:
            query["error"] = error
            query["error_description"] = "The user cancelled."
            return query
        code = "code_" + secrets.token_urlsafe(12)
        user = self.users.get(sub) or self.add_user(
            sub, email=claims.get("email"), email_verified=claims.get("email_verified", False)
        )
        profile = {
            "email": user.get("email"),
            "email_verified": user.get("email_verified"),
            "name": user.get("name"),
            "given_name": user.get("given_name"),
            "family_name": user.get("family_name"),
        }
        profile.update(claims)
        with self.lock:
            self.codes[code] = {
                "sub": sub,
                "client_id": params["client_id"],
                "redirect_uri": params["redirect_uri"],
                "challenge": params["code_challenge"],
                "nonce": params.get("nonce"),
                "scope": params.get("scope", "openid"),
                "audience": params.get("audience") or params.get("resource"),
                "claims": profile,
                "params": params,
                "sid": "sid_" + secrets.token_hex(6),
            }
        query["code"] = code
        return query

    # Token endpoint ----------------------------------------------------------------

    def _issue(self, record: dict[str, Any], *, refresh: str | None = None, with_id_token: bool = True) -> dict[str, Any]:
        scope = record["scope"]
        aud = record.get("audience")
        alg = self.token_keys.get(aud or "", self.default_key)
        access = self.access_token(record["sub"], scope=scope, aud=aud or record["client_id"], alg=alg, sid=record["sid"])
        body: dict[str, Any] = {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl, "scope": scope}
        if "openid" in scope.split() and with_id_token:
            body["id_token"] = self.id_token(record["sub"], record.get("nonce"), sid=record["sid"], **record.get("claims", {}))
        if refresh is not None:
            body["refresh_token"] = refresh
        elif "offline_access" in scope.split():
            token = "rt_" + secrets.token_urlsafe(16)
            with self.lock:
                self.refresh_tokens[token] = {
                    **record,
                    "family": secrets.token_hex(4),
                    "used_at": None,
                    "next": None,
                    "revoked": False,
                }
            body["refresh_token"] = token
        return body

    def token_endpoint(self, form: dict[str, str], client: tuple[str, str] | None) -> tuple[int, dict[str, Any]]:
        if self.fail_token_endpoint:
            return self.fail_token_endpoint, {"error": "server_error", "error_description": "boom"}
        if client is None or client != (self.client_id, self.client_secret):
            return 401, {"error": "invalid_client", "error_description": "client authentication failed"}
        grant = form.get("grant_type")
        if grant == "authorization_code":
            with self.lock:
                record = self.codes.pop(form.get("code", ""), None)
            if record is None:
                return 400, {"error": "invalid_grant", "error_description": "bad or used code"}
            if record["redirect_uri"] != form.get("redirect_uri"):
                return 400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}
            if pkce_challenge(form.get("code_verifier", "")) != record["challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "wrong code_verifier"}
            return 200, self._issue(record)
        if grant == "refresh_token":
            token = form.get("refresh_token", "")
            with self.lock:
                record = self.refresh_tokens.get(token)
                if record is None or record["revoked"] or record["sid"] in self.revoked_sids:
                    return 400, {"error": "invalid_grant", "error_description": "refresh token revoked or unknown"}
                now = time.time()
                if record["used_at"] is not None:
                    if now - record["used_at"] <= 30 and record["next"]:
                        return 200, self._issue(record, refresh=record["next"], with_id_token=self.refresh_returns_id_token)
                    for other in self.refresh_tokens.values():
                        if other["family"] == record["family"]:
                            other["revoked"] = True
                    return 400, {"error": "invalid_grant", "error_description": "refresh token reuse"}
                body = self._issue(record, with_id_token=self.refresh_returns_id_token)
                record["used_at"] = now
                record["next"] = body.get("refresh_token")
                if record["next"]:
                    self.refresh_tokens[record["next"]]["family"] = record["family"]
            return 200, body
        if grant == "client_credentials":
            scope = form.get("scope", "")
            audience = form.get("audience")
            if any(s.startswith("management:") for s in scope.split()) or not audience:
                token = "mgmt_" + secrets.token_urlsafe(16)
                with self.lock:
                    self.management_tokens.add(token)
                return 200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": scope}
            access = self.access_token(self.client_id, scope=scope, aud=audience, sid=None)
            return 200, {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl, "scope": scope}
        return 400, {"error": "unsupported_grant_type"}

    def introspect(self, token: str) -> dict[str, Any]:
        with self.lock:
            record = self.access_tokens.get(token)
            if record is None and token.count(".") == 2:
                try:
                    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
                    record = self.access_tokens.get(payload.get("jti", ""))
                except ValueError:
                    record = None
            if record is None:
                return {"active": False}
            if record["jti"] in self.revoked_jtis or record.get("sid") in self.revoked_sids:
                return {"active": False}
            if record["exp"] < time.time():
                return {"active": False}
            user = self.users.get(record["sub"])
            if user and user.get("blocked"):
                return {"active": False}
            return {"active": True, "token_type": "access_token", **record}

    def revoke(self, token: str) -> None:
        with self.lock:
            if token in self.refresh_tokens:
                family = self.refresh_tokens[token]["family"]
                for other in self.refresh_tokens.values():
                    if other["family"] == family:
                        other["revoked"] = True
                return
            record = self.access_tokens.get(token)
            if record is None and token.count(".") == 2:
                try:
                    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
                    record = self.access_tokens.get(payload.get("jti", ""))
                except ValueError:
                    record = None
            if record is not None:
                self.revoked_jtis.add(record["jti"])

    def revoke_session(self, sid: str) -> None:
        with self.lock:
            self.revoked_sids.add(sid)

    def discovery(self) -> dict[str, Any]:
        doc = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "userinfo_endpoint": f"{self.issuer}/oauth/userinfo",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "revocation_endpoint": f"{self.issuer}/oauth/revoke",
            "introspection_endpoint": f"{self.issuer}/oauth/introspect",
            "end_session_endpoint": f"{self.issuer}/oauth/logout",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "id_token_signing_alg_values_supported": ASYMMETRIC,
            "scopes_supported": ["openid", "profile", "email", "phone", "offline_access"],
            "prompt_values_supported": ["none", "login", "consent", "select_account", "create"],
        }
        if self.iss_parameter:
            doc["authorization_response_iss_parameter_supported"] = True
        return doc

    def jwks(self) -> dict[str, Any]:
        return {"keys": [jwk for jwk in (key.jwk() for key in self.keys.values()) if jwk]}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # quiet
        return

    @property
    def tenant(self) -> FakeTenant:
        return self.server.tenant  # type: ignore[attr-defined]

    def _send(self, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _form(self, raw: bytes) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(raw.decode()).items()}

    def _client(self, form: dict[str, str]) -> tuple[str, str] | None:
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("basic "):
            from urllib.parse import unquote

            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
            return unquote(user), unquote(password)
        if "client_id" in form and "client_secret" in form:
            return form["client_id"], form["client_secret"]
        return None

    def _bearer(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        return header[7:].strip() if header.lower().startswith("bearer ") else None

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def do_PATCH(self) -> None:
        self._route("PATCH")

    def do_DELETE(self) -> None:
        self._route("DELETE")

    def _route(self, method: str) -> None:
        tenant = self.tenant
        parts = urlsplit(self.path)
        path = parts.path
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        raw = self._body()
        with tenant.lock:
            tenant.requests.append((method, path))
        if path == "/.well-known/openid-configuration" and method == "GET":
            return self._send(200, tenant.discovery())
        if path == "/.well-known/jwks.json" and method == "GET":
            return self._send(200, tenant.jwks())
        if path == "/oauth/token" and method == "POST":
            form = self._form(raw)
            status, body = tenant.token_endpoint(form, self._client(form))
            return self._send(status, body)
        if path == "/oauth/revoke" and method == "POST":
            if tenant.fail_revoke:
                return self._send(503, {"error": "temporarily_unavailable"})
            form = self._form(raw)
            if self._client(form) != (tenant.client_id, tenant.client_secret):
                return self._send(401, {"error": "invalid_client"})
            tenant.revoke(form.get("token", ""))
            return self._send(200, {})
        if path == "/oauth/introspect" and method == "POST":
            if tenant.fail_introspection:
                return self._send(503, {"error": "temporarily_unavailable"})
            form = self._form(raw)
            if self._client(form) != (tenant.client_id, tenant.client_secret):
                return self._send(401, {"error": "invalid_client"})
            return self._send(200, tenant.introspect(form.get("token", "")))
        if path == "/oauth/userinfo":
            token = self._bearer() or ""
            info = tenant.introspect(token)
            if not info.get("active"):
                return self._send(401, {"error": "invalid_token"}, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
            user = tenant.users.get(info["sub"], {})
            return self._send(
                200,
                {"sub": info["sub"], **{k: user.get(k) for k in ("email", "email_verified", "name") if user.get(k) is not None}},
            )
        if path.startswith("/api/v1/"):
            return self._management(method, path[len("/api/v1") :], query, raw)
        return self._send(404, {"error": "not_found"})

    def _management(self, method: str, path: str, query: dict[str, str], raw: bytes) -> None:
        tenant = self.tenant
        if self._bearer() not in tenant.management_tokens:
            return self._send(401, {"error": "invalid_token"})
        segments = [s for s in path.split("/") if s]
        body = json.loads(raw) if raw else {}
        if segments == ["users", "lookup"] and method == "GET":
            for field in ("email", "phone_number", "username"):
                if field in query:
                    value = query[field].lower()
                    for user in tenant.users.values():
                        if str(user.get(field) or "").lower() == value:
                            return self._send(200, {"user": user})
            return self._send(404, {"error": "not_found", "error_description": "no such user"})
        if segments == ["users"] and method == "GET":
            return self._send(200, {"users": list(tenant.users.values()), "next_cursor": None, "total": len(tenant.users)})
        if segments == ["users"] and method == "POST":
            user = tenant.add_user(**body)
            return self._send(201, {"user": user})
        if len(segments) >= 2 and segments[0] == "users":
            user = tenant.users.get(segments[1])
            if user is None:
                return self._send(404, {"error": "not_found", "error_description": "no such user"})
            if len(segments) == 2:
                if method == "GET":
                    return self._send(200, {"user": user})
                if method == "PATCH":
                    user.update(body)
                    return self._send(200, {"user": user})
                if method == "DELETE":
                    del tenant.users[segments[1]]
                    return self._send(204)
            if segments[2:] == ["login-link"] and method == "POST":
                link = {"url": f"{tenant.issuer}/login-link/{secrets.token_urlsafe(8)}", "expires_at": "2026-11-22T09:10:00.000Z"}
                tenant.login_links.append({"user_id": user["id"], **body, **link})
                return self._send(201, link)
            if segments[2:] == ["sessions"]:
                if method == "GET":
                    return self._send(200, {"sessions": []})
                if method == "DELETE":
                    return self._send(200, {"revoked": 0})
        if len(segments) == 2 and segments[0] == "sessions" and method == "DELETE":
            tenant.revoke_session(segments[1])
            return self._send(204)
        return self._send(404, {"error": "not_found"})
