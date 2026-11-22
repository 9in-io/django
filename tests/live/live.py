"""Settings of the live 9in test tenants, a cookie-jar browser for the hosted pages, and the
receiver Worker's records (the same helpers as 9in's own e2e suites, in Python).

Settings come from the file named by NINE_E2E_ENV (KEY=value lines); E2E_<KEY> environment
variables override it. Values are never printed.
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

_values: dict[str, str] | None = None

#: A marker unique to this run, in test users' emails.
RUN = time.strftime("%y%m%d%H%M") + secrets.token_hex(2)


def _load() -> dict[str, str]:
    global _values
    if _values is None:
        values: dict[str, str] = {}
        path = os.environ.get("NINE_E2E_ENV")
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    match = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
                    if match:
                        values[match.group(1)] = match.group(2)
        for key, value in os.environ.items():
            if key.startswith("E2E_"):
                values[key[4:]] = value
        _values = values
    return _values


def env(name: str) -> str:
    value = _load().get(name, "")
    if not value:
        raise RuntimeError(f"E2E setting {name} is missing (NINE_E2E_ENV file or E2E_{name})")
    return value


def has(name: str) -> bool:
    return bool(_load().get(name))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Browser:
    """A cookie jar per host with manual redirects: enough to drive 9in's hosted pages."""

    def __init__(self) -> None:
        self.cookies: dict[str, dict[str, str]] = {}
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(self, method: str, url: str, form: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
        host = urlsplit(url).netloc
        headers = {"User-Agent": "9in-e2e-django/1.0"}
        jar = self.cookies.get(host, {})
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        data = None
        if form is not None:
            data = urlencode(form).encode()
            parts = urlsplit(url)
            headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"{parts.scheme}://{parts.netloc}",
                    "Referer": url,
                }
            )
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self._opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        for header in response.headers.get_all("Set-Cookie") or []:
            pair, _, attributes = header.partition(";")
            name, _, value = pair.partition("=")
            jar = self.cookies.setdefault(host, {})
            if not value.strip() or re.search(r"max-age=0\b", attributes, re.I):
                jar.pop(name.strip(), None)
            else:
                jar[name.strip()] = value.strip()
        body = response.read().decode("utf-8", "replace")
        return response.status, {k.lower(): v for k, v in response.headers.items()}, body

    def follow(self, url: str, stop_at: str | None = None) -> tuple[str, int, str | None]:
        """Follows redirects until one points at ``stop_at`` (not requested: html is None) or a page."""
        current = url
        for _ in range(20):
            if stop_at and current.startswith(stop_at):
                return current, 302, None
            status, headers, body = self.request("GET", current)
            if 300 <= status < 400 and headers.get("location"):
                current = urljoin(current, headers["location"])
                continue
            return current, status, body
        raise RuntimeError("too many redirects")


def _form(page: str, page_url: str) -> tuple[str, dict[str, str]]:
    form = page.split("<form", 1)[1].split("</form>", 1)[0] if "<form" in page else ""
    action = re.search(r'action="([^"]*)"', form)
    fields: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", form):
        if 'type="hidden"' not in tag:
            continue
        name = re.search(r'name="([^"]+)"', tag)
        value = re.search(r'value="([^"]*)"', tag)
        if name:
            fields[name.group(1)] = html.unescape(value.group(1) if value else "")
    return urljoin(page_url, html.unescape(action.group(1)) if action and action.group(1) else page_url), fields


def text(page: str) -> str:
    page = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", page)
    return re.sub(r"\s+", " ", html.unescape(page)).strip()


def sign_in(
    authorize_url: str, redirect_uri: str, identifier: str, password: str, browser: Browser | None = None
) -> dict[str, Any]:
    """Signs in on the hosted page; ``callback`` is the URL 9in redirected to, else ``page`` says why."""
    browser = browser or Browser()
    url, status, page = browser.follow(authorize_url, redirect_uri)
    if page is None:
        return {"callback": url, "page": None, "status": 302}
    if 'name="identifier"' not in page:
        return {"callback": None, "page": text(page)[:500], "status": status}
    action, fields = _form(page, url)
    status, headers, body = browser.request(
        "POST", action, {**fields, "identifier": identifier, "password": password, "action": "password"}
    )
    if not headers.get("location"):
        return {"callback": None, "page": text(body)[:500], "status": status}
    url, status, page = browser.follow(urljoin(action, headers["location"]), redirect_uri)
    return (
        {"callback": url, "page": None, "status": 302}
        if page is None
        else {"callback": None, "page": text(page)[:500], "status": status}
    )


def records(kind: str) -> list[dict[str, Any]]:
    url = f"{env('RECEIVER_URL')}/records?" + urlencode({"kind": kind, "t": env("RECEIVER_TOKEN")})
    status, _, body = Browser().request("GET", url)
    if status != 200:
        raise RuntimeError(f"receiver: {status}")
    return json.loads(body)


def wait_for(kind: str, match: Callable[[dict[str, Any]], bool], timeout: float = 60) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for record in records(kind):
            if match(record):
                return record
        time.sleep(1.5)
    raise TimeoutError(f"no {kind} record arrived")
