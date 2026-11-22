"""Django's cache framework as a :class:`nine.Cache`."""

from __future__ import annotations

import hashlib
from typing import Any

from django.core.cache import BaseCache, caches

__all__ = ["DjangoCache"]

_PREFIX = "nine:"


class DjangoCache:
    """Adapts a Django cache (``CACHES[alias]``) to the 9in SDK's cache protocol.

    The SDK keeps the discovery document, signing keys, token answers (hybrid verification)
    and processed webhook ids here. ``add`` is ``cache.add``, which is atomic on Redis,
    Memcached and the database cache: use one of those, shared by every server, when you run
    more than one process. The local-memory cache is per process.
    """

    def __init__(self, alias: str = "default") -> None:
        self.alias = alias

    @property
    def backend(self) -> BaseCache:
        return caches[self.alias]

    @staticmethod
    def key(key: str) -> str:
        """A key every backend accepts (Memcached: at most 250 bytes, no spaces or control characters)."""
        if len(key) <= 200 and key.isascii() and all(33 <= ord(c) < 127 for c in key):
            return _PREFIX + key
        return _PREFIX + "h:" + hashlib.sha256(key.encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        return self.backend.get(self.key(key))

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        if ttl is not None and ttl <= 0:
            self.backend.delete(self.key(key))
            return
        self.backend.set(self.key(key), value, timeout=None if ttl is None else int(ttl))

    def delete(self, key: str) -> None:
        self.backend.delete(self.key(key))

    def add(self, key: str, value: Any, ttl: int | None = None) -> bool:
        if ttl is not None and ttl <= 0:
            return False
        return bool(self.backend.add(self.key(key), value, timeout=None if ttl is None else int(ttl)))
