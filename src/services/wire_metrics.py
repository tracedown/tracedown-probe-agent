"""Per-probe HTTP-layer byte accounting (ingress / egress).

The Lace executor performs its probe HTTP over the stdlib ``http.client``.
Because the agent runs the executor in-process, we can measure the *actual*
bytes that cross the HTTP layer without the executor surfacing anything — no
change to the canonical Lace ``ProbeResult``.

We count plaintext HTTP-message bytes (request line + headers + body on the way
out; status line + headers + body on the way in). For HTTPS this is the
decrypted application data, so http and https are directly comparable and the
TLS handshake / record overhead is excluded.

Counting is per-thread (probes run one-per-thread in the executor pool) and only
active inside :func:`measure`, so the agent's own traffic (mTLS bootstrap,
health) is never counted.
"""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_local = threading.local()


class _Counter:
    __slots__ = ("active", "egress", "ingress")

    def __init__(self) -> None:
        self.active = False
        self.ingress = 0
        self.egress = 0


def _counter() -> _Counter:
    c = getattr(_local, "counter", None)
    if c is None:
        c = _Counter()
        _local.counter = c
    return c


class _CountingReader:
    """Wraps a response's file object so every byte read is tallied as ingress."""

    def __init__(self, fp: Any) -> None:
        self._fp = fp

    def read(self, *args: Any) -> bytes:
        data = self._fp.read(*args)
        if data:
            c = _counter()
            if c.active:
                c.ingress += len(data)
        return data

    def readline(self, *args: Any) -> bytes:
        data = self._fp.readline(*args)
        if data:
            c = _counter()
            if c.active:
                c.ingress += len(data)
        return data

    def readinto(self, buf: Any) -> int:
        n = self._fp.readinto(buf)
        if n:
            c = _counter()
            if c.active:
                c.ingress += n
        return n

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fp, name)


_installed = False


def install() -> None:
    """Patches ``http.client`` once, at agent startup. Idempotent."""
    global _installed
    if _installed:
        return

    orig_send = http.client.HTTPConnection.send
    orig_resp_init = http.client.HTTPResponse.__init__

    def patched_send(self: http.client.HTTPConnection, data: Any) -> None:
        c = _counter()
        if c.active and isinstance(data, (bytes, bytearray)):
            c.egress += len(data)
        return orig_send(self, data)

    def patched_resp_init(self: http.client.HTTPResponse, *args: Any, **kwargs: Any) -> None:
        orig_resp_init(self, *args, **kwargs)
        # Wrap the socket file object *before* begin() reads the status line and
        # headers, so ingress covers the full response, not just the body.
        if _counter().active and getattr(self, "fp", None) is not None:
            self.fp = _CountingReader(self.fp)

    http.client.HTTPConnection.send = patched_send  # type: ignore[method-assign]
    http.client.HTTPResponse.__init__ = patched_resp_init  # type: ignore[method-assign]
    _installed = True


@contextmanager
def measure() -> Iterator[_Result]:
    """Activates byte counting for the current thread for the duration of the
    block. Read the totals from the yielded object after the block."""
    c = _counter()
    prev_active, prev_in, prev_eg = c.active, c.ingress, c.egress
    c.active, c.ingress, c.egress = True, 0, 0
    result = _Result()
    try:
        yield result
    finally:
        result.ingress = c.ingress
        result.egress = c.egress
        # Restore any enclosing measurement (defensive — probes don't nest).
        c.active, c.ingress, c.egress = prev_active, prev_in, prev_eg


class _Result:
    ingress: int = 0
    egress: int = 0
