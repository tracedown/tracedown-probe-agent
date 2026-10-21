"""How far a probe run has got, readable while it is still running.

The Lace executor returns its per-call records only when the whole run
completes. A run that outlives its budget is answered from outside, by a
stand-in result (``executor._run_budget_timeout``), and until now that
stand-in could say nothing but "did not finish": no call, no timing, no hint
whether the run was stuck resolving a name, waiting for a first byte, or
receiving a response that arrived too slowly.

This module keeps that record as the run goes. The run's thread writes to a
:class:`RunProgress` through hooks on the stdlib layers the executor's HTTP
goes through (``socket``, ``ssl``, ``http.client``); the thread that enforces
the budget reads a :meth:`RunProgress.snapshot` of it when the budget expires.
Nothing in the executor changes and nothing is added to a result that
completes.

What it records is where the run was, not whose fault that is. A response
that never starts looks the same from here whether the target hung or the
route to it did.

Hooks are per-thread and inert outside :func:`track`, so the agent's own
traffic (bootstrap, renewal, the health challenge) is never recorded.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from services import tcp_state

# Where a run can be. The first two are outside any request.
STARTING = "starting"
BETWEEN_REQUESTS = "between_requests"
RESOLVING = "resolving"
CONNECTING = "connecting"
TLS_HANDSHAKE = "tls_handshake"
SENDING = "sending"
AWAITING_RESPONSE = "awaiting_response"
RECEIVING = "receiving"
STORING_BODIES = "storing_bodies"


def _ms(since: float, until: float) -> int:
    return int((until - since) * 1000)


class _Request:
    """One HTTP request: a call's own, a redirect hop, or a retry."""

    __slots__ = (
        "bytes_received",
        "conn_id",
        "connect_ms",
        "dns_ms",
        "fd",
        "first_byte_ms",
        "host",
        "method",
        "name",
        "port",
        "started",
        "timed_out",
        "tls",
        "tls_ms",
        "url",
    )

    def __init__(self, conn_id: int, method: str, url: str, host: str, name: str, port: int, tls: bool) -> None:
        self.conn_id = conn_id
        self.method = method
        self.url = url
        self.host = host
        # The bare host name or address, without the port `host` may carry.
        self.name = name
        self.port = port
        self.tls = tls
        # The connection's descriptor, once it has one: what the kernel's
        # record of the connection is read through (tcp_state.read).
        self.fd = -1
        self.timed_out = False
        self.started = time.monotonic()
        self.dns_ms: int | None = None
        self.connect_ms: int | None = None
        self.tls_ms: int | None = None
        self.first_byte_ms: int | None = None
        self.bytes_received = 0


class RunProgress:
    """The record of one run. Written by the run's thread, read by another.

    Every field is a plain attribute assigned whole, so a reader sees either
    the old value or the new one; a snapshot taken mid-step is a moment late,
    never torn.
    """

    def __init__(self) -> None:
        self.phase = STARTING
        self.phase_since = time.monotonic()
        self.requests_completed = 0
        self.request: _Request | None = None
        self.ingress = 0
        self.egress = 0
        # One entry per request whose timer expired inside the executor (a
        # per-call timeout, or one attempt of a retried call), in order.
        self.timeouts: list[dict[str, Any]] = []

    def enter(self, phase: str) -> None:
        if phase != self.phase:
            self.phase = phase
            self.phase_since = time.monotonic()

    def snapshot(self) -> dict[str, Any] | None:
        """Where the run is now, or None when it has not begun any work.

        ``None`` keeps a run that never reached the executor (or one this
        module was not tracking) reported exactly as before.
        """
        now = time.monotonic()
        phase, since, request = self.phase, self.phase_since, self.request
        if phase == STARTING and self.requests_completed == 0:
            return None
        stall: dict[str, Any] = {
            "phase": phase,
            "phaseMs": _ms(since, now),
            "requestsCompleted": self.requests_completed,
            "request": None,
        }
        tcp = tcp_state.read(request.fd) if request is not None else None
        if request is not None and self.request is not request:
            # The request finished while it was being read: its descriptor may
            # already belong to something else.
            tcp = None
        stall["verdict"], stall["reason"] = tcp_state.verdict(phase, tcp)
        if request is not None:
            stall["target"] = _target(request)
            stall["tcp"] = tcp
            stall["request"] = {
                "method": request.method,
                "url": request.url,
                "elapsedMs": _ms(request.started, now),
                "dnsMs": request.dns_ms,
                "connectMs": request.connect_ms,
                "tlsMs": request.tls_ms,
                "ttfbMs": request.first_byte_ms,
                "bytesReceived": request.bytes_received,
            }
        return stall


def _target(request: _Request) -> dict[str, Any]:
    """Where a request went, in the form a second agent can be asked to reach."""
    return {"host": request.name, "port": request.port, "tls": request.tls}


def on_timeout() -> None:
    """Called where a request's timer expires on the run's thread.

    Records the connection's TCP state at that moment, before the executor
    closes it — afterwards the kernel's record is gone.
    """
    p = _current()
    request = p.request if p is not None else None
    if p is None or request is None or request.timed_out:
        return
    request.timed_out = True
    tcp = tcp_state.read(request.fd)
    verdict, reason = tcp_state.verdict(p.phase, tcp)
    p.timeouts.append({
        "at": time.time(),
        "phase": p.phase,
        "verdict": verdict,
        "reason": reason,
        "request": {"method": request.method, "url": request.url},
        "target": _target(request),
        "tcp": tcp,
    })


def describe(stall: dict[str, Any]) -> str:
    """One clause saying where a run was when its budget expired."""
    phase = stall["phase"]
    done = stall["requestsCompleted"]
    request = stall.get("request")
    if request is None:
        after = f"after {done} completed request{'' if done == 1 else 's'}"
        if phase == STORING_BODIES:
            return f"storing response bodies, {after}"
        return f"between requests, {after}"

    what = f"request {done + 1} ({request['method']} {request['url']})"
    waited = f"{stall['phaseMs']}ms"
    host = request["url"].split("/")[2] if "//" in request["url"] else request["url"]
    if phase == RESOLVING:
        return f"{what} was still resolving {host} after {waited}"
    if phase == CONNECTING:
        return f"{what} was still connecting after {waited}"
    if phase == TLS_HANDSHAKE:
        return f"{what} was still in the TLS handshake after {waited}"
    if phase == SENDING:
        return f"{what} was still being sent after {waited}"
    if phase == RECEIVING:
        return (
            f"{what} was still receiving its response: "
            f"{request['bytesReceived']} bytes in {waited}"
        )
    return f"{what} had no response after {waited}"


_local = threading.local()


def _current() -> RunProgress | None:
    return getattr(_local, "progress", None)


@contextmanager
def assign(progress: RunProgress) -> Iterator[None]:
    """Hands the current thread the record its run should keep.

    Assigning records nothing by itself: the run decides which part of its
    work is tracked (see :func:`track`).
    """
    previous = assigned()
    _local.assigned = progress
    try:
        yield
    finally:
        _local.assigned = previous


def assigned() -> RunProgress | None:
    return getattr(_local, "assigned", None)


@contextmanager
def track(progress: RunProgress) -> Iterator[None]:
    """Records the current thread's HTTP activity into [progress] for the block."""
    previous = _current()
    _local.progress = progress
    try:
        yield
    finally:
        _local.progress = previous


def on_sent(count: int) -> None:
    """Called by the byte counter for every chunk written to the wire."""
    p = _current()
    if p is None:
        return
    p.egress += count
    if p.request is not None:
        p.enter(SENDING)


def on_received(count: int) -> None:
    """Called by the byte counter for every chunk read off the wire."""
    p = _current()
    if p is None:
        return
    p.ingress += count
    request = p.request
    if request is None:
        return
    if request.first_byte_ms is None:
        request.first_byte_ms = _ms(request.started, time.monotonic())
    request.bytes_received += count
    p.enter(RECEIVING)


_installed = False


def install() -> None:
    """Hooks ``socket``, ``ssl`` and ``http.client`` once, at startup. Idempotent.

    Each hook wraps whatever is installed at the time, so it composes with the
    egress guard's own ``getaddrinfo``/``connect`` wrappers in either order.
    """
    global _installed
    if _installed:
        return

    orig_getaddrinfo = socket.getaddrinfo
    orig_connect = socket.socket.connect
    orig_wrap_socket = ssl.SSLContext.wrap_socket
    orig_request = http.client.HTTPConnection.request
    orig_close = http.client.HTTPConnection.close

    def getaddrinfo(*args: Any, **kwargs: Any) -> Any:
        p = _current()
        request = p.request if p is not None else None
        if p is None or request is None:
            return orig_getaddrinfo(*args, **kwargs)
        p.enter(RESOLVING)
        t0 = time.monotonic()
        try:
            return orig_getaddrinfo(*args, **kwargs)
        finally:
            request.dns_ms = _ms(t0, time.monotonic())

    def connect(self: socket.socket, address: Any) -> Any:
        p = _current()
        request = p.request if p is not None else None
        if p is None or request is None:
            return orig_connect(self, address)
        p.enter(CONNECTING)
        request.fd = self.fileno()
        t0 = time.monotonic()
        try:
            result = orig_connect(self, address)
        except TimeoutError:
            on_timeout()
            raise
        request.connect_ms = _ms(t0, time.monotonic())
        return result

    def wrap_socket(self: ssl.SSLContext, *args: Any, **kwargs: Any) -> Any:
        p = _current()
        request = p.request if p is not None else None
        if p is None or request is None:
            return orig_wrap_socket(self, *args, **kwargs)
        p.enter(TLS_HANDSHAKE)
        t0 = time.monotonic()
        try:
            result = orig_wrap_socket(self, *args, **kwargs)
        except TimeoutError:
            on_timeout()
            raise
        request.tls_ms = _ms(t0, time.monotonic())
        return result

    def request(
        self: http.client.HTTPConnection, method: str, url: str, *args: Any, **kwargs: Any
    ) -> None:
        p = _current()
        if p is None:
            return orig_request(self, method, url, *args, **kwargs)
        https = isinstance(self, http.client.HTTPSConnection)
        default_port = 443 if https else 80
        host = self.host if self.port == default_port else f"{self.host}:{self.port}"
        p.request = _Request(
            id(self), method, f"{'https' if https else 'http'}://{host}{url}", host, self.host, self.port, https
        )
        orig_request(self, method, url, *args, **kwargs)
        # The request is on the wire; whatever comes next is the peer's turn.
        p.enter(AWAITING_RESPONSE)
        return None

    def close(self: http.client.HTTPConnection) -> None:
        p = _current()
        if p is not None and p.request is not None and p.request.conn_id == id(self):
            p.request = None
            p.requests_completed += 1
            p.enter(BETWEEN_REQUESTS)
        orig_close(self)

    socket.getaddrinfo = getaddrinfo  # type: ignore[assignment]
    socket.socket.connect = connect  # type: ignore[assignment,method-assign]
    ssl.SSLContext.wrap_socket = wrap_socket  # type: ignore[method-assign]
    http.client.HTTPConnection.request = request  # type: ignore[method-assign]
    http.client.HTTPConnection.close = close  # type: ignore[method-assign]
    _installed = True
