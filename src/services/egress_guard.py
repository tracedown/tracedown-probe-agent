"""Target-egress policy enforced inside the agent process (SSRF hardening).

The gateway and scheduler vet a target's host up front, but the agent is the
process that resolves DNS and dials the socket — and a tenant probe can 30x its
way to an internal address after that check, or point DNS at one. The Lace
executor is treated here as an unmodified black box: rather than asking it for a
hook, we intercept the socket layer it stands on.

``install()`` monkeypatches ``socket.getaddrinfo`` and ``socket.socket.connect``
once, process-wide. The patches enforce the blocklist **only** while a
thread-local flag is set — which :func:`active` does for the duration of a
single tenant-probe execution. Because the check happens at resolution/connect
time it covers the initial request and every redirect hop the executor follows
internally, with no executor API involved. Everything else the agent does
(health challenge to the internal gateway, mTLS bootstrap/renewal, S3 body
upload) runs without the flag set and is never affected.

The companion TLS check (:func:`script_rejects_tls_verification`) is a static
inspection of the parsed script: in the hosted deployment the agent refuses to
run a tenant script that turns certificate verification off, rather than
reaching into Lace to override it.

Non-http(s) schemes never reach here — the executor's HTTP layer only speaks
http/https and rejects the rest itself.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class EgressBlocked(OSError):
    """Raised when a connection to a disallowed address/host is attempted while
    the guard is active. Subclasses ``OSError`` so it surfaces through the
    executor's normal transport-error path as a call failure — the executor
    catches ``OSError`` from ``getaddrinfo`` / ``connect`` and records it as the
    call's error, exactly as it would a refused connection or a DNS failure.
    """


# Internal service hostnames that must never be probed, matched on the request
# host as an exact name or a subdomain. Railway's private network hands out
# ``*.railway.internal`` names; the resolved IPv6 ULA would also trip the IP
# checks below, but a name check refuses them even if resolution or address
# family would slip past.
_BLOCKED_HOST_SUFFIXES: tuple[str, ...] = (
    "railway.internal",
    "localhost",
)

# Address ranges no probe may reach. Kept explicit (rather than leaning on
# ``ipaddress`` property flags alone) so the carrier-grade-NAT block and the
# exact CIDRs are auditable and stable across Python versions — e.g. whether
# 100.64.0.0/10 counts as ``is_private`` has changed between releases.
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),        # "this host" / unspecified
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),    # RFC6598 carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (incl. instance metadata)
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918 private
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918 private
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("::/128"),           # IPv6 unspecified
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local (ULA)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
)


def _host_is_blocked(host: str) -> bool:
    h = host.strip().lower().rstrip(".")
    if not h:
        return True
    for suffix in _BLOCKED_HOST_SUFFIXES:
        if h == suffix or h.endswith("." + suffix):
            return True
    return False


def _ip_is_blocked(ip: str) -> bool:
    # Drop any IPv6 zone/scope id ("fe80::1%eth0") before parsing.
    raw = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        # Unparseable / non-IP target — fail closed.
        return True
    # IPv4-mapped IPv6 ("::ffff:127.0.0.1") is unwrapped so the mapped v4
    # address is checked against the v4 ranges rather than slipping past.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if addr.is_loopback or addr.is_link_local or addr.is_multicast \
            or addr.is_unspecified or addr.is_reserved:
        return True
    for net in _BLOCKED_NETWORKS:
        if addr.version == net.version and addr in net:
            return True
    return False


# ── Per-thread activation ───────────────────────────────────────────

_local = threading.local()


def _is_active() -> bool:
    return getattr(_local, "active", False)


@contextmanager
def active() -> Iterator[None]:
    """Enforce the egress policy for the duration of this block, on this thread.

    Wrap ONLY the executor's run call — not body upload or any other agent I/O —
    so internal traffic (S3, gateway) is never caught by the guard.
    """
    prev = getattr(_local, "active", False)
    _local.active = True
    try:
        yield
    finally:
        _local.active = prev


# ── Socket-layer interception ───────────────────────────────────────

_installed = False
_orig_getaddrinfo: Any = None
_orig_connect: Any = None


def _guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
    results = _orig_getaddrinfo(host, port, *args, **kwargs)
    if _is_active():
        if host is not None and _host_is_blocked(str(host)):
            raise EgressBlocked(
                f"egress refused: {host!s} is a blocked internal host"
            )
        # Reject the whole resolution if ANY returned address is blocked — do
        # not silently keep the "good" ones, or an attacker who pads the DNS
        # answer with one public IP could slip an internal address through.
        for sockaddr in (r[4] for r in results):
            ip = sockaddr[0]
            if _ip_is_blocked(str(ip)):
                raise EgressBlocked(
                    f"egress refused: {host!s} resolves to blocked address {ip}"
                )
    return results


def _guarded_connect(self: socket.socket, address: Any) -> Any:
    if _is_active():
        # AF_INET/AF_INET6 addresses are (ip, port[, flow, scope]); anything
        # else (AF_UNIX path, malformed) has no IP to vet — fail closed.
        ip = address[0] if isinstance(address, tuple) and address else None
        if ip is None or _ip_is_blocked(str(ip)):
            raise EgressBlocked(f"egress refused: blocked connect target {address!r}")
    return _orig_connect(self, address)


def install() -> None:
    """Monkeypatch the socket layer once. Idempotent. The patches enforce only
    while :func:`active` is in effect on the calling thread, so installing them
    is harmless to everything that runs outside a guarded probe."""
    global _installed, _orig_getaddrinfo, _orig_connect
    if _installed:
        return
    _orig_getaddrinfo = socket.getaddrinfo
    _orig_connect = socket.socket.connect
    socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
    socket.socket.connect = _guarded_connect  # type: ignore[assignment,method-assign]
    _installed = True


# ── Static TLS-verification check (SEC-H6) ──────────────────────────

def script_rejects_tls_verification(ast: dict[str, Any]) -> bool:
    """True if any call in the parsed script sets ``security.rejectInvalidCerts``
    to ``false``. The grammar makes this a bool literal, so the parsed config
    carries a plain ``False`` — no expression evaluation needed. The hosted
    agent refuses to run such a script rather than overriding Lace internals.
    """
    for call in ast.get("calls", []) or []:
        security = (call.get("config") or {}).get("security")
        if isinstance(security, dict) and security.get("rejectInvalidCerts") is False:
            return True
    return False
