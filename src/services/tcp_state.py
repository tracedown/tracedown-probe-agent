"""What the kernel knows about a stalled connection, and what that says.

A timeout seen from the agent alone is ambiguous: a target that took the
request and never answered, and a route that dropped the packets, both end in
an expired timer. The kernel's per-connection TCP state (``TCP_INFO``) is not
ambiguous about the part that matters:

- Every byte we sent acknowledged, nothing lost on the way in, and still no
  answer: the peer's TCP stack has the request and the application behind it
  is silent, or slow. That is the endpoint.
- Our segments still unacknowledged after retransmission, or segments arriving
  out of order (the ones before them were lost): the path is losing packets.
  That alone does not say whose end of the path it is — the scheduler asks a
  second agent to reach the same endpoint before deciding (``reach``).

Behind a CDN or load balancer the peer is that front, so "endpoint" means the
endpoint as its users reach it: a slow origin behind a healthy edge is the
endpoint's.

Linux only. Anywhere else, or where the call fails, there is no reading and the
verdict is ``unknown``, which the scheduler treats exactly as a timeout was
treated before any of this existed.
"""

from __future__ import annotations

import socket
import ssl
import struct
import time
from typing import Any

from services.egress_guard import EgressBlocked

# struct tcp_info (include/uapi/linux/tcp.h), up to rcv_ooopack. Older kernels
# return a shorter struct; fields past what they filled are reported as None.
_FIELDS: tuple[tuple[str, str], ...] = (
    *((name, "B") for name in (
        "state", "ca_state", "retransmits", "probes", "backoff", "options", "wscale", "flags",
    )),
    *((name, "I") for name in (
        "rto", "ato", "snd_mss", "rcv_mss", "unacked", "sacked", "lost", "retrans", "fackets",
        "last_data_sent", "last_ack_sent", "last_data_recv", "last_ack_recv",
        "pmtu", "rcv_ssthresh", "rtt", "rttvar", "snd_ssthresh", "snd_cwnd", "advmss", "reordering",
        "rcv_rtt", "rcv_space", "total_retrans",
    )),
    *((name, "Q") for name in ("pacing_rate", "max_pacing_rate", "bytes_acked", "bytes_received")),
    *((name, "I") for name in (
        "segs_out", "segs_in", "notsent_bytes", "min_rtt", "data_segs_in", "data_segs_out",
    )),
    *((name, "Q") for name in ("delivery_rate", "busy_time", "rwnd_limited", "sndbuf_limited")),
    *((name, "I") for name in ("delivered", "delivered_ce")),
    *((name, "Q") for name in ("bytes_sent", "bytes_retrans")),
    *((name, "I") for name in ("dsack_dups", "reord_seen", "rcv_ooopack")),
)


def _offsets() -> dict[str, tuple[int, str]]:
    out: dict[str, tuple[int, str]] = {}
    fmt = "@"
    for name, code in _FIELDS:
        # Native alignment, as the kernel lays the struct out.
        start = struct.calcsize(fmt + code) - struct.calcsize(code)
        out[name] = (start, code)
        fmt += code
    return out


_OFFSETS = _offsets()
_SIZE = max(start + struct.calcsize(code) for start, code in _OFFSETS.values())
_TCP_INFO = getattr(socket, "TCP_INFO", None)

# What is kept on a result. Times in milliseconds.
_KEPT = (
    "state", "retransmits", "backoff", "unacked", "lost", "total_retrans", "rtt", "min_rtt",
    "last_data_recv", "last_ack_recv", "bytes_received", "data_segs_in", "rcv_ooopack", "dsack_dups",
)
_MICROSECONDS = ("rtt", "min_rtt")

# TCP states (include/net/tcp_states.h) worth naming.
_STATES = {1: "established", 2: "syn_sent", 4: "fin_wait1", 7: "close", 8: "close_wait"}


def read(fd: int) -> dict[str, Any] | None:
    """The TCP state of the connection on [fd], or None when it cannot be read.

    Reads through a duplicate of the descriptor, so it is safe from any thread
    and never closes or disturbs the connection itself.
    """
    if _TCP_INFO is None or fd < 0:
        return None
    try:
        dup = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    try:
        raw = dup.getsockopt(socket.IPPROTO_TCP, _TCP_INFO, _SIZE)
    except OSError:
        return None
    finally:
        dup.close()
    info: dict[str, Any] = {}
    for name in _KEPT:
        start, code = _OFFSETS[name]
        end = start + struct.calcsize(code)
        info[name] = struct.unpack_from("@" + code, raw, start)[0] if len(raw) >= end else None
    for name in _MICROSECONDS:
        if info[name] is not None:
            info[name] //= 1000
    info["state"] = _STATES.get(info["state"], info["state"])
    return info


# A received segment out of order means the one before it was lost (or the
# path reorders, which healthy paths do rarely). Both a count and a share, so a
# single reordered segment on a long transfer is not called a lossy path.
_OOO_MIN = 2
_OOO_SHARE = 0.01


def lossy(tcp: dict[str, Any]) -> bool | None:
    """Whether the connection shows packet loss, or None when it cannot tell."""
    if (tcp.get("total_retrans") or 0) > 0 or (tcp.get("retransmits") or 0) > 0:
        return True
    ooo = tcp.get("rcv_ooopack")
    if ooo is None:
        return None
    segs = tcp.get("data_segs_in") or 0
    return ooo >= _OOO_MIN and ooo >= segs * _OOO_SHARE


# Where a run can be, as run_progress names it.
_WIRE_PHASES = ("connecting", "tls_handshake", "sending", "awaiting_response", "receiving")
_AGENT_PHASES = ("between_requests", "storing_bodies")


def verdict(phase: str, tcp: dict[str, Any] | None) -> tuple[str, str]:
    """Who a stall belongs to, and why, from where it stood and its TCP state.

    ``endpoint`` — the peer has everything we sent and the path lost nothing;
    ``network`` — the path lost packets, or nothing answered at all; the
    scheduler settles whose end it is; ``agent`` — the run was in the agent's
    own work, outside any request; ``unknown`` — nothing to judge by.
    """
    if phase in _AGENT_PHASES:
        return "agent", "the run was in the agent's own work, outside any request"
    if phase == "resolving":
        return "network", "the name did not resolve"
    if phase not in _WIRE_PHASES or tcp is None:
        return "unknown", "no connection state to judge by"
    if phase == "connecting" or tcp.get("state") == "syn_sent":
        return "network", "the connection was never accepted"
    loss = lossy(tcp)
    if loss:
        return "network", "the path was losing packets"
    if loss is None:
        return "unknown", "this kernel does not report receive-side loss"
    if (tcp.get("unacked") or 0) > 0:
        # In flight, not yet acknowledged, no retransmission yet: too early to say.
        return "unknown", "the last data sent was not yet acknowledged"
    return "endpoint", "the endpoint acknowledged everything sent and the path lost nothing"


def reach(host: str, port: int, use_tls: bool, attempts: int = 3, timeout_s: float = 4.0) -> dict[str, Any]:
    """Opens connections to [host]:[port] and reports whether the path is clean.

    The witness side of a ``network`` verdict: run by a second agent, it shows
    whether the endpoint is reachable from somewhere else. A connection and,
    for https, a TLS handshake — never an HTTP request, so it cannot change
    anything on the endpoint. Several attempts, because a handshake is a few
    packets and a path losing enough to stall a response loses some of them.
    The certificate is not checked: what is measured is the path, and nothing
    received is trusted.

    ``clean`` — every attempt connected (and shook hands) with no packet lost;
    ``lossy`` — connected, with loss; ``unreachable`` — some attempt failed;
    ``refused`` — this agent's egress policy does not let it dial the target.
    Only ``clean`` clears the endpoint.
    """
    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except EgressBlocked as e:
        # Not this agent's to reach; says nothing about the path.
        return {"path": "refused", "error": str(e), "attempts": []}
    except OSError as e:
        return {"path": "unreachable", "error": f"name did not resolve: {e}", "attempts": []}
    dns_ms = int((time.monotonic() - started) * 1000)
    family, kind, proto, _, address = infos[0]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    results: list[dict[str, Any]] = []
    path = "clean"
    for _ in range(attempts):
        attempt: dict[str, Any] = {}
        sock = socket.socket(family, kind, proto)
        sock.settimeout(timeout_s)
        try:
            t0 = time.monotonic()
            sock.connect(address)
            attempt["connectMs"] = int((time.monotonic() - t0) * 1000)
            if use_tls:
                t1 = time.monotonic()
                sock = context.wrap_socket(sock, server_hostname=host)
                attempt["tlsMs"] = int((time.monotonic() - t1) * 1000)
            tcp = read(sock.fileno())
            attempt["tcp"] = tcp
            if tcp is not None and lossy(tcp):
                path = "lossy"
        except EgressBlocked as e:
            return {"path": "refused", "error": str(e), "attempts": results}
        except (OSError, ssl.SSLError) as e:
            attempt["error"] = str(e) or type(e).__name__
            tcp = read(sock.fileno())
            attempt["tcp"] = tcp
            path = "unreachable"
        finally:
            sock.close()
        results.append(attempt)
        if path == "unreachable":
            break
    return {"path": path, "address": address[0], "dnsMs": dns_ms, "attempts": results}
