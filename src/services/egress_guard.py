"""Target-egress policy for the process that actually opens the connection.

The scheduler and gateway vet a target's host up front, but the agent is the
process that resolves DNS and dials the socket — and a tenant probe can 30x its
way to an internal address after that check, or point DNS at one. This module
is the last line: a guard invoked by the Lace executor with the concrete
resolved address just before every connect (initial request and every redirect
hop), which refuses connections to loopback, link-local, carrier-grade NAT,
RFC1918 / ULA private ranges, and internal service hostnames.

The executor calls the guard with the address it is about to dial and connects
to that same vetted address (no re-resolution), so approving an address pins
it — closing the DNS-rebinding and redirect-to-internal windows.

Non-http(s) schemes are refused by the executor's HTTP layer itself (it only
speaks http/https), so they never reach a guard.
"""

from __future__ import annotations

import ipaddress

from lacelang_executor import EgressBlocked

# Internal service hostnames that must never be probed, matched on the request
# host (before resolution) as an exact name or a subdomain. Railway's private
# network hands out ``*.railway.internal`` names that resolve to addresses the
# IP checks below would also catch on IPv6 ULA — but a name check refuses them
# even where resolution or address family would slip past.
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
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (incl. cloud metadata)
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
        # Unparseable address — fail closed.
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


def guard(host: str, port: int, resolved_ip: str) -> None:
    """Egress guard: refuse connections to internal / private targets.

    Raises :class:`lacelang_executor.EgressBlocked` (an ``OSError`` subclass the
    executor surfaces as a normal call failure) when the request host is an
    internal service name or the address about to be dialled is in a blocked
    range. Returns normally to allow the connection.
    """
    if _host_is_blocked(host):
        raise EgressBlocked(
            f"egress refused: {host} is a blocked internal host"
        )
    if _ip_is_blocked(resolved_ip):
        raise EgressBlocked(
            f"egress refused: {host} resolves to blocked address {resolved_ip}"
        )
