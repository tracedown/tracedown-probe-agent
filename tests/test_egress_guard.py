"""Target-egress policy: the real blocklist, its config gating, and its
wiring into the tenant-probe executor.

The address-vetting *mechanism* (initial request + every redirect hop) lives in
the Lace executor and is covered there; these tests pin the agent's own
responsibilities: that the blocklist refuses the right addresses/hosts, that a
real probe to a blocked target is refused through the per-request executor, that
the rejectInvalidCerts override is passed through, and that both are gated on
the deployment environment.

Loopback sockets only — no external network.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest
from lacelang_executor import EgressBlocked

from config import AgentSettings
from models.job import JobPayload
from services import executor as executor_service
from services.egress_guard import guard

# ── The blocklist ───────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1",          # loopback
    "127.0.0.53",         # loopback (systemd-resolved)
    "10.0.0.5",           # RFC1918
    "172.16.9.9",         # RFC1918
    "192.168.1.1",        # RFC1918
    "169.254.169.254",    # link-local — cloud metadata endpoint
    "100.64.0.1",         # carrier-grade NAT (RFC6598)
    "0.0.0.0",            # unspecified
    "::1",                # IPv6 loopback
    "fd00::1",            # IPv6 ULA
    "fe80::1",            # IPv6 link-local
    "::ffff:127.0.0.1",   # IPv4-mapped loopback
    "::ffff:10.0.0.1",    # IPv4-mapped RFC1918
])
def test_blocked_addresses_are_refused(ip: str) -> None:
    with pytest.raises(EgressBlocked):
        guard("target.example.com", 443, ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.10", "1.1.1.1", "2606:4700::1111"])
def test_public_addresses_are_allowed(ip: str) -> None:
    # No exception — a public target is fine.
    guard("api.example.com", 443, ip)


@pytest.mark.parametrize("host", [
    "redis.railway.internal",
    "gateway.railway.internal",
    "railway.internal",
    "localhost",
    "SERVICE.RAILWAY.INTERNAL",  # case-insensitive
])
def test_blocked_internal_hostnames_are_refused(host: str) -> None:
    # Blocked on the host name alone, before the resolved address matters.
    with pytest.raises(EgressBlocked):
        guard(host, 6379, "203.0.113.10")


def test_unparseable_address_fails_closed() -> None:
    with pytest.raises(EgressBlocked):
        guard("api.example.com", 443, "not-an-ip")


# ── Config gating ───────────────────────────────────────────────────

def test_guards_default_off_in_dev() -> None:
    s = AgentSettings(deployment_env="dev")
    assert s.egress_guard_enabled is False
    assert s.force_tls_verify_enabled is False


def test_guards_default_on_in_production() -> None:
    s = AgentSettings(deployment_env="production")
    assert s.egress_guard_enabled is True
    assert s.force_tls_verify_enabled is True


def test_explicit_setting_overrides_environment() -> None:
    # Force off in production…
    s = AgentSettings(deployment_env="production", egress_guard=False,
                      force_tls_verify=False)
    assert s.egress_guard_enabled is False
    assert s.force_tls_verify_enabled is False
    # …and on in dev.
    s2 = AgentSettings(deployment_env="dev", egress_guard=True,
                       force_tls_verify=True)
    assert s2.egress_guard_enabled is True
    assert s2.force_tls_verify_enabled is True


# ── Wiring into the tenant-probe executor ───────────────────────────

class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@pytest.fixture
def loopback_server():
    server = HTTPServer(("127.0.0.1", 0), _OkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def _reset_policy():
    """Restore the module egress policy after a test mutates it."""
    before = executor_service._before_connect
    force = executor_service._force_verify_tls
    yield
    executor_service.init_egress_policy(before, force)


def test_real_guard_refuses_a_probe_to_a_blocked_target(loopback_server, _reset_policy):
    """With the real guard installed, a probe whose target resolves to a
    blocked (loopback) address fails — the guard is wired into the per-request
    executor and actually stops the connection."""
    executor_service.init_egress_policy(guard, False)
    executor_service.init_user_agent("")

    payload = JobPayload(script=f'get("{loopback_server}").expect(status: 200)')
    result = executor_service._run_sync(payload)

    assert result["outcome"] == "failure"
    assert "egress refused" in (result["calls"][0]["error"] or "")


def test_guard_disabled_lets_the_probe_through(loopback_server, _reset_policy):
    """Policy off (dev/e2e default): the same loopback probe succeeds — the
    seam is a no-op unless the deployment opts in."""
    executor_service.init_egress_policy(None, False)
    executor_service.init_user_agent("")

    payload = JobPayload(script=f'get("{loopback_server}").expect(status: 200)')
    result = executor_service._run_sync(payload)

    assert result["outcome"] == "success"
    assert result["calls"][0]["response"]["status"] == 200


def test_force_tls_verify_is_passed_to_the_executor(_reset_policy):
    """When the agent forces TLS verification, the per-request executor is
    constructed with force_verify_tls=True and the egress guard — so a script's
    rejectInvalidCerts=false is overridden by host policy."""
    executor_service.init_egress_policy(guard, True)

    captured: dict = {}
    real_cls = executor_service.LaceExecutor

    def spy(*args, **kwargs):
        captured.update(kwargs)
        return real_cls(*args, **kwargs)

    # A blocked address so the run fails fast (the guard refuses before any
    # socket work); we only assert on how the executor was configured, which is
    # captured at construction — before the run.
    payload = JobPayload(script='get("http://10.0.0.1/").expect(status: 200)')
    with patch.object(executor_service, "LaceExecutor", side_effect=spy):
        executor_service._run_sync(payload)

    assert captured.get("force_verify_tls") is True
    assert captured.get("before_connect") is guard
