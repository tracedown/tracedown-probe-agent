"""Target-egress policy: the blocklist, socket-layer enforcement, the TLS
refusal, config gating, and their wiring into the tenant-probe path.

The guard is implemented entirely in the agent — the Lace executor is an
unmodified black box. Enforcement is at the socket layer (``getaddrinfo`` /
``connect``), active only while a probe runs, so it covers the initial request
and every redirect hop the executor follows internally with no executor API.

Loopback sockets only — no external network.
"""

from __future__ import annotations

import http.client
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from lacelang_validator.parser import parse

from config import AgentSettings
from models.job import JobPayload
from services import egress_guard
from services import executor as executor_service
from services.egress_guard import EgressBlocked

# ── The blocklist ───────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1",          # loopback
    "127.0.0.53",         # loopback (systemd-resolved)
    "10.0.0.5",           # RFC1918
    "172.16.9.9",         # RFC1918
    "192.168.1.1",        # RFC1918
    "169.254.169.254",    # link-local — instance metadata endpoint
    "100.64.0.1",         # carrier-grade NAT (RFC6598)
    "0.0.0.0",            # unspecified
    "::1",                # IPv6 loopback
    "fd00::1",            # IPv6 ULA
    "fe80::1",            # IPv6 link-local
    "::ffff:127.0.0.1",   # IPv4-mapped loopback
    "::ffff:10.0.0.1",    # IPv4-mapped RFC1918
])
def test_blocked_addresses(ip: str) -> None:
    assert egress_guard._ip_is_blocked(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.10", "1.1.1.1", "2606:4700::1111"])
def test_public_addresses_allowed(ip: str) -> None:
    assert egress_guard._ip_is_blocked(ip) is False


def test_unparseable_address_fails_closed() -> None:
    assert egress_guard._ip_is_blocked("not-an-ip") is True


@pytest.mark.parametrize("host", [
    "redis.railway.internal",
    "gateway.railway.internal",
    "railway.internal",
    "localhost",
    "SERVICE.RAILWAY.INTERNAL",  # case-insensitive
])
def test_blocked_internal_hostnames(host: str) -> None:
    assert egress_guard._host_is_blocked(host) is True


@pytest.mark.parametrize("host", ["api.example.com", "railwayinternal.com", "notlocalhost.dev"])
def test_public_hostnames_allowed(host: str) -> None:
    assert egress_guard._host_is_blocked(host) is False


# ── Static TLS-verification check ───────────────────────────────────

def test_script_rejects_tls_off() -> None:
    ast = parse('get("https://a/", { security: { rejectInvalidCerts: false } }).expect(status: 200)')
    assert egress_guard.script_rejects_tls_verification(ast) is True


def test_script_rejects_tls_off_on_a_later_call() -> None:
    ast = parse(
        'get("https://a/").expect(status: 200)\n'
        'get("https://b/", { security: { rejectInvalidCerts: false } }).check(status: 200)'
    )
    assert egress_guard.script_rejects_tls_verification(ast) is True


def test_script_allows_tls_on_or_default() -> None:
    ast = parse('get("https://a/", { security: { rejectInvalidCerts: true } }).expect(status: 200)')
    assert egress_guard.script_rejects_tls_verification(ast) is False
    ast2 = parse('get("https://a/").expect(status: 200)')
    assert egress_guard.script_rejects_tls_verification(ast2) is False


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
    s = AgentSettings(deployment_env="production", egress_guard=False, force_tls_verify=False)
    assert s.egress_guard_enabled is False
    assert s.force_tls_verify_enabled is False
    s2 = AgentSettings(deployment_env="dev", egress_guard=True, force_tls_verify=True)
    assert s2.egress_guard_enabled is True
    assert s2.force_tls_verify_enabled is True


# ── Loopback server + fixtures ──────────────────────────────────────

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
    """Restore module egress policy after a test mutates it. The socket patches
    stay installed (inert unless active), which is fine."""
    before_enabled = executor_service._egress_enabled
    before_reject = executor_service._reject_insecure_tls
    yield
    executor_service._egress_enabled = before_enabled
    executor_service._reject_insecure_tls = before_reject


# ── Socket-layer enforcement ────────────────────────────────────────

def test_connect_allowed_when_guard_inactive(loopback_server):
    """Installed but inactive: loopback connects normally — the patch is inert
    outside an active() block."""
    egress_guard.install()
    p = urllib.parse.urlsplit(loopback_server)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=2)
    conn.request("GET", "/")
    assert conn.getresponse().status == 200
    conn.close()


def test_connect_blocked_when_guard_active(loopback_server):
    """Inside active(): the same loopback connect is refused at the socket
    layer (getaddrinfo/connect), before any bytes flow."""
    egress_guard.install()
    p = urllib.parse.urlsplit(loopback_server)
    with pytest.raises(EgressBlocked), egress_guard.active():
        http.client.HTTPConnection(p.hostname, p.port, timeout=2).connect()


def test_active_flag_is_restored_after_block(loopback_server):
    """A block inside active() must not leave the thread guarded afterwards."""
    egress_guard.install()
    p = urllib.parse.urlsplit(loopback_server)
    with pytest.raises(EgressBlocked), egress_guard.active():
        http.client.HTTPConnection(p.hostname, p.port, timeout=2).connect()
    # Guard is off again: loopback works.
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=2)
    conn.request("GET", "/")
    assert conn.getresponse().status == 200
    conn.close()


# ── Wiring into the tenant-probe path (_run_sync) ───────────────────

def test_run_sync_refuses_probe_to_blocked_target(loopback_server, _reset_policy):
    """Egress on: a probe whose target resolves to a blocked (loopback) address
    fails through the executor — the guard is wired around the run."""
    executor_service.init_egress_policy(True, False)
    payload = JobPayload(script=f'get("{loopback_server}").expect(status: 200)')
    result = executor_service._run_sync(payload)
    assert result["outcome"] == "failure"
    assert "egress refused" in (result["calls"][0]["error"] or "")


def test_run_sync_allows_probe_when_egress_off(loopback_server, _reset_policy):
    """Egress off (dev/e2e default): the same loopback probe succeeds — the
    guard is a no-op unless the deployment opts in."""
    executor_service.init_egress_policy(False, False)
    payload = JobPayload(script=f'get("{loopback_server}").expect(status: 200)')
    result = executor_service._run_sync(payload)
    assert result["outcome"] == "success"
    assert result["calls"][0]["response"]["status"] == 200


# A host that can never resolve (RFC 2606), so a refusal that failed to
# refuse would fail loudly here instead of dialling the internet.
TLS_OFF_SCRIPT = (
    'get("https://target.invalid/", { security: { rejectInvalidCerts: false } })'
    '.expect(status: 200)'
)

REFUSAL_EVENT = {
    "callIndex": -1,
    "conditionIndex": -1,
    "trigger": "error",
    "scope": None,
    "notification": {
        "tag": "text",
        "value": (
            "${s.name} in ${w.name}.${p.name} is not being run: TLS certificate "
            "verification is required here; remove `security: { rejectInvalidCerts: "
            "false }` from the script"
        ),
    },
}


def _assert_refusal(result: dict) -> None:
    """The result is the agent's own refusal, not something the executor ran."""
    assert result["outcome"] == "failure"
    assert result["calls"] == []
    assert result["error"] == executor_service._TLS_POLICY_REFUSAL_ERROR
    assert result["runVars"] == {}
    assert result["elapsedMs"] == 0
    assert result["startedAt"] == result["endedAt"]
    assert result["ingressBytes"] == 0 and result["egressBytes"] == 0


def test_run_sync_refuses_script_disabling_tls(_reset_policy):
    """TLS policy on: a script setting rejectInvalidCerts=false is declined
    before any wire activity — no calls, explanatory error, and an `error`
    notification event: the refusal never reached the executor, so no
    extension rule could have raised the event a failure is alerted on."""
    executor_service.init_egress_policy(False, True)
    result = executor_service._run_sync(JobPayload(script=TLS_OFF_SCRIPT))
    _assert_refusal(result)
    assert result["actions"] == {"notifications": [REFUSAL_EVENT]}


def test_run_sync_refusal_is_announced_every_tick(_reset_policy):
    """A refused script is refused again every tick until it is changed, and
    every refusal carries the event — a single announcement could be lost to
    the dispatcher's failure cooldown with no second chance. Whatever `prev`
    says makes no difference."""
    executor_service.init_egress_policy(False, True)

    first = executor_service._run_sync(JobPayload(script=TLS_OFF_SCRIPT))
    _assert_refusal(first)

    repeat = executor_service._run_sync(JobPayload(script=TLS_OFF_SCRIPT, prev=first))
    _assert_refusal(repeat)
    assert repeat["actions"] == {"notifications": [REFUSAL_EVENT]}


def test_run_after_refusal_recovers(loopback_server, _reset_policy):
    """The refusal is a failure like any other to the run that follows it: a
    fixed script succeeding with the refusal as `prev` emits `recovered`, in
    exactly the shape the agent's own events copy."""
    executor_service.init_egress_policy(False, True)
    refusal = executor_service._run_sync(JobPayload(script=TLS_OFF_SCRIPT))

    fixed = JobPayload(script=f'get("{loopback_server}").expect(status: 200)', prev=refusal)
    result = executor_service._run_sync(fixed)
    assert result["outcome"] == "success"
    assert result["actions"]["notifications"] == [
        {
            "callIndex": -1,
            "conditionIndex": -1,
            "trigger": "recovered",
            "scope": None,
            "notification": {"tag": "text", "value": "${s.name} in ${w.name}.${p.name} recovered"},
        }
    ]


def test_run_sync_allows_tls_verifying_script(loopback_server, _reset_policy):
    """TLS policy on but the script does not disable verification: it runs
    normally (against a loopback target, egress off)."""
    executor_service.init_egress_policy(False, True)
    payload = JobPayload(script=f'get("{loopback_server}").expect(status: 200)')
    result = executor_service._run_sync(payload)
    assert result["outcome"] == "success"
    # The agent adds no event of its own to a result the executor produced.
    assert "notifications" not in result["actions"]
