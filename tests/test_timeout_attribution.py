"""Whose a timeout is: the endpoint's, the path's, or the agent's.

Read from the kernel's record of the stalled connection at the moment its
timer expired (``services.tcp_state``). These run against real sockets; packet
loss cannot be produced on loopback without privileges, so the loss rules are
pinned on recorded connection states instead.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterator
from typing import Any

import pytest

from models.job import JobPayload
from services import executor as executor_service
from services import tcp_state
from tests.test_run_progress import (
    _instrumented,  # noqa: F401 — the same instrumented pool
)

pytestmark = pytest.mark.skipif(not hasattr(socket, "TCP_INFO"), reason="TCP_INFO is Linux-only")


def _run(script: str, budget_ms: int = 5_000) -> dict[str, Any]:
    return asyncio.run(executor_service.execute_probe(JobPayload(script=script, requestTimeoutMs=budget_ms)))


@pytest.fixture
def unaccepting() -> Iterator[int]:
    """A port whose accept queue is full, so a further connection is never accepted.

    The kernel drops the SYN rather than refusing it, which from the client is
    a connection that hangs — what a dead route or a host gone dark look like.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(0)
    port = listener.getsockname()[1]
    fillers = []
    for _ in range(4):
        s = socket.socket()
        s.setblocking(False)
        s.connect_ex(("127.0.0.1", port))
        fillers.append(s)
    try:
        yield port
    finally:
        for s in fillers:
            s.close()
        listener.close()


def test_an_endpoint_that_took_the_request_and_never_answered_is_the_endpoints(server) -> None:
    base = server(lambda conn: None)

    result = _run(f'get("{base}/slow", {{ timeout: {{ ms: 500, action: "fail" }} }}).expect(status: 200)')

    assert result["outcome"] == "timeout"
    attribution = result["attribution"]
    assert attribution["verdict"] == "endpoint"
    [call] = attribution["calls"]
    assert call["callIndex"] == 0
    assert call["phase"] == "awaiting_response"
    assert call["request"] == {"method": "GET", "url": f"{base}/slow"}
    # The kernel's own word for it: everything sent was acknowledged.
    assert call["tcp"]["unacked"] == 0
    assert call["tcp"]["total_retrans"] == 0
    assert "target" not in attribution


def test_a_retried_call_is_judged_by_its_last_attempt(server) -> None:
    base = server(lambda conn: None)

    result = _run(
        f'get("{base}/slow", {{ timeout: {{ ms: 300, action: "retry", retries: 1 }} }}).expect(status: 200)'
    )

    assert result["outcome"] == "timeout"
    assert result["attribution"]["verdict"] == "endpoint"
    assert len(result["attribution"]["calls"]) == 1


def test_a_connection_never_accepted_is_put_to_the_path_with_a_target_to_check(unaccepting) -> None:
    result = _run(
        f'get("http://127.0.0.1:{unaccepting}/x", {{ timeout: {{ ms: 500, action: "fail" }} }}).expect(status: 200)'
    )

    assert result["outcome"] == "timeout"
    attribution = result["attribution"]
    assert attribution["verdict"] == "network"
    assert attribution["calls"][0]["phase"] == "connecting"
    assert attribution["target"] == {"host": "127.0.0.1", "port": unaccepting, "tls": False}


def test_a_run_that_did_not_time_out_carries_no_attribution(server) -> None:
    base = server(lambda conn: conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))

    result = _run(f'get("{base}/ok").expect(status: 200)')

    assert result["outcome"] == "success"
    assert "attribution" not in result


def test_the_run_budget_stand_in_carries_the_same_verdict(server) -> None:
    base = server(lambda conn: None)

    result = _run(f'get("{base}/slow").expect(status: 200)', budget_ms=1_000)

    assert result["outcome"] == "timeout"
    assert result["attribution"]["verdict"] == "endpoint"
    assert result["stall"]["tcp"]["unacked"] == 0


def test_a_run_budget_spent_connecting_is_put_to_the_path(unaccepting) -> None:
    result = _run(f'get("http://127.0.0.1:{unaccepting}/x").expect(status: 200)', budget_ms=1_000)

    assert result["outcome"] == "timeout"
    assert result["attribution"]["verdict"] == "network"
    assert result["attribution"]["target"]["port"] == unaccepting


# The rules, on connection states as the kernel reported them. The lossy ones
# were recorded in a container with `tc netem` dropping packets on loopback.
CLEAN = {"state": "established", "retransmits": 0, "unacked": 0, "total_retrans": 0,
         "data_segs_in": 31, "rcv_ooopack": 0, "dsack_dups": 0}


@pytest.mark.parametrize(
    ("phase", "tcp", "expected"),
    [
        ("awaiting_response", CLEAN, "endpoint"),
        ("receiving", CLEAN, "endpoint"),
        ("tls_handshake", CLEAN, "endpoint"),
        # Our request never acknowledged, resent four times: the network died.
        ("awaiting_response", {**CLEAN, "retransmits": 4, "unacked": 1, "total_retrans": 5}, "network"),
        # 10 % loss: 80 of 370 segments arrived after a gap.
        ("receiving", {**CLEAN, "data_segs_in": 370, "rcv_ooopack": 80}, "network"),
        # One reordered segment on a long transfer is not a lossy path.
        ("receiving", {**CLEAN, "data_segs_in": 5000, "rcv_ooopack": 1}, "endpoint"),
        ("connecting", {**CLEAN, "state": "syn_sent", "retransmits": 2}, "network"),
        ("resolving", None, "network"),
        # A kernel too old to report receive-side loss cannot clear the path.
        ("receiving", {**CLEAN, "rcv_ooopack": None}, "unknown"),
        ("receiving", None, "unknown"),
        ("between_requests", None, "agent"),
        ("storing_bodies", None, "agent"),
    ],
)
def test_who_a_stall_belongs_to(phase: str, tcp: dict[str, Any] | None, expected: str) -> None:
    assert tcp_state.verdict(phase, tcp)[0] == expected


def test_reaching_a_listening_endpoint_reports_a_clean_path(server) -> None:
    base = server(lambda conn: None)
    port = int(base.rsplit(":", 1)[1])

    reached = tcp_state.reach("127.0.0.1", port, use_tls=False)

    assert reached["path"] == "clean"
    assert len(reached["attempts"]) == 3
    assert all(a["tcp"]["state"] == "established" for a in reached["attempts"])


def test_reaching_an_endpoint_that_never_accepts_reports_it_unreachable(unaccepting) -> None:
    reached = tcp_state.reach("127.0.0.1", unaccepting, use_tls=False, timeout_s=0.5)

    assert reached["path"] == "unreachable"
    assert len(reached["attempts"]) == 1


def test_the_witness_route_answers_with_the_path(client, server) -> None:
    base = server(lambda conn: None)
    port = int(base.rsplit(":", 1)[1])

    response = client.post("/reach", json={"host": "127.0.0.1", "port": port, "tls": False})

    assert response.status_code == 200
    assert response.json()["path"] == "clean"


def test_the_witness_is_held_to_the_probe_egress_policy(client, monkeypatch) -> None:
    from services import egress_guard

    egress_guard.install()
    monkeypatch.setattr(executor_service, "_egress_enabled", True)

    response = client.post("/reach", json={"host": "127.0.0.1", "port": 9, "tls": False})

    assert response.json()["path"] == "refused"
    assert "blocked address" in response.json()["error"]


def test_an_unreadable_descriptor_has_no_state() -> None:
    assert tcp_state.read(-1) is None
    with open(__file__) as f:
        assert tcp_state.read(f.fileno()) is None
