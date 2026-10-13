"""What a run-budget timeout says about where the run was.

The stand-in result for a run that outlived its budget used to be empty: no
call, no timing, zero bytes, and a message that only named the budget. A run
stuck waiting for a first byte and one receiving a response too slowly to
finish were the same result. These pin the record the agent now keeps as a
run goes, against real sockets.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

import pytest

from models.job import JobPayload
from services import executor as executor_service
from services import run_progress, wire_metrics


@pytest.fixture(autouse=True)
def _instrumented(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Hooks installed as the lifespan does, a real probe pool, guard off."""
    wire_metrics.install()
    run_progress.install()
    monkeypatch.setattr(executor_service, "_egress_enabled", False)
    monkeypatch.setattr(executor_service, "_storage", None)
    pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-probe")
    try:
        with patch.object(executor_service, "_probe_pool", pool):
            yield
    finally:
        pool.shutdown(wait=False)


@pytest.fixture
def server() -> Iterator[Callable[[Callable[[socket.socket], None]], str]]:
    """A raw TCP server whose behaviour per connection the test supplies.

    Closing every accepted socket on the way out is what ends the over-budget
    executor thread, which otherwise runs on to its own per-call timeout.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    release = threading.Event()
    accepted: list[socket.socket] = []

    def start(behaviour: Callable[[socket.socket], None]) -> str:
        def serve() -> None:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                accepted.append(conn)
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        def handle(conn: socket.socket) -> None:
            try:
                conn.recv(65536)
                behaviour(conn)
                release.wait(10)
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        return f"http://127.0.0.1:{listener.getsockname()[1]}"

    yield start
    release.set()
    listener.close()
    for conn in accepted:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def _run(script: str) -> dict[str, Any]:
    payload = JobPayload(script=script, requestTimeoutMs=1_000)
    return asyncio.run(executor_service.execute_probe(payload))


def _text(result: dict[str, Any]) -> str:
    return result["actions"]["notifications"][0]["notification"]["value"]


OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


def test_a_target_that_never_answers_is_reported_as_awaiting_a_response(server) -> None:
    base = server(lambda conn: None)

    result = _run(f'get("{base}/slow").expect(status: 200)')

    assert result["outcome"] == "timeout"
    stall = result["stall"]
    assert stall["phase"] == run_progress.AWAITING_RESPONSE
    assert stall["requestsCompleted"] == 0
    assert stall["request"]["method"] == "GET"
    assert stall["request"]["url"] == f"{base}/slow"
    assert stall["request"]["connectMs"] is not None
    assert stall["request"]["ttfbMs"] is None
    assert stall["request"]["bytesReceived"] == 0
    assert f"request 1 (GET {base}/slow) had no response after" in result["error"]
    assert result["error"].startswith("probe did not finish within its 1000ms run budget: ")
    # The request went out and nothing came back: the counters say so.
    assert result["egressBytes"] > 0
    assert result["ingressBytes"] == 0


def test_a_response_that_arrives_too_slowly_is_reported_as_receiving(server) -> None:
    def dribble(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"x" * 500)

    base = server(dribble)

    result = _run(f'get("{base}/big").expect(status: 200)')

    stall = result["stall"]
    assert stall["phase"] == run_progress.RECEIVING
    assert stall["request"]["ttfbMs"] is not None
    assert stall["request"]["bytesReceived"] > 0
    assert "was still receiving its response" in result["error"]
    assert result["ingressBytes"] == stall["request"]["bytesReceived"]


def test_the_stalled_request_is_numbered_after_those_that_completed(server) -> None:
    def second_hangs(conn: socket.socket, seen: list[int] = []) -> None:  # noqa: B006
        seen.append(1)
        if len(seen) == 1:
            conn.sendall(OK)

    base = server(second_hangs)

    result = _run(f'get("{base}/a").expect(status: 200)\nget("{base}/b").expect(status: 200)')

    stall = result["stall"]
    assert stall["requestsCompleted"] == 1
    assert stall["request"]["url"] == f"{base}/b"
    assert f"request 2 (GET {base}/b)" in result["error"]


def test_the_announcement_says_where_the_run_was(server) -> None:
    base = server(lambda conn: None)

    result = _run(f'get("{base}/slow").expect(status: 200)')

    text = _text(result)
    assert text.startswith(
        "${s.name} in ${w.name}.${p.name} timed out: the run did not complete within 1000ms ("
    )
    assert f"GET {base}/slow" in text


def test_a_url_cannot_inject_a_template_variable_into_the_announcement(server) -> None:
    base = server(lambda conn: None)

    result = _run(f'get("{base}/x?q=$${{s.name}}").expect(status: 200)')

    # Whatever the URL carried, no unescaped `${` beyond the agent's own prefix.
    tail = _text(result).split("timed out: ", 1)[1]
    assert "${" not in tail.replace("\\${", "")


def test_a_run_that_completes_carries_no_stall(server) -> None:
    base = server(lambda conn: conn.sendall(OK))

    result = _run(f'get("{base}/").expect(status: 200)')

    assert result["outcome"] == "success"
    assert "stall" not in result


def test_the_agents_own_traffic_is_not_recorded() -> None:
    """Outside a tracked run the hooks must be inert."""
    progress = run_progress.RunProgress()
    with run_progress.assign(progress):
        try:
            socket.getaddrinfo("localhost", 80)
        except OSError:
            pass
    assert progress.snapshot() is None


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        (run_progress.RESOLVING, "request 3 (GET https://api.example.com/v1) was still resolving api.example.com after 900ms"),
        (run_progress.CONNECTING, "request 3 (GET https://api.example.com/v1) was still connecting after 900ms"),
        (run_progress.TLS_HANDSHAKE, "request 3 (GET https://api.example.com/v1) was still in the TLS handshake after 900ms"),
        (run_progress.RECEIVING, "request 3 (GET https://api.example.com/v1) was still receiving its response: 2048 bytes in 900ms"),
    ],
)
def test_each_phase_reads_as_a_clause(phase: str, expected: str) -> None:
    stall = {
        "phase": phase,
        "phaseMs": 900,
        "requestsCompleted": 2,
        "request": {"method": "GET", "url": "https://api.example.com/v1", "bytesReceived": 2048},
    }
    assert run_progress.describe(stall) == expected


def test_a_run_stalled_outside_any_request_says_so() -> None:
    between = {"phase": run_progress.BETWEEN_REQUESTS, "phaseMs": 5, "requestsCompleted": 1, "request": None}
    storing = {"phase": run_progress.STORING_BODIES, "phaseMs": 5, "requestsCompleted": 2, "request": None}
    assert run_progress.describe(between) == "between requests, after 1 completed request"
    assert run_progress.describe(storing) == "storing response bodies, after 2 completed requests"
