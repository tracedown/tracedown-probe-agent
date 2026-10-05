"""The text a per-call timeout is announced with.

The bundled laceNotifications default is a bare "Request timed out", and a
`text` event's value is the template the dispatcher renders — so without an
override the mail for a timed-out call names neither the service nor the call.
The agent sets a template that does, opening the way its own run-level events
do.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from models.job import JobPayload
from services import executor as executor_service

TEMPLATE = "${s.name} in ${w.name}.${p.name} call to ${url} timed out"


class _SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.6)
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except OSError:
            pass  # the client gave up at its timeout, as intended

    def log_message(self, *_args):
        pass


@pytest.fixture
def slow_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _guard_off(monkeypatch):
    """The socket-layer guard is off by default; pin it so the loopback
    target is reachable whatever another test left behind."""
    monkeypatch.setattr(executor_service, "_egress_enabled", False)


def _timeouts(result: dict) -> list[dict]:
    return [e for e in result["actions"]["notifications"] if e["trigger"] == "timeout"]


@pytest.mark.parametrize(
    "variables",
    [
        pytest.param({}, id="defaults"),
        pytest.param({"notifyRecovery": "false"}, id="recovery off"),
        pytest.param({"trackBaseline": "true"}, id="baseline on"),
    ],
)
def test_per_call_timeout_names_the_service_and_the_call(slow_server, variables):
    """A call that outlives its own `timeout.ms` is announced with the agent's
    template, not the extension's bare default, whichever extensions the run
    activates. `${url}` resolves downstream from the call record the event
    points at."""
    payload = JobPayload(
        script=f'get("{slow_server}/", {{ timeout: {{ ms: 200 }} }}).expect(status: 200)',
        variables=variables,
    )
    result = executor_service._run_sync(payload)

    assert result["outcome"] == "timeout"
    (event,) = _timeouts(result)
    assert event["callIndex"] == 0
    assert event["notification"] == {"tag": "text", "value": TEMPLATE}


def test_a_scripts_own_timeout_notification_still_wins(slow_server):
    """The default is a default: a `timeout.notification` the script declares
    is what the extension emits."""
    payload = JobPayload(
        script=(
            f'get("{slow_server}/", {{ timeout: {{ ms: 200, notification: text("custom") }} }})'
            ".expect(status: 200)"
        )
    )
    result = executor_service._run_sync(payload)

    (event,) = _timeouts(result)
    assert event["notification"] == {"tag": "text", "value": "custom"}


def test_each_timed_out_call_is_announced(slow_server):
    """One event per timed-out call, each pointing at its own call record."""
    payload = JobPayload(
        script=(
            f'get("{slow_server}/a", {{ timeout: {{ ms: 200, action: "warn" }} }})'
            ".expect(status: 200)\n"
            f'get("{slow_server}/b", {{ timeout: {{ ms: 200, action: "warn" }} }})'
            ".expect(status: 200)"
        )
    )
    result = executor_service._run_sync(payload)

    events = _timeouts(result)
    assert [e["callIndex"] for e in events] == [0, 1]
    assert all(e["notification"]["value"] == TEMPLATE for e in events)
