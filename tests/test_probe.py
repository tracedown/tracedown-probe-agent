"""Tests for the /probe endpoint.

These tests mock the LaceExecutor to avoid network calls and the
lacelang dependency in unit tests.
"""

from __future__ import annotations

from copy import deepcopy
from unittest.mock import patch

from fastapi.testclient import TestClient

SAMPLE_EXECUTOR_RESULT = {
    "outcome": "success",
    "startedAt": "2026-05-01T12:00:00.000Z",
    "endedAt": "2026-05-01T12:00:00.342Z",
    "elapsedMs": 342,
    "runVars": {"counter": "1"},
    "calls": [
        {
            "index": 0,
            "outcome": "success",
            "startedAt": "2026-05-01T12:00:00.000Z",
            "endedAt": "2026-05-01T12:00:00.142Z",
            "request": {"url": "https://api.example.com/health", "method": "GET", "headers": {}},
            "response": {
                "status": 200,
                "statusText": "OK",
                "headers": {"content-type": "application/json"},
                "responseTimeMs": 142,
                "dnsMs": 12,
                "connectMs": 25,
                "tlsMs": 38,
                "ttfbMs": 55,
                "transferMs": 12,
                "sizeBytes": 256,
            },
            "redirects": [],
            "assertions": [
                {"method": "expect", "scope": "status", "op": "eq", "outcome": "pass", "actual": 200, "expected": 200}
            ],
            "config": {},
            "warnings": [],
            "error": None,
        }
    ],
    "actions": {},
}

JOB_PAYLOAD = {
    "script": 'get("https://api.example.com/health").expect(status: 200)',
    "variables": {"base_url": "https://api.example.com"},
    "requestTimeoutMs": 30000,
}


def test_probe_returns_raw_result(client: TestClient) -> None:
    """POST /probe forwards the executor's raw ProbeResult verbatim."""
    with patch("services.executor.LaceExecutor") as mock_cls:
        mock_cls.return_value.run.return_value = deepcopy(SAMPLE_EXECUTOR_RESULT)

        resp = client.post("/probe", json=JOB_PAYLOAD)

    assert resp.status_code == 200
    body = resp.json()

    # Executor fields forwarded verbatim — no agent-added fields
    assert body["outcome"] == "success"
    assert body["elapsedMs"] == 342
    assert body["startedAt"] == "2026-05-01T12:00:00.000Z"
    assert len(body["calls"]) == 1
    assert body["calls"][0]["response"]["status"] == 200
    assert body["calls"][0]["response"]["dnsMs"] == 12
    assert body["runVars"] == {"counter": "1"}
    assert body["actions"] == {}
    assert "jobId" not in body


def test_probe_refusal_is_announced_over_the_route(client: TestClient) -> None:
    """A TLS-policy refusal carries its own `error` notification event, on the
    first tick and again when the scheduler sends that refusal back as `prev`
    — through the route, so the JSON round trip (`scope` as null) is covered."""
    script = (
        'get("https://target.invalid/", { security: { rejectInvalidCerts: false } })'
        '.expect(status: 200)'
    )
    with patch("services.executor._reject_insecure_tls", True):
        first = client.post("/probe", json={"script": script}).json()
        repeat = client.post("/probe", json={"script": script, "prev": first}).json()

    for body in (first, repeat):
        assert body["outcome"] == "failure" and body["calls"] == []
        (event,) = body["actions"]["notifications"]
        assert event["trigger"] == "error"
        assert event["scope"] is None
