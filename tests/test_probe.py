"""Tests for the /probe endpoint.

These tests mock the LaceExecutor to avoid network calls and the
lacelang dependency in unit tests.
"""

from __future__ import annotations

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
        mock_cls.return_value.run.return_value = dict(SAMPLE_EXECUTOR_RESULT)

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
    assert "jobId" not in body


def test_probe_failure_result(client: TestClient) -> None:
    """POST /probe correctly forwards a failure outcome."""
    failure_result = {
        "outcome": "failure",
        "startedAt": "2026-05-01T12:00:00.000Z",
        "endedAt": "2026-05-01T12:00:01.000Z",
        "elapsedMs": 1000,
        "runVars": {},
        "calls": [
            {
                "index": 0,
                "outcome": "failure",
                "startedAt": "2026-05-01T12:00:00.000Z",
                "endedAt": "2026-05-01T12:00:01.000Z",
                "request": {"url": "https://api.example.com/health", "method": "GET", "headers": {}},
                "response": None,
                "redirects": [],
                "assertions": [],
                "config": {},
                "warnings": [],
                "error": "Connection refused",
            }
        ],
        "actions": {},
    }

    with patch("services.executor.LaceExecutor") as mock_cls:
        mock_cls.return_value.run.return_value = failure_result

        resp = client.post("/probe", json=JOB_PAYLOAD)

    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "failure"
    assert body["calls"][0]["error"] == "Connection refused"


def test_probe_with_prev(client: TestClient) -> None:
    """POST /probe forwards prev result to the executor."""
    prev_result = {
        "outcome": "success",
        "startedAt": "2026-05-01T11:00:00.000Z",
        "endedAt": "2026-05-01T11:00:00.100Z",
        "elapsedMs": 100,
        "runVars": {"counter": "0"},
        "calls": [],
        "actions": {},
    }

    payload_with_prev = {**JOB_PAYLOAD, "prev": prev_result}

    with patch("services.executor.LaceExecutor") as mock_cls:
        mock_cls.return_value.run.return_value = dict(SAMPLE_EXECUTOR_RESULT)

        resp = client.post("/probe", json=payload_with_prev)

    assert resp.status_code == 200
    mock_cls.return_value.run.assert_called_once()
    call_kwargs = mock_cls.return_value.run.call_args
    assert call_kwargs.kwargs.get("prev") == prev_result or call_kwargs[1].get("prev") == prev_result
