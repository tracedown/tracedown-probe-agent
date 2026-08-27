"""Run-budget (``requestTimeoutMs``) handling on the /probe path.

The scheduler sizes both its HTTP client timeout and its execution lock from a
single per-run budget. These tests pin the agent to the same reading of that
number: absent means no budget at all (the behaviour that predates the field),
a sane value bounds the whole run rather than a single call, and a value the
agent cannot act on never costs the tick its probe.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from models.job import MAX_RUN_TIMEOUT_MS, MIN_RUN_TIMEOUT_MS, JobPayload
from services import executor as executor_service

SCRIPT = 'get("https://api.example.com/health").expect(status: 200)'

QUICK_RESULT: dict[str, Any] = {
    "outcome": "success",
    "startedAt": "2026-05-01T12:00:00.000Z",
    "endedAt": "2026-05-01T12:00:00.010Z",
    "elapsedMs": 10,
    "runVars": {},
    "calls": [],
    "actions": {},
}


@pytest.fixture
def probe_pool() -> Iterator[None]:
    """A dedicated probe pool, as the lifespan installs in production.

    Without it the executor falls back to the loop's default pool, which
    ``asyncio.run`` joins on the way out — that would make an over-budget run
    block the test long after the agent had already answered, hiding the very
    thing under test.
    """
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-probe")
    try:
        with patch.object(executor_service, "_probe_pool", pool):
            yield
    finally:
        pool.shutdown(wait=False)


def _payload(**extra: Any) -> JobPayload:
    """Build a payload the way the scheduler does — camelCase wire names."""
    return JobPayload(**{"script": SCRIPT, **extra})


# ── The wire field ──────────────────────────────────────────────────


def test_absent_field_means_no_budget() -> None:
    """A scheduler that does not send the field yet leaves the run unbounded."""
    assert _payload().request_timeout_ms is None


def test_camelcase_wire_name_is_accepted() -> None:
    """The scheduler sends camelCase; the model must bind that exact name."""
    assert _payload(requestTimeoutMs=30_000).request_timeout_ms == 30_000


def test_numeric_string_is_coerced() -> None:
    """A JSON-encoded number still lands as a budget rather than being dropped."""
    assert _payload(requestTimeoutMs="45000").request_timeout_ms == 45_000


# ── Validation: clamp, never reject ─────────────────────────────────


@pytest.mark.parametrize("value", [0, -1, -30_000, "not-a-number", [30_000], {}, True])
def test_unusable_values_fall_back_to_no_budget(value: Any) -> None:
    """Nothing the scheduler can send may cost the tick its probe."""
    assert _payload(requestTimeoutMs=value).request_timeout_ms is None


def test_below_floor_is_clamped_up() -> None:
    assert _payload(requestTimeoutMs=5).request_timeout_ms == MIN_RUN_TIMEOUT_MS


def test_above_ceiling_is_clamped_down() -> None:
    assert _payload(requestTimeoutMs=10**9).request_timeout_ms == MAX_RUN_TIMEOUT_MS


def test_bad_budget_still_runs_the_probe(client: TestClient) -> None:
    """A budget the agent cannot read must not become a status the scheduler
    has to reason about — it runs the probe and answers with the result."""
    with patch("services.executor.LaceExecutor") as mock_cls:
        mock_cls.return_value.run.return_value = dict(QUICK_RESULT)
        resp = client.post(
            "/probe", json={"script": SCRIPT, "requestTimeoutMs": "garbage"}
        )

    assert resp.status_code == 200
    assert resp.json()["outcome"] == "success"


# ── Enforcement ─────────────────────────────────────────────────────


def test_budget_is_enforced_over_the_whole_run(probe_pool: None) -> None:
    """A run that outlives the budget is answered as a timeout, not waited out."""

    def slow(_payload: JobPayload) -> dict[str, Any]:
        time.sleep(5)
        return dict(QUICK_RESULT)

    payload = _payload(requestTimeoutMs=1_000)
    with patch("services.executor._run_sync", slow):
        started = time.monotonic()
        result = asyncio.run(executor_service.execute_probe(payload))
    waited = time.monotonic() - started

    # `timeout` and not `error`: the scheduler must read this as an observation
    # of the target, never as a fault of the agent worth re-dispatching.
    assert result["outcome"] == "timeout"
    assert result["calls"] == []
    assert "1000ms run budget" in result["error"]
    assert result["ingressBytes"] == 0
    assert result["egressBytes"] == 0
    # The whole point: the answer lands on the budget, not at the mercy of the
    # executor's per-call timeouts.
    assert waited < 4.0


def test_run_inside_the_budget_is_returned_untouched(probe_pool: None) -> None:
    """A budget that is not exceeded changes nothing about the result."""
    payload = _payload(requestTimeoutMs=30_000)
    with patch("services.executor._run_sync", lambda _p: dict(QUICK_RESULT)):
        result = asyncio.run(executor_service.execute_probe(payload))

    assert result == QUICK_RESULT


def test_no_budget_waits_for_the_executor(probe_pool: None) -> None:
    """Without the field the agent waits for the executor exactly as before."""

    def slow(_payload: JobPayload) -> dict[str, Any]:
        time.sleep(0.3)
        return dict(QUICK_RESULT)

    with patch("services.executor._run_sync", slow):
        result = asyncio.run(executor_service.execute_probe(_payload()))

    assert result["outcome"] == "success"
