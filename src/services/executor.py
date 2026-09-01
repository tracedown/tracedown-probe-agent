"""Lace script execution service.

Wraps ``LaceExecutor.run()`` and returns the raw ProbeResult dict.
Execution is synchronous (the executor does blocking HTTP), so we
offload it to a thread pool.

When body saving is enabled, the executor writes bodies to a temp
directory. After execution, any saved bodies are uploaded to the
configured storage backend and ``bodyPath`` values in the result
are replaced with storage references.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lacelang_executor import LaceExecutor

from models.job import JobPayload
from services import wire_metrics
from storage.base import BodyStorage

log = logging.getLogger(__name__)

# Singleton executor — no root dir, no extensions, no prev tracking.
# The agent receives fully self-contained scripts from the scheduler.
_executor = LaceExecutor(root=None, track_prev=False)

# Dedicated pool for probe execution, sized by PROBE_AGENT_MAX_CONCURRENCY.
# Isolated from the default asyncio pool so that (a) probe concurrency isn't
# capped at Python's default min(32, cpu+4) — which throttles hard when
# per-probe latency is high — and (b) a saturated probe pool never starves
# the health challenge, which stays on the default pool.
_probe_pool: ThreadPoolExecutor | None = None


def init_probe_pool(max_workers: int) -> None:
    """Initialize the probe execution pool at startup."""
    global _probe_pool
    _probe_pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="probe")

# Lace script used for health challenge-response.
_HEALTH_SCRIPT = 'get("$tokenUrl").expect(status: 200).store({ "$$token": this.body.token })'

# Module-level storage reference, set by init_storage().
_storage: BodyStorage | None = None

# User-Agent every probe announces itself with, set by init_user_agent().
# Empty leaves the executor's own generic default in place.
_user_agent: str = ""

# Target-egress policy for tenant probes, set by init_egress_policy(). The guard
# (or None) is handed to the per-request executor so every connect — initial and
# every redirect hop — is vetted against the blocked-range policy. force_verify
# overrides a script's rejectInvalidCerts=false. Both default to off so nothing
# changes unless the deployment opts in (production does, via config).
#
# Note: only the per-request *tenant* executor is guarded. The health-challenge
# singleton below deliberately is not — it dials the gateway on the internal
# network, exactly the kind of address the guard blocks.
_before_connect = None  # type: ignore[var-annotated]
_force_verify_tls: bool = False


def init_storage(storage: BodyStorage) -> None:
    """Set the body storage backend. Called once at startup."""
    global _storage
    _storage = storage


def init_user_agent(user_agent: str) -> None:
    """Set the User-Agent probes send. Called once at startup."""
    global _user_agent
    _user_agent = user_agent


def init_egress_policy(before_connect, force_verify_tls: bool) -> None:
    """Set the tenant-probe egress guard and TLS-verify override. Called once
    at startup. ``before_connect`` is an egress guard callable or None."""
    global _before_connect, _force_verify_tls
    _before_connect = before_connect
    _force_verify_tls = force_verify_tls


def _run_sync(payload: JobPayload) -> dict[str, Any]:
    """Execute a Lace script and handle body storage.

    Creates a per-request executor to avoid shared config mutation
    when multiple probes run concurrently in the thread pool.
    """
    bodies_dir = tempfile.mkdtemp(prefix="lace-bodies-")

    try:
        # Determine which extensions to load based on variables
        active_extensions = ["laceNotifications"]
        variables = payload.variables or {}
        if variables.get("trackBaseline") == "true":
            active_extensions.append("laceBaseline")
        # Recovery notifications are on by default (the extension only emits
        # on a failure->success transition); set notifyRecovery=false to opt out.
        if variables.get("notifyRecovery") != "false":
            active_extensions.append("laceEmitRecovery")

        executor = LaceExecutor(
            root=None,
            track_prev=False,
            extensions=active_extensions,
            # Target-egress policy: vet every connect (initial + each redirect
            # hop) and optionally enforce TLS verification, per deployment config.
            before_connect=_before_connect,
            force_verify_tls=_force_verify_tls,
        )

        # Spec §3.6 precedence: a script setting its own User-Agent still wins
        # over this, which is per-deployment.
        if _user_agent:
            executor._config.setdefault("executor", {})["user_agent"] = _user_agent

        executor._config.setdefault("result", {})
        if payload.allow_body_save:
            executor._config["result"]["bodies"] = {"dir": bodies_dir}

        if "laceEmitRecovery" in active_extensions:
            # The recovery text doubles as the dispatcher-side template, so a
            # ${var}-rich default gives the message context (service, path).
            executor._config.setdefault("extensions", {})["laceEmitRecovery"] = {
                "recovery_message": "${s.name} in ${w.name}.${p.name} recovered",
            }

        with wire_metrics.measure() as wire:
            result = executor.run(
                script=payload.script,
                vars=payload.variables if payload.variables else None,
                prev=payload.prev,
            )

        # Actual HTTP-layer bytes this probe put on / took off the wire. Tracedown
        # metadata, not part of the canonical Lace ProbeResult — the ingestor
        # persists and aggregates them.
        result["ingressBytes"] = wire.ingress
        result["egressBytes"] = wire.egress

        # Upload any saved bodies and rewrite paths in the result.
        if _storage is not None:
            _upload_bodies(result, payload.secret_values or [])

        return result
    finally:
        shutil.rmtree(bodies_dir, ignore_errors=True)


# Mask token — mirrors the scheduler-side ResultRedactor so masked bytes read
# identically wherever they surface.
_MASK = "••••••"  # ••••••


def _redact_body_bytes(data: bytes, secret_values: list[str]) -> bytes:
    """Replace every occurrence of a secret plaintext in [data] with the mask.

    Byte-level replacement so it works on both text and binary bodies without a
    decode step. Longest-first so a secret that is a substring of another is
    masked fully rather than leaving a fragment behind.
    """
    if not secret_values:
        return data
    mask = _MASK.encode("utf-8")
    for secret in sorted((s for s in secret_values if s), key=len, reverse=True):
        needle = secret.encode("utf-8")
        if needle and needle in data:
            data = data.replace(needle, mask)
    return data


def _upload_bodies(result: dict[str, Any], secret_values: list[str]) -> None:
    """Upload body files to storage under a unique key, rewriting bodyPath.

    Each probe run gets a fresh random namespace so bodies from different orgs /
    services / runs sharing this agent can never collide on a storage key (the key
    is not derived from any attacker-influenced value). Secret plaintexts are
    masked out of the body bytes before upload.
    """
    # Per-run random namespace — collision-free across tenants, not attacker-controlled.
    run_prefix = uuid.uuid4().hex

    for call in result.get("calls", []):
        response = call.get("response")
        if response is None:
            continue

        body_path = response.get("bodyPath")
        if body_path is None:
            continue

        local = Path(body_path)
        if not local.exists():
            continue

        # Mask secret values in the body bytes BEFORE they leave the agent.
        if secret_values:
            original = local.read_bytes()
            redacted = _redact_body_bytes(original, secret_values)
            if redacted != original:
                local.write_bytes(redacted)

        key = f"{run_prefix}/{local.name}"
        ref = _storage.upload(local, key)
        response["bodyPath"] = ref


def _run_health_sync(token_url: str) -> str:
    """Run the health challenge script and extract the token."""
    result = _executor.run(
        script=_HEALTH_SCRIPT,
        vars={"tokenUrl": token_url},
    )

    if result["outcome"] != "success":
        error = result.get("calls", [{}])[0].get("error", "unknown error")
        raise RuntimeError(f"health script failed: {error}")

    token = result.get("runVars", {}).get("token")
    if not token:
        raise RuntimeError("health script did not extract token")

    return token


def _now_iso() -> str:
    """Timestamp in the format the Lace executor stamps results with (§9)."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    return stamp.replace("+00:00", "Z")


def _run_budget_timeout(
    budget_ms: int, started_at: str, elapsed_ms: int
) -> dict[str, Any]:
    """A ProbeResult standing in for a run that outlived its budget.

    Shaped like any other result (spec §9) so the ingestor persists it on the
    normal path: `outcome=timeout` is the honest monitoring status, `calls` is
    empty because the executor returns per-call records only when the whole run
    completes, and the byte counters are zero for the same reason.

    Deliberately a 200 with a result, never a 5xx: the scheduler treats an
    agent error status as a fault of the agent, and this is not one — the
    target did not answer inside the budget the scheduler itself set, which is
    an observation about the target and must not be re-dispatched elsewhere.
    """
    return {
        "outcome": "timeout",
        "startedAt": started_at,
        "endedAt": _now_iso(),
        "elapsedMs": elapsed_ms,
        "runVars": {},
        "calls": [],
        "actions": {},
        "error": f"probe did not finish within its {budget_ms}ms run budget",
        "ingressBytes": 0,
        "egressBytes": 0,
    }


async def execute_probe(payload: JobPayload) -> dict[str, Any]:
    """Execute a probe job and return the raw ProbeResult dict.

    The executor already produces a spec-compliant result (§9).
    Forwarded as-is — the scheduler knows which job it dispatched.

    ``requestTimeoutMs`` is a budget for the **whole run**, and the run budget
    is enforced here because nothing below can enforce it: Lace's `timeout.ms`
    is per call (spec §3.2) and the executor applies it one call at a time,
    with no notion of a ceiling across the script. A three-call script under a
    30s budget is therefore free to spend 90s down there — which is exactly the
    window in which the scheduler gives up, records a timeout the target never
    caused, and eventually dispatches the same service twice.

    So the deadline is a wall clock over the whole execution. When it expires
    the agent answers immediately with a `timeout` ProbeResult of its own,
    inside the scheduler's own client timeout, and the run is settled by an
    observation rather than by a transport failure.

    Residual gap, worth stating plainly: the executor runs synchronously in a
    thread and offers no cancellation, so an over-budget run keeps running
    after the answer has been sent, until its own per-call timeouts expire. It
    holds a pool slot (of `PROBE_AGENT_MAX_CONCURRENCY`) for that long and its
    result is discarded. Nothing is double-probed — the scheduler is not asked
    to retry — and the overshoot is bounded by the script's own timeouts, which
    the gateway already caps at the Lace system ceiling.
    """
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(_probe_pool, _run_sync, payload)

    budget_ms = payload.request_timeout_ms
    if budget_ms is None:
        # No budget dispatched (a scheduler that does not send the field yet):
        # wait for the executor exactly as before.
        return await future

    started_at = _now_iso()
    started_mono = time.monotonic()
    try:
        return await asyncio.wait_for(future, timeout=budget_ms / 1000.0)
    except (asyncio.TimeoutError, TimeoutError):
        elapsed_ms = int((time.monotonic() - started_mono) * 1000)
        log.warning(
            "probe exceeded its %dms run budget after %dms — answering with a timeout result; "
            "the execution thread runs on until its per-call timeouts expire",
            budget_ms,
            elapsed_ms,
        )
        return _run_budget_timeout(budget_ms, started_at, elapsed_ms)


async def run_health_script(token_url: str) -> str:
    """Run the health challenge Lace script in a thread pool."""
    return await asyncio.to_thread(_run_health_sync, token_url)
