"""Inbound job payload from the probe-scheduler."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator
from pydantic.alias_generators import to_camel

log = logging.getLogger(__name__)

#: Smallest run budget the agent will act on. Below this a probe cannot
#: realistically finish a DNS lookup and a TLS handshake, so a value under the
#: floor is a configuration mistake rather than an intent — clamped up rather
#: than obeyed, so the mistake costs a slow probe and not every probe.
MIN_RUN_TIMEOUT_MS = 1_000

#: Largest run budget the agent will act on — the Lace system ceiling
#: (`executor.maxTimeoutMs`, spec §11), which is also the backend's
#: `probe.maxTimeoutMs` default. A budget above it could not be reached by any
#: script the platform accepts, so anything larger is clamped down.
MAX_RUN_TIMEOUT_MS = 300_000


class JobPayload(BaseModel):
    """A single probe job dispatched by the scheduler.

    ``script`` is raw Lace source code.  ``variables`` are the fully
    resolved service variables (org -> workspace -> project -> service
    scope chain already merged by the scheduler).

    The agent is fully stateless — it doesn't need to know the job ID,
    service, org, or its own identity.  The scheduler correlates the
    response because it made the request.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    script: str
    variables: dict[str, Any] = {}
    prev: dict[str, Any] | None = None
    #: False when the scheduler forbids body persistence (unverified-domain
    #: anti-scraping limit). Bodies are then neither saved nor uploaded.
    allow_body_save: bool = True
    #: Resolved plaintext values of this run's secret variables. Masked out of
    #: any saved response body before it is uploaded, so a monitored endpoint
    #: that reflects a credential never lands the org's secret in the body store.
    secret_values: list[str] = []
    #: Wall-clock budget in milliseconds for the **whole run** — every call in
    #: the script, start to finish — not a per-call timeout. It is the same
    #: budget the scheduler sizes its own HTTP timeout and execution lock from,
    #: so honouring it here is what keeps the two ends agreeing on when a run is
    #: over. ``None`` (the field absent) means no budget: the run takes as long
    #: as the script's own per-call timeouts allow, exactly as before this field
    #: existed. See :func:`services.executor.execute_probe`.
    request_timeout_ms: int | None = None

    @field_validator("request_timeout_ms", mode="before")
    @classmethod
    def _sanitise_run_budget(cls, value: Any) -> int | None:
        """Clamp the dispatched budget into a range the agent can act on.

        Clamp rather than reject: a dispatch is the only chance this tick has
        to observe the target, so a scheduler that sends a number the agent
        dislikes must still get its probe run. Anything uninterpretable — a
        non-number, or a value at or below zero, which would time every probe
        out instantly — is treated as if the field had been omitted, which is
        the behaviour that predates it. Every correction is logged, because
        silently running to a budget nobody asked for is how the original
        mismatch went unnoticed.
        """
        if value is None:
            return None
        ms = None if isinstance(value, bool) else _as_int(value)
        if ms is None:
            log.warning(
                "dispatch carried a non-numeric requestTimeoutMs (%r) — running with no run budget",
                value,
            )
            return None
        if ms <= 0:
            log.warning(
                "dispatch carried requestTimeoutMs=%d — running with no run budget", ms
            )
            return None
        if ms < MIN_RUN_TIMEOUT_MS:
            log.warning(
                "dispatch carried requestTimeoutMs=%d, below the %dms floor — clamping up",
                ms,
                MIN_RUN_TIMEOUT_MS,
            )
            return MIN_RUN_TIMEOUT_MS
        if ms > MAX_RUN_TIMEOUT_MS:
            log.warning(
                "dispatch carried requestTimeoutMs=%d, above the %dms ceiling — clamping down",
                ms,
                MAX_RUN_TIMEOUT_MS,
            )
            return MAX_RUN_TIMEOUT_MS
        return ms


def _as_int(value: Any) -> int | None:
    """Best-effort integer coercion; None when the value is not a number."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
