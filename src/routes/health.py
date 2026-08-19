"""Health check endpoints.

``GET /health`` — basic liveness for a load balancer or orchestrator.
``POST /health/challenge`` — challenge-response that exercises the Lace
executor end-to-end to verify the agent can actually run probes.
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter
from lacelang_executor import __version__ as executor_version
from pydantic import BaseModel

from services.executor import run_health_script

log = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(BaseModel):
    status: str
    version: str
    executor_version: str


class ChallengeRequest(BaseModel):
    challenge_id: str
    token_url: str


class ChallengeResponse(BaseModel):
    challenge_id: str
    token: str | None
    elapsed_ms: int
    success: bool
    error: str | None = None


@router.get("", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Basic liveness check."""
    return HealthResponse(status="ok", version="0.1.0", executor_version=executor_version)


@router.post("/challenge", response_model=ChallengeResponse)
async def challenge(body: ChallengeRequest) -> ChallengeResponse:
    """Challenge-response that exercises the full executor pipeline.

    The aggregate-worker sends a ``tokenUrl`` pointing to a backend
    endpoint that returns a one-time token.  The agent runs a real Lace
    script to fetch it, proving the executor works, the network is
    functional, and data is not corrupted.
    """
    start = time.monotonic()

    try:
        token = await run_health_script(body.token_url)
        elapsed = int((time.monotonic() - start) * 1000)
        return ChallengeResponse(
            challenge_id=body.challenge_id,
            token=token,
            elapsed_ms=elapsed,
            success=True,
        )
    except Exception as exc:  # noqa: BLE001 — any failure must report as unhealthy, never crash the endpoint
        elapsed = int((time.monotonic() - start) * 1000)
        log.warning("health challenge failed: %s", exc)
        return ChallengeResponse(
            challenge_id=body.challenge_id,
            token=None,
            elapsed_ms=elapsed,
            success=False,
            error=str(exc),
        )
