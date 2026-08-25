"""Probe execution endpoint.

``POST /probe`` — accepts a job payload from the scheduler, runs the
Lace script, and returns the raw executor result with the job ID
attached.

The body may arrive plain or sealed (see ``mtls.envelope``). Which one is
the scheduler's choice, not a setting here: the agent reads whichever it is
given, and answers in the same shape it was asked in. That is what lets the
option be turned on without coordinating a restart across the fleet.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from models.job import JobPayload
from mtls import envelope
from services.executor import execute_probe

log = logging.getLogger(__name__)

router = APIRouter(tags=["probe"])


@router.post("/probe")
async def run_probe(request: Request) -> JSONResponse:
    """Execute a Lace script and return the raw ProbeResult dict."""
    body = await request.json()

    if not envelope.is_envelope(body):
        return JSONResponse(content=await execute_probe(JobPayload(**body)))

    private_key = getattr(request.app.state, "agent_private_key", None)
    if private_key is None:
        # Sealed dispatch to an agent with no key of its own — it is running
        # without mTLS certificates, so there is nothing to decrypt with.
        log.error("sealed dispatch received but this agent holds no private key")
        return JSONResponse(status_code=400, content={"error": "payload_encryption_unavailable"})

    try:
        opened = envelope.open_envelope(body, private_key)
    except envelope.EnvelopeError:
        log.error("sealed dispatch could not be opened — key mismatch or corrupt payload")
        return JSONResponse(status_code=400, content={"error": "payload_undecryptable"})

    # The scheduler seals its own certificate inside, so the reply can be sealed
    # back to it. Inside rather than beside: the tunnel already proved who sent
    # this, and keeping it under the GCM tag means nothing about the exchange
    # travels in the clear.
    reply_cert = opened.pop("replyCert", None)
    result = await execute_probe(JobPayload(**opened))

    if not reply_cert:
        # Sealed one way only. Honest rather than silently downgrading: a
        # scheduler that sealed its request expects a sealed answer.
        log.error("sealed dispatch carried no replyCert — cannot seal the response")
        return JSONResponse(status_code=400, content={"error": "missing_reply_certificate"})

    return JSONResponse(content=envelope.seal_envelope(result, reply_cert))
