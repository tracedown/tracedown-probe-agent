"""Witness endpoint.

``POST /reach`` — asked by the scheduler when another agent's run timed out on
a path that was losing packets, or on a connection nothing answered: can this
agent reach the same endpoint, over a clean path? The answer is what tells a
route problem near the first agent from an endpoint that is unreachable or
losing packets on its own side.

Connections and TLS handshakes only, never an HTTP request — nothing on the
endpoint can change because of it (``services.tcp_state.reach``). Under the
same egress policy as a probe run, and like ``/probe`` reachable only by the
scheduler (the server context admits only its certificate).
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from services.executor import reach_target

router = APIRouter(tags=["reach"])


class ReachRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    tls: bool = True


@router.post("/reach")
async def reach(body: ReachRequest) -> dict:
    """Connect (and shake hands) with the endpoint; report how the path behaved."""
    return await reach_target(body.host, body.port, body.tls)
