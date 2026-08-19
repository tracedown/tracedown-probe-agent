"""Probe execution endpoint.

``POST /probe`` — accepts a job payload from the scheduler, runs the
Lace script, and returns the raw executor result with the job ID
attached.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from models.job import JobPayload
from services.executor import execute_probe

router = APIRouter(tags=["probe"])


@router.post("/probe")
async def run_probe(payload: JobPayload) -> JSONResponse:
    """Execute a Lace script and return the raw ProbeResult dict."""
    result = await execute_probe(payload)
    return JSONResponse(content=result)
