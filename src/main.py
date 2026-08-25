"""Tracedown probe agent — FastAPI application entry point.

Startup lifecycle:
1. Load settings from environment (``PROBE_AGENT_*``).
2. Initialize body storage backend (filesystem or S3-compatible).
3. If bootstrap_token + scheduler_url are set and no certs exist,
   generate a keypair and register with the scheduler (mTLS bootstrap).
4. Start uvicorn with mTLS if certificates are present, plain HTTP
   otherwise (local dev / test mode).
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import AgentSettings
from mtls import envelope
from mtls.bootstrap import ensure_registered
from mtls.renewal import renewal_loop
from mtls.ssl_context import build_server_context, certs_exist
from routes.health import router as health_router
from routes.probe import router as probe_router
from services import wire_metrics
from services.executor import init_probe_pool, init_storage

log = logging.getLogger(__name__)


def _create_storage(settings: AgentSettings):
    """Build the configured body storage backend."""
    if settings.storage_backend == "s3":
        from storage.s3 import S3Storage
        return S3Storage(
            bucket=settings.s3_bucket,
            endpoint_url=settings.s3_endpoint_url,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
            prefix=settings.s3_prefix,
            region=settings.s3_region,
        )
    else:
        from storage.filesystem import FilesystemStorage
        return FilesystemStorage(root_dir=settings.storage_dir)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialize storage and bootstrap mTLS."""
    settings: AgentSettings = app.state.settings

    init_probe_pool(settings.max_concurrency)
    log.info("probe concurrency: %d", settings.max_concurrency)

    # Instrument http.client so each probe's HTTP-layer ingress/egress is measured.
    wire_metrics.install()

    storage = _create_storage(settings)
    init_storage(storage)
    log.info("body storage: %s", settings.storage_backend)

    if settings.bootstrap_token and settings.scheduler_url:
        await ensure_registered(settings)

    # Rotate the client certificate before it expires. Checks immediately, then
    # on a periodic timer. Best-effort — never crashes the agent. The live TLS
    # context (present only in mTLS mode) is passed in so a renewed certificate
    # is hot-swapped onto the running listener without a restart.
    renewal_task = asyncio.create_task(
        renewal_loop(settings, ssl_context=getattr(app.state, "server_ssl_context", None))
    )

    try:
        yield
    finally:
        renewal_task.cancel()
        try:
            await renewal_task
        except asyncio.CancelledError:
            pass


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    settings = AgentSettings()
    app = FastAPI(
        title="Tracedown Probe Agent",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.include_router(probe_router)
    app.include_router(health_router)
    return app


app = create_app()


if __name__ == "__main__":
    import asyncio

    import uvicorn

    s = app.state.settings

    # Register before binding the socket so the certificate is on disk when the
    # server starts and it can come up in mTLS mode on the very first boot. The
    # lifespan bootstrap runs only after the socket is already bound, which would
    # force the first boot to serve plain HTTP until a restart. A failed bootstrap
    # is intentionally fatal here: an agent with no certificate must not fall back
    # to an unauthenticated plain-HTTP listener — the certificate is the only
    # thing authorizing inbound probe requests.
    if s.bootstrap_token and s.scheduler_url and not certs_exist(s):
        asyncio.run(ensure_registered(s))

    ssl_context_factory = None
    if certs_exist(s):
        server_ctx = build_server_context(s)
        # Publish the live context so the renewal loop can hot-swap the renewed
        # certificate onto it — new connections pick up the new cert with no
        # restart. uvicorn calls this factory once at startup and serves every
        # connection from the returned context object.
        app.state.server_ssl_context = server_ctx
        ssl_context_factory = lambda config, default: server_ctx
        # The same key the certificate was issued for, held for opening a sealed
        # dispatch. Loaded once here rather than per request: it is read from
        # disk, and a probe should not pay for that on every run. Its presence is
        # what /health advertises, so an agent without certificates simply
        # reports that it cannot take sealed payloads.
        try:
            app.state.agent_private_key = envelope.load_private_key(s.key_path)
        except Exception as exc:  # noqa: BLE001 — never fatal; sealing is optional
            app.state.agent_private_key = None
            log.warning("could not load the agent key for payload encryption: %s", exc)
        log.info("starting with mTLS on port %d", s.port)
    else:
        log.info("no certificates found — starting in plain HTTP mode on port %d", s.port)

    # Pass the app object (not the "main:app" import string) so the server shares
    # this module's app instance — the one carrying server_ssl_context on its state.
    config = uvicorn.Config(
        app,
        host=s.host,
        port=s.port,
        log_level=s.log_level,
        ssl_context_factory=ssl_context_factory,
    )
    uvicorn.Server(config).run()
