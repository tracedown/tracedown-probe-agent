"""mTLS certificate renewal.

An already-registered agent rotates its client certificate before it
expires.  On startup and then on a periodic timer, the agent inspects the
``notAfter`` of its current certificate; when it falls within
``renew_before_days`` of expiry it generates a fresh RSA-4096 keypair + CSR,
proves possession of its CURRENT private key by signing the new CSR bytes,
and calls the scheduler's ``/internal/agents/renew`` endpoint.  The signed
certificate and new key are written atomically — the existing files are
replaced only after a successful response, so trust never gaps.

Renewal is best-effort: any failure is logged and retried on the next cycle;
it never crashes the agent.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import ssl
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from config import AgentSettings
from mtls.bootstrap import build_csr_pem, generate_keypair, private_key_pem
from mtls.ca_pins import bundle_preserves_pins, ca_fingerprints, read_pins, write_pins
from mtls.ssl_context import build_client_context

log = logging.getLogger(__name__)


def _cert_not_after(cert_path: Path) -> datetime | None:
    """Return the current certificate's expiry as an aware UTC datetime."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except Exception as exc:  # noqa: BLE001 — best-effort inspection
        log.warning("could not read certificate at %s: %s", cert_path, exc)
        return None

    # not_valid_after_utc is aware; not_valid_after (older cryptography) is naive UTC.
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=UTC)
    return not_after


def _resolve_slug(settings: AgentSettings) -> str | None:
    """Resolve the agent's slug from config override or the persisted file."""
    if settings.slug:
        return settings.slug
    slug_path = Path(settings.slug_path)
    if slug_path.exists():
        slug = slug_path.read_text().strip()
        if slug:
            return slug
    return None


def _atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically via a temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _renewal_verify(settings: AgentSettings):
    """The httpx ``verify`` argument for a renewal call.

    An https endpoint is contacted over mutual TLS using the agent's already-held
    certificate + trusted CA (never verify=False once bootstrapped). A plain http
    endpoint (internal network) has no transport to verify.
    """
    if settings.scheduler_url.lower().startswith("https"):
        return build_client_context(settings)
    return False


async def _renew(
    settings: AgentSettings,
    slug: str,
    ssl_context: ssl.SSLContext | None = None,
) -> None:
    """Generate a new keypair/CSR and swap in the renewed certificate.

    When ``ssl_context`` is supplied (the live server context in mTLS mode), the
    renewed certificate is reloaded onto it so new connections serve it with no
    restart.
    """
    key_path = Path(settings.key_path)
    cert_path = Path(settings.cert_path)

    # Load the CURRENT private key to prove possession over the new CSR.
    current_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    new_key = generate_keypair()
    csr_pem = build_csr_pem(new_key)

    signature = current_key.sign(
        csr_pem.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature).decode("ascii")

    log.info("renewing certificate for slug %s via %s", slug, settings.scheduler_url)
    # Once bootstrapped the agent already holds its certificate + trusted CA, so
    # a renewal over https runs as mutual TLS (present our cert, verify the CA) —
    # never verify=False. When the endpoint is plain http (internal network),
    # there is no transport to verify; the CA-continuity pin below still guards
    # the trust anchor regardless of transport.
    verify = _renewal_verify(settings)
    async with httpx.AsyncClient(verify=verify) as client:
        resp = await client.post(
            f"{settings.scheduler_url}/internal/agents/renew",
            json={"slug": slug, "csrPem": csr_pem, "signature": signature_b64},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()

    # Trust-anchor continuity: a renewal must never be allowed to swap the CA
    # for one the agent has not already pinned. Reject the whole renewal if the
    # returned bundle drops every pinned CA — otherwise an on-path attacker could
    # install their own CA and then impersonate the scheduler to us.
    pins_path = Path(settings.ca_pins_path)
    pinned = read_pins(pins_path)
    ca_root = data.get("caRootPem")
    if ca_root and not bundle_preserves_pins(ca_root, pinned):
        raise RuntimeError(
            "renewal returned a CA bundle that drops every pinned trust anchor — "
            "refusing to rotate the trust anchor (possible MITM)"
        )

    # Replace key first, then cert — both atomic, so the pair on disk is always
    # consistent for a concurrent reload.
    _atomic_write(key_path, private_key_pem(new_key))
    _atomic_write(cert_path, data["certificatePem"].encode("utf-8"))

    if ca_root:
        _atomic_write(Path(settings.ca_cert_path), ca_root.encode("utf-8"))
        # Advance the pin set to the (continuity-checked) new bundle so an old CA
        # that later expires and drops out is followed forward.
        new_pins = ca_fingerprints(ca_root)
        if new_pins:
            write_pins(pins_path, new_pins)

    log.info("certificate renewed — new cert written to %s", cert_path)

    # Hot-swap the renewed material onto the live listener so no restart is
    # needed. load_cert_chain replaces the served certificate for new
    # connections; load_verify_locations adds the (possibly rotated) CA so
    # client certificates signed by it keep validating. Best-effort: on failure
    # the files are already written, so a restart still recovers.
    if ssl_context is not None:
        try:
            ssl_context.load_cert_chain(str(cert_path), str(key_path))
            ssl_context.load_verify_locations(cafile=settings.ca_cert_path)
            log.info("hot-reloaded server TLS certificate after renewal")
        except Exception as exc:  # noqa: BLE001 — reload must not crash renewal
            log.warning("could not hot-reload TLS certificate (restart will apply it): %s", exc)


async def renew_if_needed(
    settings: AgentSettings,
    ssl_context: ssl.SSLContext | None = None,
) -> None:
    """Renew the certificate when within ``renew_before_days`` of expiry.

    Best-effort: never raises. Skips silently when renewal cannot proceed
    (missing scheduler URL, unknown slug, missing cert files). ``ssl_context``,
    when given, is the live listener context to hot-reload after a renewal.
    """
    if not settings.scheduler_url:
        return

    cert_path = Path(settings.cert_path)
    key_path = Path(settings.key_path)
    if not cert_path.exists() or not key_path.exists():
        return

    try:
        not_after = _cert_not_after(cert_path)
        if not_after is None:
            return

        days_left = (not_after - datetime.now(UTC)).total_seconds() / 86400
        if days_left > settings.renew_before_days:
            log.debug("certificate has %.1f days left — no renewal needed", days_left)
            return

        slug = _resolve_slug(settings)
        if not slug:
            log.warning(
                "certificate expires in %.1f days but slug is unknown "
                "(set PROBE_AGENT_SLUG) — skipping renewal",
                days_left,
            )
            return

        log.info("certificate expires in %.1f days — renewing", days_left)
        await _renew(settings, slug, ssl_context=ssl_context)
    except Exception as exc:  # noqa: BLE001 — renewal must never crash the agent
        log.warning("certificate renewal failed (will retry next cycle): %s", exc)


async def renewal_loop(
    settings: AgentSettings,
    ssl_context: ssl.SSLContext | None = None,
) -> None:
    """Background task: check for renewal now, then every ``renew_check_hours``.

    ``ssl_context`` is the live listener context (mTLS mode only); a renewed
    certificate is hot-swapped onto it so the running server needs no restart.
    """
    interval = max(1, settings.renew_check_hours) * 3600
    while True:
        await renew_if_needed(settings, ssl_context=ssl_context)
        await asyncio.sleep(interval)
