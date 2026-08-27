"""mTLS certificate bootstrap.

On first startup the agent generates an RSA-4096 keypair, creates a
CSR, and registers with the probe-scheduler.  The scheduler validates
the bootstrap token (which already identifies this agent), signs the
CSR with its internal CA, and returns the signed certificate + CA root.
Subsequent starts skip registration if the cert files already exist.

This one request is the agent's only unauthenticated moment, so the gateway is
authenticated before the token leaves the process — by the system trust store,
by an out-of-band pin, or by an explicit local-development opt-out. See
``mtls/bootstrap_trust.py``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from config import AgentSettings
from mtls.bootstrap_trust import resolve_bootstrap_verify, verification_failure_hint
from mtls.ca_pins import ca_fingerprints, write_pins

log = logging.getLogger(__name__)


def generate_keypair() -> rsa.RSAPrivateKey:
    """Generate a fresh RSA-4096 private key."""
    log.info("generating RSA-4096 keypair")
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def private_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a private key to unencrypted PKCS#8 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def build_csr_pem(private_key: rsa.RSAPrivateKey) -> str:
    """Build a PKCS#10 CSR for the agent, signed by ``private_key``."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tracedown-agent"),
            ])
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


async def ensure_registered(settings: AgentSettings) -> None:
    """Generate a keypair and register with the scheduler if needed."""
    cert_path = Path(settings.cert_path)
    key_path = Path(settings.key_path)

    if cert_path.exists() and key_path.exists():
        log.info("certificates already present — skipping bootstrap")
        return

    private_key = generate_keypair()

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(private_key_pem(private_key))

    csr_pem = build_csr_pem(private_key)

    import socket
    hostname = socket.getfqdn()
    # https:// — the scheduler dials this URI over mutual TLS. The agent's
    # certificate (issued below) is what authorizes those requests, so the
    # advertised scheme must be https or the scheduler would connect in the clear.
    agent_uri = f"https://{hostname}:{settings.port}"

    log.info("registering with scheduler at %s (agent URI: %s)", settings.scheduler_url, agent_uri)

    # Authenticate the gateway BEFORE the token is on the wire. Raises rather
    # than falling back, so a configuration that cannot authenticate the peer
    # fails registration instead of quietly leaking the token.
    verify = await resolve_bootstrap_verify(settings)

    try:
        async with httpx.AsyncClient(verify=verify) as client:
            resp = await client.post(
                f"{settings.scheduler_url}/internal/agents/register",
                json={
                    "bootstrapToken": settings.bootstrap_token,
                    "csrPem": csr_pem,
                    "agentUri": agent_uri,
                },
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.ConnectError as exc:
        # A failed handshake here is the common upgrade symptom: the gateway is
        # behind a certificate the agent cannot chain to. Say exactly what to set.
        raise RuntimeError(
            verification_failure_hint(settings.scheduler_url, exc)
        ) from exc

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_text(data["certificatePem"])

    ca_root_pem = data["caRootPem"]
    ca_path = Path(settings.ca_cert_path)
    ca_path.parent.mkdir(parents=True, exist_ok=True)
    ca_path.write_text(ca_root_pem)

    # Trust-on-first-use: pin the CA fingerprints we were just handed. Renewal
    # will refuse any future bundle that drops all of these (an anchor swap).
    pins = ca_fingerprints(ca_root_pem)
    if pins:
        write_pins(Path(settings.ca_pins_path), pins)
        log.info("pinned %d CA fingerprint(s) at bootstrap: %s", len(pins), ", ".join(sorted(pins)))

    slug = data.get("slug")
    if slug:
        slug_path = Path(settings.slug_path)
        slug_path.parent.mkdir(parents=True, exist_ok=True)
        slug_path.write_text(slug)

    log.info("bootstrap complete — certificate written to %s", cert_path)
