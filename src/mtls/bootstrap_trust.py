"""Peer authentication for the one-shot bootstrap request.

Bootstrap is the agent's only unauthenticated moment. That single POST carries
the single-use bootstrap token *and* receives the CA bundle the agent pins for
the rest of its life; every later call is mutual TLS against that pinned anchor.
So if the peer is not authenticated on this one request, nothing downstream is
either: an on-path attacker reads the token in the clear and installs a CA of
their own, which the agent then trusts forever.

The gateway can be authenticated three ways, in order of preference:

* **System trust store** (the default) — the gateway is reached over ordinary,
  publicly trusted HTTPS, which is what a reverse proxy with a real certificate
  gives you. Nothing to configure.
* **Out-of-band pinning** — ``PROBE_AGENT_BOOTSTRAP_CA_BUNDLE`` (a PEM bundle,
  for a gateway fronted by a private CA) or ``PROBE_AGENT_BOOTSTRAP_PIN_SHA256``
  (the SHA-256 fingerprint of the certificate the gateway presents). Both reach
  the operator alongside the bootstrap token, which already has to travel out of
  band.
* **An explicit opt-out** — ``PROBE_AGENT_INSECURE_SKIP_BOOTSTRAP_TLS_VERIFY``,
  for local development only. It is refused when ``DEPLOYMENT_ENV=production``
  and logged at WARNING every time it is used.

A plain ``http://`` gateway URL has no transport to authenticate at all. It is
what the Compose stacks use on a private container network, so it stays allowed
(loudly) outside production and is refused outright in production.

Deliberately, no path through this module returns "do not verify" by default:
reaching it always takes an environment variable whose name says what it costs.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from config import AgentSettings

log = logging.getLogger(__name__)

#: Environment variable naming the deployment environment. Mirrors the backend's
#: ``SecretGuard``: only the exact value ``production`` arms the guards, and
#: anything else (unset included) is treated as development.
DEPLOYMENT_ENV_VAR = "DEPLOYMENT_ENV"
PRODUCTION = "production"

#: Name of the opt-out, spelled out in error messages so an operator who hits a
#: guard is told the exact variable rather than left to guess.
INSECURE_VAR = "PROBE_AGENT_INSECURE_SKIP_BOOTSTRAP_TLS_VERIFY"
CA_BUNDLE_VAR = "PROBE_AGENT_BOOTSTRAP_CA_BUNDLE"
PIN_VAR = "PROBE_AGENT_BOOTSTRAP_PIN_SHA256"

#: How to obtain the fingerprint PIN_VAR wants, quoted in guidance messages.
FINGERPRINT_HOWTO = (
    "openssl s_client -connect HOST:443 </dev/null 2>/dev/null "
    "| openssl x509 -noout -fingerprint -sha256"
)

_PRECONNECT_TIMEOUT_SECONDS = 10.0


def is_production(settings: AgentSettings) -> bool:
    """True when the resolved deployment environment is exactly ``production``."""
    return settings.deployment_env.strip().lower() == PRODUCTION


def normalize_fingerprints(raw: str) -> set[str]:
    """Parse ``PROBE_AGENT_BOOTSTRAP_PIN_SHA256`` into lowercase hex digests.

    Accepts one or more fingerprints separated by commas or whitespace, with or
    without the colons that ``openssl x509 -fingerprint`` prints, and with or
    without a leading ``sha256:`` label.
    """
    pins: set[str] = set()
    for chunk in raw.replace(",", " ").split():
        candidate = chunk.strip().lower()
        candidate = candidate.removeprefix("sha256:").replace(":", "")
        if not candidate:
            continue
        if len(candidate) != 64 or not all(c in "0123456789abcdef" for c in candidate):
            raise RuntimeError(
                f"{PIN_VAR} contains {chunk!r}, which is not a SHA-256 fingerprint "
                f"(64 hex characters, colons optional). Obtain it with: {FINGERPRINT_HOWTO}"
            )
        pins.add(candidate)
    if not pins:
        raise RuntimeError(f"{PIN_VAR} is set but contains no fingerprint.")
    return pins


def _host_port(url: str) -> tuple[str, int]:
    """Split a gateway URL into the host and port to open a TLS connection to."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise RuntimeError(f"PROBE_AGENT_SCHEDULER_URL is not a usable URL: {url!r}")
    return host, parts.port or 443


def fetch_peer_certificate(host: str, port: int, timeout: float) -> bytes:
    """Return the DER of the certificate ``host:port`` presents.

    Verification is off for this handshake on purpose — its whole point is to
    obtain the certificate so the caller can decide whether to trust it. No
    secret is sent over it, and the connection is closed again immediately.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError(
            f"{host}:{port} presented no TLS certificate to pin against."
        )
    return der


def pinned_context(der: bytes) -> ssl.SSLContext:
    """Build a client context that trusts exactly the certificate in ``der``.

    ``PARTIAL_CHAIN`` lets that certificate act as the trust anchor even when it
    is a leaf issued by some CA rather than a self-signed root — without it
    OpenSSL insists on walking up to a self-signed certificate the agent does
    not have. Hostname matching is off because the pin, not the name in it, is
    the identity being authenticated.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=der)
    return ctx


def ca_bundle_context(bundle_path: str) -> ssl.SSLContext:
    """Build a client context that verifies the gateway against a private CA."""
    path = Path(bundle_path)
    if not path.is_file():
        raise RuntimeError(
            f"{CA_BUNDLE_VAR}={bundle_path} does not exist (or is not a file). "
            "Point it at the PEM bundle of the CA that issued the gateway's "
            "certificate, and make sure it is mounted into the agent container."
        )
    ctx = ssl.create_default_context(cafile=str(path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Python 3.13 turned on OpenSSL's X509_STRICT in the default context: the
    # chain must carry RFC 5280 key identifiers and the CA a keyUsage with
    # keyCertSign. A public CA always does (system_trust_context keeps the
    # flag); an operator's private CA often does not — roots minted by older
    # tooling, including the Tracedown gateway's own before it issued them —
    # and the operator handed us this bundle precisely to trust it. The bundle
    # is the trust decision; strictness about its metadata is not.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def system_trust_context() -> ssl.SSLContext:
    """Build a client context verifying against the system trust store."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _pin_and_bind(pins: set[str], der: bytes) -> ssl.SSLContext:
    """Check ``der`` against ``pins`` and bind the request to that certificate.

    The pre-connect handshake that produced ``der`` already proved the peer holds
    that certificate's private key, and the returned context trusts nothing else,
    so the request that follows is bound to the same certificate rather than to
    "whatever answers next" — there is no check-then-use gap to race.
    """
    presented = hashlib.sha256(der).hexdigest()
    if presented not in pins:
        raise RuntimeError(
            f"the gateway presented a certificate whose SHA-256 fingerprint is "
            f"{presented}, which is not in {PIN_VAR} ({', '.join(sorted(pins))}). "
            "Refusing to send the bootstrap token. Either the pin is stale (the "
            "gateway's certificate was renewed — take a fresh fingerprint when you "
            f"mint the token: {FINGERPRINT_HOWTO}) or something is intercepting the "
            "connection."
        )
    log.info("gateway certificate matches the configured pin %s", presented)
    return pinned_context(der)


async def resolve_bootstrap_verify(settings: AgentSettings) -> ssl.SSLContext | bool:
    """Return the httpx ``verify`` argument for the bootstrap registration call.

    Raises :class:`RuntimeError` — fatal, bootstrap must not proceed — when the
    configuration would send the token to an unauthenticated peer in production.
    """
    insecure = settings.insecure_skip_bootstrap_tls_verify
    production = is_production(settings)

    if insecure and production:
        raise RuntimeError(
            f"{INSECURE_VAR} is set but {DEPLOYMENT_ENV_VAR}={PRODUCTION} — refusing to "
            "send the bootstrap token to a gateway nobody authenticated. Serve the "
            "gateway over publicly trusted HTTPS, or set "
            f"{CA_BUNDLE_VAR} to the PEM bundle of its private CA, or set {PIN_VAR} to "
            "the SHA-256 fingerprint of the certificate it presents (which the operator "
            "who issued your bootstrap token can hand you along with it)."
        )

    scheme = urlsplit(settings.scheduler_url).scheme.lower()
    if scheme != "https":
        if production:
            # No escape hatch here on purpose: the opt-out is refused in production
            # either way. The answer is an https URL that terminates TLS in front of
            # the gateway — which means the vhost has to proxy /internal/agents/
            # through to it, so the message says so rather than assuming it does.
            raise RuntimeError(
                f"refusing to send the bootstrap token in the clear: "
                f"PROBE_AGENT_SCHEDULER_URL is {settings.scheduler_url!r} (not https) and "
                f"{DEPLOYMENT_ENV_VAR}={PRODUCTION}. Point it at an https:// URL that "
                f"terminates TLS in front of the gateway; that vhost must proxy "
                f"/internal/agents/ through to the gateway for enrolment and renewal to "
                f"reach it. If its certificate comes from a private CA rather than a "
                f"public one, set {CA_BUNDLE_VAR} to the CA's PEM bundle or {PIN_VAR} to "
                f"the certificate's SHA-256 fingerprint ({FINGERPRINT_HOWTO})."
            )
        log.warning(
            "bootstrapping over %s — the bootstrap token is sent unencrypted and the "
            "gateway is not authenticated. Acceptable only on a private network you "
            "trust; use an https:// gateway URL anywhere else.",
            scheme or "an unknown scheme",
        )
        return False

    if insecure:
        log.warning(
            "%s is set — the gateway's TLS certificate will NOT be verified. The "
            "bootstrap token and the CA the agent pins for life are both exposed to "
            "anyone on the path. This is for local development only.",
            INSECURE_VAR,
        )
        return False

    if settings.bootstrap_pin_sha256:
        if settings.bootstrap_ca_bundle:
            log.info(
                "%s is set as well as %s — the pin takes precedence",
                CA_BUNDLE_VAR,
                PIN_VAR,
            )
        # Parse before touching the network so a typo'd pin is a config error,
        # not a confusing mismatch after a connection was already made.
        pins = normalize_fingerprints(settings.bootstrap_pin_sha256)
        host, port = _host_port(settings.scheduler_url)
        der = await asyncio.to_thread(
            fetch_peer_certificate, host, port, _PRECONNECT_TIMEOUT_SECONDS
        )
        return _pin_and_bind(pins, der)

    if settings.bootstrap_ca_bundle:
        log.info(
            "verifying the gateway against the CA bundle at %s",
            settings.bootstrap_ca_bundle,
        )
        return ca_bundle_context(settings.bootstrap_ca_bundle)

    log.info("verifying the gateway's certificate against the system trust store")
    return system_trust_context()


def verification_failure_hint(url: str, exc: BaseException) -> str:
    """The message shown when the bootstrap connection could not be authenticated."""
    return (
        f"could not authenticate the gateway at {url} while registering: {exc}. "
        "The bootstrap token is only ever sent to a peer the agent could authenticate, "
        "so registration was abandoned before it was sent. If the gateway's certificate "
        f"comes from a private CA, set {CA_BUNDLE_VAR} to that CA's PEM bundle; or set "
        f"{PIN_VAR} to the SHA-256 fingerprint of the certificate the gateway presents "
        f"({FINGERPRINT_HOWTO}). For local development only, {INSECURE_VAR}=true skips "
        "verification entirely."
    )
