"""The bootstrap token is never sent to an unauthenticated peer.

Bootstrap is the agent's only unauthenticated moment — it carries the single-use
token and receives the CA the agent pins for life — so these tests cover the
three ways the gateway can be authenticated and every path that refuses to send
the token when it cannot be.

Only loopback sockets are used; nothing here touches an external network.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from config import AgentSettings
from mtls import bootstrap, bootstrap_trust
from mtls.bootstrap_trust import (
    INSECURE_VAR,
    normalize_fingerprints,
    resolve_bootstrap_verify,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Keep an ambient DEPLOYMENT_ENV out of the settings under test."""
    monkeypatch.delenv("DEPLOYMENT_ENV", raising=False)
    monkeypatch.delenv("PROBE_AGENT_DEPLOYMENT_ENV", raising=False)


def _settings(**kwargs) -> AgentSettings:
    base = {
        "bootstrap_token": "t" * 64,
        "scheduler_url": "https://gateway.example.com",
    }
    base.update(kwargs)
    return AgentSettings(**base)


def _self_signed(common_name: str, tmp_path, ca: bool = False):
    """Write a self-signed cert + key for ``common_name``.

    Returns ``(cert_pem_path, key_path, der)``. ``ca=False`` (the default) makes
    a plain end-entity certificate — which is what proves the pinned context
    anchors on a leaf, not only on a CA.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{common_name}.pem"
    key_path = tmp_path / f"{common_name}-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)


class _TlsServer:
    """A loopback TLS listener that completes ``handshakes`` handshakes and stops."""

    def __init__(self, cert_path, key_path, handshakes: int = 4):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        self._ctx = ctx
        self._handshakes = handshakes
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        for _ in range(self._handshakes):
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                with self._ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except OSError:
                pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._sock.close()
        return False


# --- fingerprint parsing ----------------------------------------------------


def test_normalize_fingerprints_accepts_openssl_and_bare_forms():
    digest = "ab" * 32
    colonised = ":".join(digest[i : i + 2] for i in range(0, 64, 2)).upper()
    assert normalize_fingerprints(colonised) == {digest}
    assert normalize_fingerprints(f"sha256:{digest.upper()}") == {digest}
    other = "cd" * 32
    assert normalize_fingerprints(f"{digest}, {other}") == {digest, other}


def test_normalize_fingerprints_rejects_nonsense():
    with pytest.raises(RuntimeError, match="not a SHA-256 fingerprint"):
        normalize_fingerprints("deadbeef")
    with pytest.raises(RuntimeError, match="no fingerprint"):
        normalize_fingerprints("   ")


# --- the default is verification --------------------------------------------


def test_https_default_verifies_against_system_trust_store():
    verify = asyncio.run(resolve_bootstrap_verify(_settings()))
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode is ssl.CERT_REQUIRED
    assert verify.check_hostname is True


def test_verify_false_is_not_reachable_without_the_opt_out():
    """No default configuration, production or not, yields an unverified https call."""
    for env in ("dev", "staging", "production"):
        verify = asyncio.run(resolve_bootstrap_verify(_settings(deployment_env=env)))
        assert verify is not False


def test_ca_bundle_is_used_when_configured(tmp_path):
    cert_path, _, _ = _self_signed("gateway.internal", tmp_path, ca=True)
    verify = asyncio.run(
        resolve_bootstrap_verify(_settings(bootstrap_ca_bundle=str(cert_path)))
    )
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode is ssl.CERT_REQUIRED
    # The private CA is in the store the request will verify against.
    assert any(c["serialNumber"] for c in verify.get_ca_certs())


def test_missing_ca_bundle_says_what_to_fix(tmp_path):
    missing = tmp_path / "nope.pem"
    with pytest.raises(RuntimeError, match="PROBE_AGENT_BOOTSTRAP_CA_BUNDLE"):
        asyncio.run(
            resolve_bootstrap_verify(_settings(bootstrap_ca_bundle=str(missing)))
        )


# --- out-of-band pinning ----------------------------------------------------


def test_pin_match_binds_the_request_to_that_certificate(tmp_path):
    cert_path, key_path, der = _self_signed("localhost", tmp_path)
    fingerprint = hashlib.sha256(der).hexdigest()

    with _TlsServer(cert_path, key_path) as server:
        settings = _settings(
            scheduler_url=f"https://127.0.0.1:{server.port}",
            bootstrap_pin_sha256=fingerprint,
        )
        verify = asyncio.run(resolve_bootstrap_verify(settings))
        assert isinstance(verify, ssl.SSLContext)

        # The context really does authenticate that server: a live handshake
        # against it succeeds where the system trust store would not.
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=5) as sock,
            verify.wrap_socket(sock, server_hostname="127.0.0.1") as tls,
        ):
            assert tls.getpeercert(binary_form=True) == der


def test_malformed_pin_fails_before_any_connection_is_made():
    """A typo'd pin is a config error, not a confusing mismatch after connecting."""
    settings = _settings(
        # Port 1 on loopback refuses instantly — reaching it at all would fail
        # differently from the parse error this must raise.
        scheduler_url="https://127.0.0.1:1",
        bootstrap_pin_sha256="not-a-fingerprint",
    )
    with pytest.raises(RuntimeError, match="not a SHA-256 fingerprint"):
        asyncio.run(resolve_bootstrap_verify(settings))


def test_pin_mismatch_refuses_before_the_token_is_sent(tmp_path):
    cert_path, key_path, _ = _self_signed("localhost", tmp_path)
    _, _, other_der = _self_signed("impostor", tmp_path)

    with _TlsServer(cert_path, key_path) as server:
        settings = _settings(
            scheduler_url=f"https://127.0.0.1:{server.port}",
            bootstrap_pin_sha256=hashlib.sha256(other_der).hexdigest(),
        )
        with pytest.raises(
            RuntimeError, match="not in PROBE_AGENT_BOOTSTRAP_PIN_SHA256"
        ):
            asyncio.run(resolve_bootstrap_verify(settings))


def test_pinned_context_rejects_a_different_certificate(tmp_path):
    cert_path, key_path, _ = _self_signed("localhost", tmp_path)
    _, _, other_der = _self_signed("impostor", tmp_path)
    ctx = bootstrap_trust.pinned_context(other_der)

    with (
        _TlsServer(cert_path, key_path) as server,
        socket.create_connection(("127.0.0.1", server.port), timeout=5) as sock,
        pytest.raises(ssl.SSLError),
    ):
        ctx.wrap_socket(sock, server_hostname="127.0.0.1")


# --- the development opt-out ------------------------------------------------


def test_opt_out_is_refused_in_production():
    settings = _settings(
        insecure_skip_bootstrap_tls_verify=True, deployment_env="production"
    )
    with pytest.raises(RuntimeError, match=INSECURE_VAR):
        asyncio.run(resolve_bootstrap_verify(settings))


def test_opt_out_is_refused_in_production_from_the_platform_env_var(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_ENV", "production")
    settings = _settings(insecure_skip_bootstrap_tls_verify=True)
    with pytest.raises(RuntimeError, match=INSECURE_VAR):
        asyncio.run(resolve_bootstrap_verify(settings))


def test_opt_out_outside_production_skips_verification_and_warns(caplog):
    settings = _settings(insecure_skip_bootstrap_tls_verify=True)
    with caplog.at_level("WARNING"):
        verify = asyncio.run(resolve_bootstrap_verify(settings))
    assert verify is False
    assert INSECURE_VAR in caplog.text


# --- plain http (the Compose stacks) ----------------------------------------


def test_plain_http_still_works_outside_production_but_warns(caplog):
    """The local dev and e2e stacks bootstrap over http on a private network."""
    settings = _settings(scheduler_url="http://tracedown-gateway:20714")
    with caplog.at_level("WARNING"):
        verify = asyncio.run(resolve_bootstrap_verify(settings))
    assert verify is False
    assert "unencrypted" in caplog.text


def test_plain_http_is_refused_in_production():
    settings = _settings(
        scheduler_url="http://tracedown-gateway:20714", deployment_env="production"
    )
    with pytest.raises(RuntimeError, match="in the clear"):
        asyncio.run(resolve_bootstrap_verify(settings))


def test_plain_http_in_production_offers_no_opt_out():
    """The opt-out is refused in production on both branches — no way round it.

    The production deployment terminates TLS in front of the gateway, so the
    https URL the dashboard is served on is always an available answer; the
    error says so rather than pointing at a flag that would then be refused.
    """
    settings = _settings(
        scheduler_url="http://tracedown-gateway:20714",
        deployment_env="production",
        insecure_skip_bootstrap_tls_verify=True,
    )
    with pytest.raises(RuntimeError, match=INSECURE_VAR):
        asyncio.run(resolve_bootstrap_verify(settings))

    settings = _settings(
        scheduler_url="http://tracedown-gateway:20714", deployment_env="production"
    )
    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(resolve_bootstrap_verify(settings))
    assert INSECURE_VAR not in str(excinfo.value)
    assert "https://" in str(excinfo.value)


# --- the guard actually stops registration ----------------------------------


def test_ensure_registered_sends_nothing_when_the_peer_cannot_be_authenticated(
    tmp_path, monkeypatch
):
    posted: list[object] = []

    class _NeverCalled:
        def __init__(self, **kwargs):
            posted.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *args, **kwargs):  # pragma: no cover — must not run
            posted.append(kwargs)
            raise AssertionError("the bootstrap token must not be sent")

    monkeypatch.setattr(bootstrap.httpx, "AsyncClient", _NeverCalled)
    monkeypatch.setattr(bootstrap, "generate_keypair", lambda: _small_key())

    settings = _settings(
        scheduler_url="http://gateway:8080",
        deployment_env="production",
        cert_path=str(tmp_path / "agent.pem"),
        key_path=str(tmp_path / "agent-key.pem"),
        ca_cert_path=str(tmp_path / "ca.pem"),
        ca_pins_path=str(tmp_path / "ca-pins.txt"),
        slug_path=str(tmp_path / "slug.txt"),
    )
    with pytest.raises(RuntimeError, match="in the clear"):
        asyncio.run(bootstrap.ensure_registered(settings))

    assert posted == []
    assert not (tmp_path / "agent.pem").exists()


def _small_key():
    """A 2048-bit key — same interface, far cheaper than the real RSA-4096."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
