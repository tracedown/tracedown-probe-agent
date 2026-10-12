"""Renewal authenticates whatever answers for the gateway — and only that.

An agent enrolled through ``https://`` reaches the gateway in one of two ways:
directly, where the gateway presents a certificate from the platform's own CA,
or through something that terminates TLS in front of it, where the certificate
comes from a CA the agent's pinned bundle has never heard of. Renewal used to
verify against the pinned CA alone, so the second kind of agent could not renew
at all and kept its first certificate until it expired.

These run ``renewal._renew`` against real TLS listeners on loopback: the trust
decision is made by OpenSSL, not by a stub.
"""

from __future__ import annotations

import asyncio
import datetime
import http.server
import ipaddress
import json
import socket
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import AgentSettings
from mtls import renewal
from mtls.ca_pins import ca_fingerprints, write_pins


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("DEPLOYMENT_ENV", "PROBE_AGENT_DEPLOYMENT_ENV"):
        monkeypatch.delenv(var, raising=False)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _ca(cn: str):
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(ca_key, ca_cert, cn: str, dns: list[str], ips: list[str] = ()):
    key = _key()
    now = datetime.datetime.now(datetime.UTC)
    sans = [x509.DNSName(d) for d in dns] + [
        x509.IPAddress(ipaddress.ip_address(i)) for i in ips
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


class _RenewEndpoint:
    """An https listener on loopback that answers POST /internal/agents/renew."""

    def __init__(self, tmp_path, name, key, cert, payload):
        cert_file = tmp_path / f"{name}.pem"
        key_file = tmp_path / f"{name}-key.pem"
        cert_file.write_text(_pem(cert))
        key_file.write_bytes(_key_pem(key))
        self.requests: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                outer.requests.append({"path": self.path, "json": json.loads(body)})
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_file), str(key_file))
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def world(tmp_path):
    """An enrolled agent: a platform CA it pinned, and its own cert + key."""
    platform_key, platform_ca = _ca("Platform Internal CA")
    agent_key, agent_cert = _leaf(platform_key, platform_ca, "agent-a", ["agent-a"])

    ca_path = tmp_path / "ca.pem"
    ca_path.write_text(_pem(platform_ca))
    cert_path = tmp_path / "agent.pem"
    cert_path.write_text(_pem(agent_cert))
    key_path = tmp_path / "agent-key.pem"
    key_path.write_bytes(_key_pem(agent_key))
    pins_path = tmp_path / "ca-pins.txt"
    write_pins(pins_path, ca_fingerprints(_pem(platform_ca)))

    def settings(port: int, **extra) -> AgentSettings:
        return AgentSettings(
            scheduler_url=f"https://localhost:{port}",
            ca_cert_path=str(ca_path),
            cert_path=str(cert_path),
            key_path=str(key_path),
            ca_pins_path=str(pins_path),
            slug="agent-a",
            **extra,
        )

    return {
        "tmp": tmp_path,
        "platform_key": platform_key,
        "platform_ca": platform_ca,
        "old_cert": _pem(agent_cert),
        "cert_path": cert_path,
        "settings": settings,
        "payload": {"certificatePem": "NEW-CERT", "caRootPem": _pem(platform_ca)},
    }


def _front(world, name="front", dns=("localhost",)):
    """A TLS front: its own CA, which the agent's pinned bundle does not hold."""
    front_key, front_ca = _ca("Some Public CA")
    key, cert = _leaf(front_key, front_ca, name, list(dns), ["127.0.0.1"] if "localhost" in dns else [])
    bundle = world["tmp"] / f"{name}-ca.pem"
    bundle.write_text(_pem(front_ca))
    return key, cert, bundle


def test_renewal_through_a_tls_front_is_authenticated_as_the_operator_configured(world):
    # The regression: the front's certificate is not from the pinned CA, and
    # renewal used to stop right there with CERTIFICATE_VERIFY_FAILED.
    key, cert, bundle = _front(world)
    with _RenewEndpoint(world["tmp"], "front", key, cert, world["payload"]) as srv:
        settings = world["settings"](srv.port, bootstrap_ca_bundle=str(bundle))
        asyncio.run(renewal._renew(settings, "agent-a"))

    assert world["cert_path"].read_text() == "NEW-CERT"
    assert [r["path"] for r in srv.requests] == ["/internal/agents/renew"]
    assert srv.requests[0]["json"]["slug"] == "agent-a"


def test_a_gateway_with_a_platform_ca_certificate_is_still_reached_first_try(world, monkeypatch):
    # Nothing changes where it already worked: mutual TLS against the pinned
    # CA, and the configured front trust is never even consulted.
    key, cert = _leaf(world["platform_key"], world["platform_ca"], "gateway", ["gateway"])

    async def must_not_be_called(settings):
        raise AssertionError("the TLS-front path was taken for a platform-CA gateway")

    monkeypatch.setattr(renewal, "gateway_trust_context", must_not_be_called)
    with _RenewEndpoint(world["tmp"], "gateway", key, cert, world["payload"]) as srv:
        asyncio.run(renewal._renew(world["settings"](srv.port), "agent-a"))

    assert world["cert_path"].read_text() == "NEW-CERT"
    assert len(srv.requests) == 1


def test_a_certificate_nobody_vouched_for_is_refused_and_nothing_is_written(world):
    # Neither the pinned CA nor the configured bundle issued it.
    key, cert, _ = _front(world, name="rogue")
    _, _, other_bundle = _front(world, name="expected")
    with _RenewEndpoint(world["tmp"], "rogue", key, cert, world["payload"]) as srv:
        settings = world["settings"](srv.port, bootstrap_ca_bundle=str(other_bundle))
        with pytest.raises(httpx.ConnectError):
            asyncio.run(renewal._renew(settings, "agent-a"))

    assert srv.requests == []
    assert world["cert_path"].read_text() == world["old_cert"]


def test_the_front_must_hold_a_certificate_for_the_name_that_was_dialled(world):
    # A trusted CA is not enough: any certificate that CA ever issued would
    # otherwise do. The pinned-CA path does not check names (the platform CA
    # only issues to the platform); the front path must.
    key, cert, bundle = _front(world, name="elsewhere", dns=("elsewhere.example",))
    with _RenewEndpoint(world["tmp"], "elsewhere", key, cert, world["payload"]) as srv:
        settings = world["settings"](srv.port, bootstrap_ca_bundle=str(bundle))
        with pytest.raises(httpx.ConnectError):
            asyncio.run(renewal._renew(settings, "agent-a"))

    assert srv.requests == []
    assert world["cert_path"].read_text() == world["old_cert"]


def test_the_enrolment_opt_out_does_not_reach_renewal(world):
    # PROBE_AGENT_INSECURE_SKIP_BOOTSTRAP_TLS_VERIFY is about one request, made
    # once, before the agent had anything to verify with. Renewal has no such
    # excuse and never skips verification.
    key, cert, _ = _front(world, name="unverified")
    with _RenewEndpoint(world["tmp"], "unverified", key, cert, world["payload"]) as srv:
        settings = world["settings"](srv.port, insecure_skip_bootstrap_tls_verify=True)
        with pytest.raises(httpx.ConnectError):
            asyncio.run(renewal._renew(settings, "agent-a"))

    assert srv.requests == []
    assert world["cert_path"].read_text() == world["old_cert"]


def test_only_a_rejected_certificate_moves_on_to_the_front(world, monkeypatch):
    # A refused connection says nothing about which trust anchor is right, so
    # it must surface as itself rather than trigger a second attempt.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]

    async def must_not_be_called(settings):
        raise AssertionError("a refused connection was retried against the TLS front")

    monkeypatch.setattr(renewal, "gateway_trust_context", must_not_be_called)
    with pytest.raises(httpx.ConnectError):
        asyncio.run(renewal._renew(world["settings"](closed_port), "agent-a"))

    assert world["cert_path"].read_text() == world["old_cert"]


def test_a_front_that_swaps_the_trust_anchor_is_still_refused(world):
    # Being authenticated as the front does not make its answer trusted: the
    # CA-continuity pin holds on this path exactly as on the other.
    key, cert, bundle = _front(world)
    _, attacker_ca = _ca("Attacker CA")
    payload = {"certificatePem": "NEW-CERT", "caRootPem": _pem(attacker_ca)}
    with _RenewEndpoint(world["tmp"], "front", key, cert, payload) as srv:
        settings = world["settings"](srv.port, bootstrap_ca_bundle=str(bundle))
        with pytest.raises(RuntimeError, match="trust anchor"):
            asyncio.run(renewal._renew(settings, "agent-a"))

    assert world["cert_path"].read_text() == world["old_cert"]
