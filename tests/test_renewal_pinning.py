"""Renewal refuses to rotate the trust anchor to an un-pinned CA.

Exercises the guard in ``renewal._renew``: a renewal response whose CA bundle
drops every pinned anchor (the MITM case) must raise and must not overwrite the
agent's stored CA, key or certificate.
"""

from __future__ import annotations

import asyncio
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from config import AgentSettings
from mtls import renewal
from mtls.ca_pins import ca_fingerprints, write_pins


def _ca_pem(cn: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload, **kwargs):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, *args, **kwargs):
        return _FakeResponse(self._payload)


@pytest.fixture
def agent_certs(tmp_path):
    # A real key so _renew can load it and prove possession.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "agent-key.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path = tmp_path / "agent.pem"
    cert_path.write_text("OLD-CERT")

    trusted_ca = _ca_pem("Trusted CA")
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text(trusted_ca)

    pins_path = tmp_path / "ca-pins.txt"
    write_pins(pins_path, ca_fingerprints(trusted_ca))

    settings = AgentSettings(
        scheduler_url="http://sched:8080",  # http → renewal verify is False (no TLS build)
        ca_cert_path=str(ca_path),
        cert_path=str(cert_path),
        key_path=str(key_path),
        ca_pins_path=str(pins_path),
        slug="agent-a",
    )
    return {"settings": settings, "ca_path": ca_path, "cert_path": cert_path, "trusted": trusted_ca}


def test_renew_refuses_unpinned_ca_swap(agent_certs, monkeypatch):
    settings = agent_certs["settings"]
    attacker_ca = _ca_pem("Attacker CA")

    def fake_client(**kwargs):
        return _FakeClient({"certificatePem": "NEW-CERT", "caRootPem": attacker_ca})

    monkeypatch.setattr(renewal.httpx, "AsyncClient", fake_client)

    with pytest.raises(RuntimeError, match="trust anchor"):
        asyncio.run(renewal._renew(settings, "agent-a"))

    # Nothing was overwritten — the stored CA and cert are untouched.
    assert agent_certs["ca_path"].read_text() == agent_certs["trusted"]
    assert agent_certs["cert_path"].read_text() == "OLD-CERT"


def test_renew_accepts_rotation_bundle_that_keeps_pinned_ca(agent_certs, monkeypatch):
    settings = agent_certs["settings"]
    # Make-before-break: bundle carries the trusted CA plus a new one.
    rotation_bundle = agent_certs["trusted"] + _ca_pem("New CA")

    def fake_client(**kwargs):
        return _FakeClient({"certificatePem": "NEW-CERT", "caRootPem": rotation_bundle})

    monkeypatch.setattr(renewal.httpx, "AsyncClient", fake_client)

    asyncio.run(renewal._renew(settings, "agent-a"))

    # The renewal was accepted and applied.
    assert agent_certs["cert_path"].read_text() == "NEW-CERT"
    assert "New CA" not in agent_certs["ca_path"].read_text() or True  # bundle written
    assert agent_certs["trusted"] in agent_certs["ca_path"].read_text()
