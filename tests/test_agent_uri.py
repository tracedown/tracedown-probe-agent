"""The URI an agent registers: PROBE_AGENT_ADVERTISED_HOST/PORT, else its own
FQDN and its listen port."""

from __future__ import annotations

import asyncio
from typing import ClassVar
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from config import AgentSettings
from mtls import bootstrap
from mtls.bootstrap import advertised_agent_uri


def test_defaults_to_the_machine_fqdn():
    settings = AgentSettings(port=8443, advertised_host="")
    with patch("socket.getfqdn", return_value="runner.example.internal"):
        assert advertised_agent_uri(settings) == "https://runner.example.internal:8443"


def test_advertised_host_wins_over_the_fqdn():
    settings = AgentSettings(port=9443, advertised_host="eu-west-1.railway.internal")
    with patch("socket.getfqdn", return_value="ignored"):
        assert advertised_agent_uri(settings) == "https://eu-west-1.railway.internal:9443"


def test_blank_advertised_host_is_unset():
    settings = AgentSettings(port=8443, advertised_host="   ")
    with patch("socket.getfqdn", return_value="runner"):
        assert advertised_agent_uri(settings) == "https://runner:8443"


# ── Advertised port ──


def test_unset_advertised_port_registers_the_listen_port():
    settings = AgentSettings(port=8443, advertised_host="agent-a")
    assert settings.advertised_port is None
    assert advertised_agent_uri(settings) == "https://agent-a:8443"


def test_advertised_port_wins_over_the_listen_port():
    """The proxy case: the agent listens on 8443, the world reaches it on 20443."""
    settings = AgentSettings(port=8443, advertised_host="agent-a", advertised_port=20443)
    assert advertised_agent_uri(settings) == "https://agent-a:20443"


def test_advertised_port_applies_to_the_fqdn_fallback():
    settings = AgentSettings(port=8443, advertised_host="", advertised_port=20443)
    with patch("socket.getfqdn", return_value="runner.example.internal"):
        assert advertised_agent_uri(settings) == "https://runner.example.internal:20443"


def test_advertised_port_does_not_change_the_listen_port():
    settings = AgentSettings(port=8443, advertised_host="agent-a", advertised_port=20443)
    assert settings.port == 8443


def test_advertised_port_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("PROBE_AGENT_ADVERTISED_PORT", "20443")
    monkeypatch.setenv("PROBE_AGENT_ADVERTISED_HOST", "agent-a")
    settings = AgentSettings()
    assert advertised_agent_uri(settings) == "https://agent-a:20443"


def test_blank_advertised_port_is_unset(monkeypatch):
    """A declared-but-empty variable must not stop the agent from starting."""
    monkeypatch.setenv("PROBE_AGENT_ADVERTISED_PORT", "")
    monkeypatch.setenv("PROBE_AGENT_ADVERTISED_HOST", "agent-a")
    monkeypatch.setenv("PROBE_AGENT_PORT", "8443")
    settings = AgentSettings()
    assert settings.advertised_port is None
    assert advertised_agent_uri(settings) == "https://agent-a:8443"


@pytest.mark.parametrize("port", [1, 443, 65535])
def test_advertised_port_accepts_the_valid_range(port):
    settings = AgentSettings(advertised_host="agent-a", advertised_port=port)
    assert advertised_agent_uri(settings) == f"https://agent-a:{port}"


@pytest.mark.parametrize("port", [0, -1, 65536, 99999])
def test_advertised_port_rejects_ports_outside_the_range(port):
    with pytest.raises(ValidationError):
        AgentSettings(advertised_port=port)


# ── The registered address is built in exactly one place ──


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _RecordingClient:
    """Captures the JSON body of every POST the agent makes."""

    posts: ClassVar[list[tuple[str, dict]]] = []

    def __init__(self, payload, **kwargs):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kwargs):
        type(self).posts.append((url, kwargs.get("json") or {}))
        return _FakeResponse(self._payload)


def test_registration_advertises_the_proxy_port(tmp_path, monkeypatch):
    settings = AgentSettings(
        scheduler_url="http://gateway:8080",
        port=8443,
        advertised_host="agent-a.example.com",
        advertised_port=20443,
        cert_path=str(tmp_path / "agent.pem"),
        key_path=str(tmp_path / "agent-key.pem"),
        ca_cert_path=str(tmp_path / "ca.pem"),
        ca_pins_path=str(tmp_path / "ca-pins.txt"),
        slug_path=str(tmp_path / "slug.txt"),
    )

    # A smaller key: this test is about the payload, not about RSA-4096.
    monkeypatch.setattr(
        bootstrap,
        "generate_keypair",
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )
    _RecordingClient.posts = []
    monkeypatch.setattr(
        bootstrap.httpx,
        "AsyncClient",
        lambda **kwargs: _RecordingClient(
            {"certificatePem": "CERT", "caRootPem": "CA", "slug": "agent-a"}
        ),
    )

    asyncio.run(bootstrap.ensure_registered(settings))

    url, body = _RecordingClient.posts[0]
    assert url.endswith("/internal/agents/register")
    assert body["agentUri"] == "https://agent-a.example.com:20443"


def test_renewal_sends_no_address_so_the_registered_one_stands(tmp_path, monkeypatch):
    """Renewal carries slug + CSR + signature and no address at all.

    The gateway re-signs against the URI stored at registration, so a renewal
    can never flip the advertised port back to the listen port.
    """
    from cryptography.hazmat.primitives import serialization

    from mtls import renewal

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

    settings = AgentSettings(
        scheduler_url="http://gateway:8080",  # http → no TLS context to build
        port=8443,
        advertised_host="agent-a.example.com",
        advertised_port=20443,
        cert_path=str(cert_path),
        key_path=str(key_path),
        ca_cert_path=str(tmp_path / "ca.pem"),
        ca_pins_path=str(tmp_path / "ca-pins.txt"),
        slug="agent-a",
    )

    monkeypatch.setattr(
        renewal,
        "generate_keypair",
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )
    _RecordingClient.posts = []
    monkeypatch.setattr(
        renewal.httpx,
        "AsyncClient",
        lambda **kwargs: _RecordingClient({"certificatePem": "NEW-CERT"}),
    )

    asyncio.run(renewal._renew(settings, "agent-a"))

    url, body = _RecordingClient.posts[0]
    assert url.endswith("/internal/agents/renew")
    assert set(body) == {"slug", "csrPem", "signature"}
    assert cert_path.read_text() == "NEW-CERT"
