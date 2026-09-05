"""The agent server admits only the scheduler, via the certificate EKU split.

Agent certificates are issued ``serverAuth``-only; only the scheduler holds a
``clientAuth`` certificate. A ``PROTOCOL_TLS_SERVER`` context verifies the peer
for the TLS-*client* purpose, so OpenSSL rejects a ``serverAuth``-only client
certificate ("unsuitable certificate purpose"). This is what stops one agent's
certificate from being used to dial another agent's ``/probe`` endpoint.

Like ``test_mtls``, these use ``asyncio.start_server`` with the exact context
``build_server_context`` produces, so they run fast without Docker.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import AgentSettings
from mtls.ssl_context import build_server_context


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca(cn: str, key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def _leaf(cn, key, ca_cert, ca_key, eku):
    # Key identifiers as the gateway issues them (RFC 5280; enforced by 3.13's
    # default context).
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )


def _write(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture
def eku_pki(tmp_path):
    ca_key = _key()
    ca_cert = _ca("Test CA", ca_key)

    srv_key = _key()
    srv_cert = _leaf("agent-a", srv_key, ca_cert, ca_key, [ExtendedKeyUsageOID.SERVER_AUTH])

    scheduler_key = _key()
    scheduler_cert = _leaf(
        "tracedown-scheduler", scheduler_key, ca_cert, ca_key, [ExtendedKeyUsageOID.CLIENT_AUTH]
    )

    # A rogue: another agent's serverAuth-only cert, tried as a client.
    rogue_key = _key()
    rogue_cert = _leaf("agent-b", rogue_key, ca_cert, ca_key, [ExtendedKeyUsageOID.SERVER_AUTH])

    ca_path = tmp_path / "ca.pem"
    cert_path = tmp_path / "agent.pem"
    key_path = tmp_path / "agent-key.pem"
    _write(ca_path, ca_cert)
    _write(cert_path, srv_cert)
    _write_key(key_path, srv_key)

    sched_path = tmp_path / "scheduler.pem"
    sched_key_path = tmp_path / "scheduler-key.pem"
    _write(sched_path, scheduler_cert)
    _write_key(sched_key_path, scheduler_key)

    rogue_path = tmp_path / "rogue.pem"
    rogue_key_path = tmp_path / "rogue-key.pem"
    _write(rogue_path, rogue_cert)
    _write_key(rogue_key_path, rogue_key)

    settings = AgentSettings(
        ca_cert_path=str(ca_path), cert_path=str(cert_path), key_path=str(key_path)
    )
    return {
        "settings": settings,
        "ca_path": ca_path,
        "scheduler": (str(sched_path), str(sched_key_path)),
        "rogue": (str(rogue_path), str(rogue_key_path)),
    }


async def _serve(ctx: ssl.SSLContext):
    async def handle(reader, writer):
        with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
            writer.write(b"x")
            await writer.drain()
            await reader.read()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _authorized(port: int, ca_path: str, client_cert) -> bool:
    cctx = ssl.create_default_context(cafile=ca_path)
    cctx.check_hostname = False
    cctx.load_cert_chain(client_cert[0], client_cert[1])
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=cctx)
    except ssl.SSLError:
        return False
    try:
        try:
            data = await reader.read(1)
        except (ssl.SSLError, ConnectionError, OSError):
            data = b""
    finally:
        writer.close()
        with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
            await writer.wait_closed()
    return data == b"x"


def test_scheduler_clientauth_cert_is_admitted(eku_pki):
    ctx = build_server_context(eku_pki["settings"])

    async def run():
        server, port = await _serve(ctx)
        async with server:
            assert await _authorized(port, str(eku_pki["ca_path"]), eku_pki["scheduler"])

    asyncio.run(run())


def test_rogue_agent_serverauth_cert_is_refused(eku_pki):
    """Another agent's serverAuth-only certificate cannot act as a TLS client
    here — the cross-agent SSRF the EKU split forecloses."""
    ctx = build_server_context(eku_pki["settings"])

    async def run():
        server, port = await _serve(ctx)
        async with server:
            assert not await _authorized(port, str(eku_pki["ca_path"]), eku_pki["rogue"])

    asyncio.run(run())
