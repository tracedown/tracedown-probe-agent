"""Mutual-TLS server context: authorization model and certificate hot-reload.

These tests exercise the security-critical behavior that the certificate — not
an API key or bearer token — is what authorizes inbound requests, and that a
renewed certificate is picked up by the live listener without a restart.

They use ``asyncio.start_server`` with the exact context ``build_server_context``
produces, rather than a full uvicorn boot, so they run fast and deterministically
without Docker.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from config import AgentSettings
from mtls.ssl_context import build_server_context


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _self_signed(cn: str, key) -> x509.Certificate:
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


def _signed_by(cn: str, key, ca_cert: x509.Certificate, ca_key) -> x509.Certificate:
    # Mirrors what the gateway's CaService issues: the key identifiers RFC 5280
    # requires, which Python 3.13's default context enforces (X509_STRICT).
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )


def _write(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture
def pki(tmp_path):
    """A CA, a CA-signed server identity, a CA-signed client, and a rogue client."""
    ca_key = _key()
    ca_cert = _self_signed("Test CA", ca_key)

    srv_key = _key()
    srv_cert = _signed_by("agent-v1", srv_key, ca_cert, ca_key)

    cli_key = _key()
    cli_cert = _signed_by("scheduler", cli_key, ca_cert, ca_key)

    rogue_key = _key()
    rogue_cert = _self_signed("rogue", rogue_key)

    ca_path = tmp_path / "ca.pem"
    cert_path = tmp_path / "agent.pem"
    key_path = tmp_path / "agent-key.pem"
    _write(ca_path, ca_cert)
    _write(cert_path, srv_cert)
    _write_key(key_path, srv_key)

    cli_path = tmp_path / "client.pem"
    cli_key_path = tmp_path / "client-key.pem"
    _write(cli_path, cli_cert)
    _write_key(cli_key_path, cli_key)

    rogue_path = tmp_path / "rogue.pem"
    rogue_key_path = tmp_path / "rogue-key.pem"
    _write(rogue_path, rogue_cert)
    _write_key(rogue_key_path, rogue_key)

    settings = AgentSettings(
        ca_cert_path=str(ca_path),
        cert_path=str(cert_path),
        key_path=str(key_path),
    )
    return {
        "tmp": tmp_path,
        "settings": settings,
        "ca_cert": ca_cert,
        "ca_key": ca_key,
        "ca_path": ca_path,
        "cert_path": cert_path,
        "key_path": key_path,
        "client": (str(cli_path), str(cli_key_path)),
        "rogue": (str(rogue_path), str(rogue_key_path)),
    }


async def _serve(ctx: ssl.SSLContext):
    async def handle(reader, writer):
        # Only reached once the mutual handshake succeeds. Send a byte so the
        # authorized client's read completes without racing the socket close.
        with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
            writer.write(b"x")
            await writer.drain()
            await reader.read()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _exchange(port: int, ca_path: str, client_cert=None):
    """Connect and return ``(server_cn, authorized)``.

    ``authorized`` is True only when the server's handler actually ran and sent
    its byte — the reliable signal that the mutual handshake was accepted. Under
    TLS 1.3 the client's own handshake finishes before the server validates the
    client certificate, so a rejected client still completes ``open_connection``;
    the rejection then shows up as the handler never running (EOF / no data) or an
    SSL alert on read. Either way, no server byte means not authorized.
    """
    cctx = ssl.create_default_context(cafile=ca_path)
    cctx.check_hostname = False
    if client_cert:
        cctx.load_cert_chain(client_cert[0], client_cert[1])
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=cctx)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        try:
            data = await reader.read(1)
        except (ssl.SSLError, ConnectionError, OSError):
            data = b""
    finally:
        writer.close()
        with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
            await writer.wait_closed()
    cn = x509.load_der_x509_certificate(der).subject.rfc4514_string() if der else None
    return cn, data == b"x"


def test_context_requires_client_certificate(pki):
    ctx = build_server_context(pki["settings"])
    assert ctx.verify_mode == ssl.CERT_REQUIRED

    async def run():
        server, port = await _serve(ctx)
        async with server:
            # A CA-signed client is authorized and reaches the handler.
            cn, authorized = await _exchange(port, str(pki["ca_path"]), client_cert=pki["client"])
            assert authorized
            assert cn == "CN=agent-v1"

            # No client certificate — the CERT_REQUIRED listener never runs the
            # handler, so the certificate alone is the authorization.
            _, authorized = await _exchange(port, str(pki["ca_path"]), client_cert=None)
            assert not authorized

            # A certificate not signed by our CA — likewise rejected.
            _, authorized = await _exchange(port, str(pki["ca_path"]), client_cert=pki["rogue"])
            assert not authorized

    asyncio.run(run())


def test_renewal_hot_swaps_served_certificate(pki):
    """Rewriting the cert files and reloading the live context swaps the served
    certificate for new connections — the mechanism the renewal loop relies on."""
    ctx = build_server_context(pki["settings"])

    async def run():
        server, port = await _serve(ctx)
        async with server:
            cn_before, authorized = await _exchange(
                port, str(pki["ca_path"]), client_cert=pki["client"]
            )
            assert authorized
            assert cn_before == "CN=agent-v1"

            # Issue a renewed server identity from the same CA and reload it,
            # exactly as renewal._renew does after writing the new files.
            new_key = _key()
            new_cert = _signed_by("agent-v2", new_key, pki["ca_cert"], pki["ca_key"])
            _write(pki["cert_path"], new_cert)
            _write_key(pki["key_path"], new_key)
            ctx.load_cert_chain(str(pki["cert_path"]), str(pki["key_path"]))

            cn_after, authorized = await _exchange(
                port, str(pki["ca_path"]), client_cert=pki["client"]
            )
            assert authorized
            assert cn_after == "CN=agent-v2"

    asyncio.run(run())
