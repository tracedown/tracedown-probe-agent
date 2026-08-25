"""Payload envelope: round trip, rejection, and the parameters that must not drift.

The interop risk here is silent. RSA-OAEP with a mismatched MGF1 digest does not
raise on the sending side — it produces a wrapped key the peer decrypts to
garbage. Both ends therefore pin SHA-256 for the digest *and* MGF1, and the
assertions below fix that in place so a well-meant "simplification" on either
side fails a test instead of failing in production.
"""

from __future__ import annotations

import base64
import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from mtls import envelope


def _keypair_and_cert() -> tuple[rsa.RSAPrivateKey, str]:
    """A throwaway self-signed cert, shaped like the one the CA issues an agent."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key, pem


def test_seals_and_opens_round_trip() -> None:
    key, pem = _keypair_and_cert()
    payload = {"script": "GET https://example.test", "variables": {"s_token": "hunter2"}}

    sealed = envelope.seal_envelope(payload, pem)
    assert envelope.is_envelope(sealed)
    assert envelope.open_envelope(sealed, key) == payload


def test_the_plaintext_is_not_recoverable_from_the_envelope() -> None:
    _, pem = _keypair_and_cert()
    sealed = envelope.seal_envelope({"variables": {"s_token": "hunter2"}}, pem)

    # The whole point: a secret in the payload must not survive into the wire form.
    assert "hunter2" not in json.dumps(sealed)
    assert "hunter2" not in base64.b64decode(sealed["ct"]).decode("latin-1")


def test_a_plain_job_is_not_mistaken_for_an_envelope() -> None:
    assert not envelope.is_envelope({"script": "GET https://example.test", "variables": {}})


def test_the_wrong_key_cannot_open_it() -> None:
    _, pem = _keypair_and_cert()
    other_key, _ = _keypair_and_cert()
    sealed = envelope.seal_envelope({"script": "x"}, pem)

    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(sealed, other_key)


def test_a_tampered_ciphertext_is_refused() -> None:
    key, pem = _keypair_and_cert()
    sealed = envelope.seal_envelope({"script": "GET https://example.test"}, pem)

    raw = bytearray(base64.b64decode(sealed["ct"]))
    raw[0] ^= 0x01
    sealed["ct"] = base64.b64encode(bytes(raw)).decode()

    # GCM authenticates; a flipped bit is a failure, not a different plaintext.
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(sealed, key)


def test_an_unknown_version_or_algorithm_is_refused() -> None:
    key, pem = _keypair_and_cert()
    sealed = envelope.seal_envelope({"script": "x"}, pem)

    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope({**sealed, "v": 99}, key)
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope({**sealed, "alg": "RSA-OAEP-1+A256GCM"}, key)


def test_oaep_uses_sha256_for_both_digest_and_mgf1() -> None:
    """The interop invariant, asserted directly.

    A peer wrapping with MGF1-SHA1 produces a key this cannot unwrap. Decrypting
    our own wrapped key with an explicitly SHA-256/MGF1-SHA-256 spec proves which
    parameters were used, rather than trusting the constant to stay correct.
    """
    key, pem = _keypair_and_cert()
    sealed = envelope.seal_envelope({"script": "x"}, pem)

    unwrapped = key.decrypt(
        base64.b64decode(sealed["ek"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    assert len(unwrapped) == 32  # AES-256 content key

    with pytest.raises(ValueError):
        key.decrypt(
            base64.b64decode(sealed["ek"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


def test_the_iv_is_fresh_for_every_seal() -> None:
    _, pem = _keypair_and_cert()
    payload = {"script": "x"}
    ivs = {envelope.seal_envelope(payload, pem)["iv"] for _ in range(8)}
    # A repeated IV under the same key is catastrophic for GCM; a fresh content
    # key each time makes it safe regardless, but reuse would still be a smell.
    assert len(ivs) == 8
