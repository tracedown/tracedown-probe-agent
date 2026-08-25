"""Optional payload encryption for the scheduler <-> agent exchange.

mTLS already authenticates both ends and encrypts the channel, and the
scheduler pins this agent's certificate, so a network attacker cannot read a
dispatch. What the tunnel does *not* survive is an intermediary that terminates
TLS deliberately — an ingress controller, a managed edge, a tunnel daemon given
the keys. This envelope closes that: the payload is sealed to the peer's public
key, so only the peer can read it however many hops the bytes take.

It is off unless the scheduler turns it on, and the agent supports both shapes
at once: an unencrypted dispatch keeps working exactly as before.

Format (both directions), JSON:

    {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "ek": b64, "iv": b64, "ct": b64}

``ek`` is a fresh 256-bit content key wrapped with the recipient's RSA public
key. ``ct`` is AES-256-GCM over the plaintext JSON with the GCM tag appended,
which is what both Python and Java produce by default.

The OAEP parameters are pinned deliberately: SHA-256 digest **and** SHA-256
MGF1. Java's "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" silently uses SHA-1 for
MGF1 unless an explicit OAEPParameterSpec says otherwise, which decrypts as
garbage rather than failing loudly — the scheduler passes that spec, and this
must stay matched to it.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate

ALG = "RSA-OAEP-256+A256GCM"
VERSION = 1

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class EnvelopeError(ValueError):
    """The payload claimed to be an envelope but could not be opened."""


def is_envelope(body: dict[str, Any]) -> bool:
    """Whether an inbound body is a sealed envelope rather than a plain job."""
    return "ek" in body and "ct" in body


def open_envelope(body: dict[str, Any], private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    """Decrypts a sealed envelope to the JSON object inside it."""
    version = body.get("v")
    if version != VERSION:
        raise EnvelopeError(f"unsupported envelope version {version!r}")
    if body.get("alg") != ALG:
        raise EnvelopeError(f"unsupported envelope algorithm {body.get('alg')!r}")
    try:
        content_key = private_key.decrypt(base64.b64decode(body["ek"]), _OAEP)
        iv = base64.b64decode(body["iv"])
        plaintext = AESGCM(content_key).decrypt(iv, base64.b64decode(body["ct"]), None)
    except Exception as exc:
        # Deliberately uninformative: which step failed is a decryption oracle,
        # and the caller can do nothing differently either way.
        raise EnvelopeError("could not open envelope") from exc
    return json.loads(plaintext)


def seal_envelope(payload: dict[str, Any], recipient_cert_pem: str) -> dict[str, Any]:
    """Seals ``payload`` to the public key in ``recipient_cert_pem``."""
    certificate = load_pem_x509_certificate(recipient_cert_pem.encode())
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise EnvelopeError("recipient certificate does not carry an RSA key")

    content_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ciphertext = AESGCM(content_key).encrypt(iv, json.dumps(payload).encode(), None)
    return {
        "v": VERSION,
        "alg": ALG,
        "ek": base64.b64encode(public_key.encrypt(content_key, _OAEP)).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
    }


def load_private_key(key_path: str) -> rsa.RSAPrivateKey:
    """Loads the agent's own RSA key — the one its certificate was issued for."""
    with open(key_path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise EnvelopeError("agent key is not an RSA key")
    return key
