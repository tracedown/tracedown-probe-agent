"""Trust-anchor pinning: bootstrap records the CA, renewal refuses an anchor swap.

These guard the fix for the renewal path overwriting the stored CA with whatever
a response contained — an on-path attacker installing their own trust anchor.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mtls.ca_pins import (
    bundle_preserves_pins,
    ca_fingerprints,
    read_pins,
    write_pins,
)


def _ca(cn: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_fingerprints_count_every_cert_in_a_bundle():
    a, b = _ca("CA A"), _ca("CA B")
    assert len(ca_fingerprints(a)) == 1
    assert len(ca_fingerprints(a + b)) == 2
    # Distinct CAs → distinct fingerprints.
    assert ca_fingerprints(a).isdisjoint(ca_fingerprints(b))


def test_pin_file_roundtrip(tmp_path):
    pins = {"aa", "bb", "cc"}
    path = tmp_path / "ca-pins.txt"
    write_pins(path, pins)
    assert read_pins(path) == pins
    # Missing file → empty set (never crashes).
    assert read_pins(tmp_path / "nope.txt") == set()


def test_continuity_allows_rotation_but_blocks_swap():
    old, new, attacker = _ca("Old"), _ca("New"), _ca("Attacker")
    pinned = ca_fingerprints(old)

    # Same CA — trivially continuous.
    assert bundle_preserves_pins(old, pinned)
    # Make-before-break rotation bundle keeps the old CA present → allowed.
    assert bundle_preserves_pins(old + new, pinned)
    # A wholesale swap to a CA we never pinned → refused.
    assert not bundle_preserves_pins(attacker, pinned)
    assert not bundle_preserves_pins(new, pinned)


def test_no_pins_is_trust_on_first_use():
    # First-ever bootstrap has no pins yet — continuity is vacuously satisfied.
    assert bundle_preserves_pins(_ca("Anything"), set())
