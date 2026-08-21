"""Self-hosted MTProto RSA server-key provisioning and fingerprints."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from intelligram.mtproto.tl import encode_tl_bytes


@dataclass(frozen=True, slots=True)
class ServerKeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    fingerprint: int


def mtproto_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> int:
    """Return the signed lower-64-bit SHA-1 fingerprint used by MTProto.

    MTProto hashes the TL serialization of the *bare* `rsa_public_key` value:
    the serialized modulus and public exponent without a constructor ID.
    """

    numbers = public_key.public_numbers()
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    digest = hashlib.sha1(encode_tl_bytes(modulus) + encode_tl_bytes(exponent)).digest()
    return int.from_bytes(digest[-8:], "little", signed=True)


def load_or_create_server_keypair(private_key_path: Path, public_key_path: Path) -> ServerKeyPair:
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    if private_key_path.exists():
        private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            raise RuntimeError("The configured MTProto private key must be an RSA key of at least 2048 bits")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_private_key(private_key_path, private_key)

    public_key = private_key.public_key()
    public_key_path.write_bytes(
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    try:
        os.chmod(public_key_path, 0o644)
    except OSError:
        pass
    return ServerKeyPair(private_key=private_key, public_key=public_key, fingerprint=mtproto_public_key_fingerprint(public_key))


def _write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    encoded = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
