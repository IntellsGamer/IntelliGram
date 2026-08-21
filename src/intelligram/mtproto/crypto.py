"""MTProto 2.0 encrypted-envelope primitives.

This module follows the public client-server MTProto 2.0 specification and is
kept deliberately independent from HTTP application code. It does not replace
the authorization-key handshake or TL dispatcher; those layers build on this
validated envelope implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
import struct
from typing import Final

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BLOCK_SIZE: Final = 16
MIN_PADDING: Final = 12
MAX_PADDING: Final = 1024
EXTERNAL_HEADER_SIZE: Final = 24
INNER_HEADER_SIZE: Final = 32


class MTProtoSecurityError(ValueError):
    """A packet failed an MTProto integrity or framing check."""


@dataclass(frozen=True, slots=True)
class EncryptedMessage:
    server_salt: int
    session_id: int
    msg_id: int
    seq_no: int
    body: bytes
    padding: bytes


def auth_key_id(auth_key: bytes) -> int:
    _require_auth_key(auth_key)
    return int.from_bytes(hashlib.sha1(auth_key).digest()[-8:], "little", signed=False)


def derive_aes_key_iv(auth_key: bytes, msg_key: bytes, *, from_client: bool) -> tuple[bytes, bytes]:
    """Derive the MTProto 2.0 AES-256-IGE key and 32-byte IV.

    ``from_client=True`` uses x=0 and decrypts client-to-server traffic. A
    server-to-client envelope uses x=8.
    """

    _require_auth_key(auth_key)
    if len(msg_key) != 16:
        raise MTProtoSecurityError("msg_key must contain exactly 16 bytes")
    x = 0 if from_client else 8
    sha256_a = hashlib.sha256(msg_key + auth_key[x:x + 36]).digest()
    sha256_b = hashlib.sha256(auth_key[40 + x:76 + x] + msg_key).digest()
    aes_key = sha256_a[0:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[0:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv


def aes_ige_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) != 32 or len(iv) != 32 or not plaintext or len(plaintext) % BLOCK_SIZE:
        raise MTProtoSecurityError("Invalid AES-IGE encryption parameters")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    previous_cipher = iv[:BLOCK_SIZE]
    previous_plain = iv[BLOCK_SIZE:]
    output = bytearray()
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        encrypted = encryptor.update(_xor(block, previous_cipher))
        cipher_block = _xor(encrypted, previous_plain)
        output.extend(cipher_block)
        previous_cipher = cipher_block
        previous_plain = block
    encryptor.finalize()
    return bytes(output)


def aes_ige_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32 or len(iv) != 32 or not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise MTProtoSecurityError("Invalid AES-IGE decryption parameters")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    previous_cipher = iv[:BLOCK_SIZE]
    previous_plain = iv[BLOCK_SIZE:]
    output = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        cipher_block = ciphertext[offset:offset + BLOCK_SIZE]
        decrypted = decryptor.update(_xor(cipher_block, previous_plain))
        plain_block = _xor(decrypted, previous_cipher)
        output.extend(plain_block)
        previous_cipher = cipher_block
        previous_plain = plain_block
    decryptor.finalize()
    return bytes(output)


def encrypt_server_message(
    *,
    auth_key: bytes,
    server_salt: int,
    session_id: int,
    msg_id: int,
    seq_no: int,
    body: bytes,
    padding: bytes | None = None,
) -> bytes:
    """Build a server-to-client MTProto 2.0 encrypted envelope."""

    _require_auth_key(auth_key)
    if not body or len(body) % 4:
        raise MTProtoSecurityError("TL message body must be non-empty and four-byte aligned")
    inner = struct.pack("<QQQII", _u64(server_salt), _u64(session_id), _u64(msg_id), _u32(seq_no), _u32(len(body))) + body
    if padding is None:
        padding = os.urandom(_padding_length(len(inner)))
    if not (MIN_PADDING <= len(padding) <= MAX_PADDING) or (len(inner) + len(padding)) % BLOCK_SIZE:
        raise MTProtoSecurityError("Invalid MTProto padding")
    plaintext = inner + padding
    msg_key = hashlib.sha256(auth_key[96:128] + plaintext).digest()[8:24]
    aes_key, aes_iv = derive_aes_key_iv(auth_key, msg_key, from_client=False)
    encrypted = aes_ige_encrypt(aes_key, aes_iv, plaintext)
    return struct.pack("<Q", auth_key_id(auth_key)) + msg_key + encrypted


def decrypt_client_message(*, auth_key: bytes, envelope: bytes) -> EncryptedMessage:
    """Decrypt and fully validate one client-to-server MTProto 2.0 envelope."""

    _require_auth_key(auth_key)
    if len(envelope) < EXTERNAL_HEADER_SIZE + BLOCK_SIZE or (len(envelope) - EXTERNAL_HEADER_SIZE) % BLOCK_SIZE:
        raise MTProtoSecurityError("Invalid encrypted envelope length")
    received_key_id = struct.unpack_from("<Q", envelope, 0)[0]
    if received_key_id != auth_key_id(auth_key):
        raise MTProtoSecurityError("AUTH_KEY_UNREGISTERED")
    msg_key = envelope[8:24]
    aes_key, aes_iv = derive_aes_key_iv(auth_key, msg_key, from_client=True)
    plaintext = aes_ige_decrypt(aes_key, aes_iv, envelope[24:])
    expected_msg_key = hashlib.sha256(auth_key[88:120] + plaintext).digest()[8:24]
    if not hmac.compare_digest(msg_key, expected_msg_key):
        raise MTProtoSecurityError("MESSAGE_KEY_INVALID")
    if len(plaintext) < INNER_HEADER_SIZE:
        raise MTProtoSecurityError("Encrypted payload is shorter than the MTProto header")
    server_salt, session_id, msg_id, seq_no, body_length = struct.unpack_from("<QQQII", plaintext, 0)
    remaining = len(plaintext) - INNER_HEADER_SIZE
    padding_length = remaining - body_length
    if body_length < 0 or body_length % 4 or body_length > remaining:
        raise MTProtoSecurityError("MESSAGE_LENGTH_INVALID")
    if padding_length < MIN_PADDING or padding_length > MAX_PADDING:
        raise MTProtoSecurityError("PADDING_LENGTH_INVALID")
    body = plaintext[INNER_HEADER_SIZE:INNER_HEADER_SIZE + body_length]
    padding = plaintext[INNER_HEADER_SIZE + body_length:]
    return EncryptedMessage(server_salt, session_id, msg_id, seq_no, body, padding)


def _padding_length(inner_length: int) -> int:
    required = MIN_PADDING
    while (inner_length + required) % BLOCK_SIZE:
        required += 1
    return required


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _require_auth_key(auth_key: bytes) -> None:
    if len(auth_key) != 256:
        raise MTProtoSecurityError("MTProto auth_key must contain exactly 256 bytes")


def _u64(value: int) -> int:
    return value & ((1 << 64) - 1)


def _u32(value: int) -> int:
    return value & ((1 << 32) - 1)
