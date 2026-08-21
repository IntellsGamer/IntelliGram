from __future__ import annotations

import hashlib
import os
import struct

import pytest

from intelligram.mtproto.crypto import (
    MTProtoSecurityError,
    aes_ige_decrypt,
    aes_ige_encrypt,
    auth_key_id,
    decrypt_client_message,
    derive_aes_key_iv,
)


def _encrypt_client_message(auth_key: bytes, server_salt: int, session_id: int, msg_id: int, seq_no: int, body: bytes) -> bytes:
    inner = struct.pack("<QQQII", server_salt, session_id, msg_id, seq_no, len(body)) + body
    padding_length = 12
    while (len(inner) + padding_length) % 16:
        padding_length += 1
    padding = bytes(range(padding_length))
    plaintext = inner + padding
    msg_key = hashlib.sha256(auth_key[88:120] + plaintext).digest()[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=True)
    return struct.pack("<Q", auth_key_id(auth_key)) + msg_key + aes_ige_encrypt(key, iv, plaintext)


def test_aes_ige_round_trip() -> None:
    key = os.urandom(32)
    iv = os.urandom(32)
    plaintext = os.urandom(64)
    assert aes_ige_decrypt(key, iv, aes_ige_encrypt(key, iv, plaintext)) == plaintext


def test_decrypt_client_message_round_trip() -> None:
    auth_key = bytes(range(256))
    body = struct.pack("<I", 0x7ABE77EC) + struct.pack("<Q", 42)  # ping constructor and payload
    envelope = _encrypt_client_message(auth_key, 10, 20, (1_700_000_000 << 32) + 8, 1, body)
    message = decrypt_client_message(auth_key=auth_key, envelope=envelope)
    assert message.server_salt == 10
    assert message.session_id == 20
    assert message.seq_no == 1
    assert message.body == body


def test_decrypt_client_message_rejects_tampered_integrity() -> None:
    auth_key = bytes(range(256))
    body = struct.pack("<I", 0x7ABE77EC) + struct.pack("<Q", 42)
    envelope = bytearray(_encrypt_client_message(auth_key, 10, 20, (1_700_000_000 << 32) + 8, 1, body))
    envelope[-1] ^= 1
    with pytest.raises(MTProtoSecurityError):
        decrypt_client_message(auth_key=auth_key, envelope=bytes(envelope))
