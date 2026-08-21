from __future__ import annotations

import hashlib
import struct
import time

import pytest

from intelligram.mtproto.adapter import MTProtoSessionAdapter
from intelligram.mtproto.crypto import MTProtoSecurityError, aes_ige_decrypt, aes_ige_encrypt, auth_key_id, derive_aes_key_iv
from intelligram.mtproto.tl import MSGS_ACK_CONSTRUCTOR, PING_CONSTRUCTOR, PONG_CONSTRUCTOR, RPC_RESULT_CONSTRUCTOR


def _encrypt_client(auth_key: bytes, *, salt: int, session_id: int, msg_id: int, seq_no: int, body: bytes) -> bytes:
    inner = struct.pack("<QQQII", salt, session_id, msg_id, seq_no, len(body)) + body
    padding_length = 12
    while (len(inner) + padding_length) % 16:
        padding_length += 1
    plaintext = inner + b"\x01" * padding_length
    msg_key = hashlib.sha256(auth_key[88:120] + plaintext).digest()[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=True)
    return struct.pack("<Q", auth_key_id(auth_key)) + msg_key + aes_ige_encrypt(key, iv, plaintext)


def _decrypt_server(auth_key: bytes, envelope: bytes) -> tuple[int, int, int, int, bytes]:
    assert struct.unpack_from("<Q", envelope, 0)[0] == auth_key_id(auth_key)
    msg_key = envelope[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=False)
    plaintext = aes_ige_decrypt(key, iv, envelope[24:])
    assert msg_key == hashlib.sha256(auth_key[96:128] + plaintext).digest()[8:24]
    salt, session_id, msg_id, seq_no, body_length = struct.unpack_from("<QQQII", plaintext, 0)
    return salt, session_id, msg_id, seq_no, plaintext[32:32 + body_length]


def test_encrypted_ping_yields_standards_shaped_rpc_result() -> None:
    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    request_message_id = (int(time.time()) << 32) + 4
    ping_id = 987654321
    request_body = struct.pack("<Iq", PING_CONSTRUCTOR, ping_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)

    response = adapter.handle_encrypted(
        _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=1, body=request_body)
    )

    assert response is not None
    response_salt, response_session, response_message_id, response_seq_no, body = _decrypt_server(auth_key, response)
    assert (response_salt, response_session) == (salt, session_id)
    assert response_message_id % 4 == 1
    assert response_seq_no == 1
    constructor, result_request_id, result_constructor, pong_message_id, pong_ping_id = struct.unpack("<IqIqq", body)
    assert constructor == RPC_RESULT_CONSTRUCTOR
    assert result_request_id == request_message_id
    assert result_constructor == PONG_CONSTRUCTOR
    assert pong_message_id == request_message_id
    assert pong_ping_id == ping_id


def test_msgs_ack_has_no_response_and_replayed_message_is_rejected() -> None:
    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    request_message_id = (int(time.time()) << 32) + 4
    ack_body = struct.pack("<IIi", MSGS_ACK_CONSTRUCTOR, 0x1CB5C415, 0)
    encrypted = _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=0, body=ack_body)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)

    assert adapter.handle_encrypted(encrypted) is None
    with pytest.raises(MTProtoSecurityError, match="MESSAGE_REPLAY"):
        adapter.handle_encrypted(encrypted)
