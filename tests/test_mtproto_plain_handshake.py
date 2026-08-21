from __future__ import annotations

import os
import struct

import pytest

from intelligram.mtproto.keys import load_or_create_server_keypair
from intelligram.mtproto.plain_handshake import (
    REQ_PQ_MULTI_CONSTRUCTOR,
    RES_PQ_CONSTRUCTOR,
    PlainHandshakeAdapter,
    PlainHandshakeError,
    decode_plain_packet,
    encode_plain_packet,
)
from intelligram.mtproto.tl import TLReader


def test_req_pq_multi_returns_res_pq_with_self_owned_fingerprint(tmp_path) -> None:
    key_pair = load_or_create_server_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    adapter = PlainHandshakeAdapter(key_pair)
    nonce = os.urandom(16)
    request = encode_plain_packet(4, struct.pack("<I", REQ_PQ_MULTI_CONSTRUCTOR) + nonce)

    response = decode_plain_packet(adapter.handle_packet(request))
    reader = TLReader(response.body)
    assert reader.uint32() == RES_PQ_CONSTRUCTOR
    assert response.body[4:20] == nonce
    assert response.body[20:36] != b"\x00" * 16
    reader.offset = 36
    pq = int.from_bytes(reader.bytes(), "big")
    assert pq == adapter.pq
    assert reader.vector_longs() == [key_pair.fingerprint]
    assert reader.remaining == 0


def test_plain_handshake_rejects_nonzero_auth_key_id(tmp_path) -> None:
    key_pair = load_or_create_server_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    adapter = PlainHandshakeAdapter(key_pair)
    packet = bytearray(encode_plain_packet(4, struct.pack("<I", REQ_PQ_MULTI_CONSTRUCTOR) + os.urandom(16)))
    packet[0] = 1
    with pytest.raises(PlainHandshakeError, match="auth_key_id"):
        adapter.handle_packet(bytes(packet))
