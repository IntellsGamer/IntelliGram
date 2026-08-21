from __future__ import annotations

import os
import struct

from fastapi.testclient import TestClient

from intelligram.api.app import create_app
from intelligram.config import Settings
from intelligram.mtproto.plain_handshake import REQ_PQ_MULTI_CONSTRUCTOR, RES_PQ_CONSTRUCTOR, decode_plain_packet, encode_plain_packet
from intelligram.mtproto.tl import TLReader
from intelligram.mtproto.transport import AbridgedFrameBuffer, encode_abridged_packet


def test_apiws_accepts_binary_abridged_req_pq_multi(tmp_path) -> None:
    settings = Settings(
        database_path=tmp_path / "test.sqlite3",
        host="127.0.0.1",
        port=8080,
        public_base_url="http://testserver",
        token_secret=b"test-secret" * 8,
        development_mode=True,
        development_login_code=None,
        mtproto_dc_id=1,
        mtproto_port=10443,
        mtproto_rsa_private_key_path=tmp_path / "mtproto_private.pem",
        mtproto_rsa_public_key_path=tmp_path / "mtproto_public.pem",
    )
    client = TestClient(create_app(settings))
    nonce = os.urandom(16)
    packet = encode_plain_packet(4, struct.pack("<I", REQ_PQ_MULTI_CONSTRUCTOR) + nonce)

    with client.websocket_connect("/apiws", subprotocols=["binary"]) as websocket:
        websocket.send_bytes(b"\xef" + encode_abridged_packet(packet))
        response_data = websocket.receive_bytes()

    frame_buffer = AbridgedFrameBuffer()
    frames = frame_buffer.feed(response_data)
    assert len(frames) == 1
    response = decode_plain_packet(frames[0])
    reader = TLReader(response.body)
    assert reader.uint32() == RES_PQ_CONSTRUCTOR
    assert reader.raw_bytes(16) == nonce
