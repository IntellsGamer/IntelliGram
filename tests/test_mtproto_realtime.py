from __future__ import annotations

import asyncio
import hashlib
import struct

from intelligram.api.app import MTProtoConnectionHub
from intelligram.mtproto.adapter import MTProtoSessionAdapter
from intelligram.mtproto.crypto import aes_ige_decrypt, auth_key_id, derive_aes_key_iv
from intelligram.mtproto.tl import TLReader, UPDATES_TOO_LONG_CONSTRUCTOR
from intelligram.mtproto.transport import AbridgedFrameBuffer
from intelligram.services.updates import UpdateEnvelope


class FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send_bytes(self, data: bytes) -> None:
        self.sent.append(data)


def test_mtproto_connection_hub_pushes_encrypted_updates_too_long() -> None:
    auth_key = bytes(range(256))
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=927, user_id=73, session_id=88)
    socket = FakeWebSocket()
    envelope = UpdateEnvelope(
        user_id=73,
        pts=1,
        pts_count=1,
        seq=1,
        date=1,
        kind="updateNewMessage",
        payload={},
    )

    async def exercise() -> None:
        hub = MTProtoConnectionHub.create()
        await hub.add(73, socket, adapter)  # type: ignore[arg-type]
        await hub.publish([envelope])

    asyncio.run(exercise())
    assert len(socket.sent) == 1

    frame_buffer = AbridgedFrameBuffer(require_tag=False)
    packets = frame_buffer.feed(socket.sent[0])
    assert len(packets) == 1
    packet = packets[0]
    assert struct.unpack_from("<Q", packet, 0)[0] == auth_key_id(auth_key)
    msg_key = packet[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=False)
    plaintext = aes_ige_decrypt(key, iv, packet[24:])
    assert msg_key == hashlib.sha256(auth_key[96:128] + plaintext).digest()[8:24]
    _, _, _, _, body_length = struct.unpack_from("<QQQII", plaintext, 0)
    body = plaintext[32:32 + body_length]
    reader = TLReader(body)
    assert reader.uint32() == UPDATES_TOO_LONG_CONSTRUCTOR


def test_mtproto_connection_hub_excludes_the_origin_socket() -> None:
    auth_key = bytes(range(256))
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=928, user_id=74, session_id=89)
    socket = FakeWebSocket()
    envelope = UpdateEnvelope(
        user_id=74,
        pts=1,
        pts_count=1,
        seq=1,
        date=1,
        kind="updateNewMessage",
        payload={},
    )

    async def exercise() -> None:
        hub = MTProtoConnectionHub.create()
        await hub.add(74, socket, adapter)  # type: ignore[arg-type]
        await hub.publish([envelope], exclude=socket)  # type: ignore[arg-type]

    asyncio.run(exercise())
    assert socket.sent == []
