from __future__ import annotations

import asyncio
import os
import struct

from intelligram.mtproto.gateway import MTProtoGateway
from intelligram.mtproto.keys import load_or_create_server_keypair
from intelligram.mtproto.plain_handshake import REQ_PQ_MULTI_CONSTRUCTOR, RES_PQ_CONSTRUCTOR, decode_plain_packet, encode_plain_packet
from intelligram.mtproto.tl import TLReader
from intelligram.mtproto.transport import ABRIDGED_TAG, encode_abridged_packet, read_abridged_packet


def test_abridged_gateway_serves_req_pq_multi(tmp_path) -> None:
    async def scenario() -> None:
        key_pair = load_or_create_server_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
        gateway = MTProtoGateway(key_pair)
        await gateway.start("127.0.0.1", 0)
        host, port = gateway.sockets[0]
        reader, writer = await asyncio.open_connection(host, port)
        try:
            nonce = os.urandom(16)
            packet = encode_plain_packet(4, struct.pack("<I", REQ_PQ_MULTI_CONSTRUCTOR) + nonce)
            writer.write(ABRIDGED_TAG + encode_abridged_packet(packet))
            await writer.drain()
            response = decode_plain_packet(await read_abridged_packet(reader))
            tl_reader = TLReader(response.body)
            assert tl_reader.uint32() == RES_PQ_CONSTRUCTOR
            assert response.body[4:20] == nonce
        finally:
            writer.close()
            await writer.wait_closed()
            await gateway.close()

    asyncio.run(scenario())
