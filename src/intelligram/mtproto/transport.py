"""MTProto transport frame codecs.

The abridged codec mirrors Telegram Web A's `TCPAbridged.ts`: a one-byte `0xef`
connection tag followed by a word-count frame header and four-byte-aligned
payload. The gateway uses this codec before dispatching plaintext or encrypted
MTProto envelopes.
"""

from __future__ import annotations

import asyncio


ABRIDGED_TAG = b"\xef"
WORD_SIZE = 4
MAX_ABRIDGED_PACKET_LENGTH = 0xFFFFFF * WORD_SIZE


class TransportError(ValueError):
    """A transport frame violates MTProto framing constraints."""


def encode_abridged_packet(payload: bytes) -> bytes:
    if not payload or len(payload) % WORD_SIZE or len(payload) > MAX_ABRIDGED_PACKET_LENGTH:
        raise TransportError("Invalid abridged packet length")
    word_count = len(payload) // WORD_SIZE
    if word_count < 127:
        header = bytes([word_count])
    else:
        header = b"\x7f" + word_count.to_bytes(3, "little")
    return header + payload


async def read_abridged_packet(reader: asyncio.StreamReader) -> bytes:
    first = await reader.readexactly(1)
    if first[0] < 127:
        word_count = first[0]
    elif first[0] == 127:
        word_count = int.from_bytes(await reader.readexactly(3), "little")
    else:
        raise TransportError("Invalid abridged packet length marker")
    length = word_count * WORD_SIZE
    if not length or length > MAX_ABRIDGED_PACKET_LENGTH:
        raise TransportError("Invalid abridged packet length")
    return await reader.readexactly(length)


class AbridgedFrameBuffer:
    """Incremental abridged frame decoder for stream and WebSocket adapters."""

    def __init__(self, *, require_tag: bool = False):
        self.buffer = bytearray()
        self.require_tag = require_tag
        self.tag_consumed = not require_tag

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer.extend(data)
        if not self.tag_consumed:
            if not self.buffer:
                return []
            if self.buffer[:1] != ABRIDGED_TAG:
                raise TransportError("Expected abridged transport tag 0xef")
            del self.buffer[:1]
            self.tag_consumed = True
        frames: list[bytes] = []
        while True:
            if not self.buffer:
                return frames
            first = self.buffer[0]
            header_length = 1 if first < 127 else 4
            if len(self.buffer) < header_length:
                return frames
            if first < 127:
                word_count = first
            elif first == 127:
                word_count = int.from_bytes(self.buffer[1:4], "little")
            else:
                raise TransportError("Invalid abridged packet length marker")
            payload_length = word_count * WORD_SIZE
            if not payload_length or payload_length > MAX_ABRIDGED_PACKET_LENGTH:
                raise TransportError("Invalid abridged packet length")
            if len(self.buffer) < header_length + payload_length:
                return frames
            start = header_length
            frames.append(bytes(self.buffer[start:start + payload_length]))
            del self.buffer[:header_length + payload_length]
