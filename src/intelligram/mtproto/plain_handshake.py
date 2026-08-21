"""Initial unencrypted MTProto authorization-key handshake adapter.

This module implements the first publicly documented handshake exchange:
`req_pq`/`req_pq_multi` → `resPQ`. The subsequent RSA_PAD, DH, and auth-key
persistence stages extend this same state machine.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
import struct
import time

from intelligram.mtproto.keys import ServerKeyPair
from intelligram.mtproto.tl import TLDecodeError, TLReader, encode_int32, encode_int64, encode_tl_bytes, encode_uint32, encode_vector_longs


REQ_PQ_CONSTRUCTOR = 0x60469778
REQ_PQ_MULTI_CONSTRUCTOR = 0xBE7E8EF1
RES_PQ_CONSTRUCTOR = 0x05162463


class PlainHandshakeError(ValueError):
    """The peer sent an invalid plaintext MTProto handshake packet."""


@dataclass(frozen=True, slots=True)
class PlainPacket:
    message_id: int
    body: bytes


@dataclass(frozen=True, slots=True)
class HandshakeState:
    client_nonce: bytes
    server_nonce: bytes


class PlainHandshakeAdapter:
    def __init__(self, server_key_pair: ServerKeyPair):
        self.server_key_pair = server_key_pair
        self.p, self.q = _generate_factor_pair()
        self.pq = self.p * self.q
        self.states: dict[bytes, HandshakeState] = {}
        self.last_server_message_id = 0

    def handle_packet(self, packet: bytes) -> bytes:
        incoming = decode_plain_packet(packet)
        reader = TLReader(incoming.body)
        constructor = reader.uint32()
        if constructor not in {REQ_PQ_CONSTRUCTOR, REQ_PQ_MULTI_CONSTRUCTOR}:
            raise PlainHandshakeError(f"Unsupported plaintext handshake constructor: 0x{constructor:08x}")
        if reader.remaining != 16:
            raise PlainHandshakeError("req_pq nonce must be exactly 16 bytes")
        nonce = incoming.body[4:20]
        server_nonce = secrets.token_bytes(16)
        self.states[nonce] = HandshakeState(client_nonce=nonce, server_nonce=server_nonce)
        body = (
            encode_uint32(RES_PQ_CONSTRUCTOR)
            + nonce
            + server_nonce
            + encode_tl_bytes(self.pq.to_bytes(8, "big"))
            + encode_vector_longs([self.server_key_pair.fingerprint])
        )
        return encode_plain_packet(self._next_server_message_id(), body)

    def _next_server_message_id(self) -> int:
        candidate = (int(time.time()) << 32) | secrets.randbits(30)
        candidate = (candidate & ~0b11) | 0b01
        if candidate <= self.last_server_message_id:
            candidate = (self.last_server_message_id + 4) | 0b01
        self.last_server_message_id = candidate
        return candidate


def encode_plain_packet(message_id: int, body: bytes) -> bytes:
    if not body or len(body) % 4:
        raise ValueError("Plain MTProto body must be non-empty and four-byte aligned")
    return struct.pack("<QqI", 0, message_id, len(body)) + body


def decode_plain_packet(packet: bytes) -> PlainPacket:
    if len(packet) < 20:
        raise PlainHandshakeError("Plain MTProto packet is shorter than its header")
    auth_key_id, message_id, body_length = struct.unpack_from("<QqI", packet, 0)
    if auth_key_id != 0:
        raise PlainHandshakeError("Plain handshake packet must have auth_key_id=0")
    if body_length < 4 or body_length % 4 or len(packet) != 20 + body_length:
        raise PlainHandshakeError("Plain MTProto packet length is invalid")
    return PlainPacket(message_id=message_id, body=packet[20:])


def _generate_factor_pair() -> tuple[int, int]:
    # MTProto clients factor a 63-bit pq during the public handshake. Keeping
    # both factors at 31 bits preserves that bounded protocol requirement.
    while True:
        p = _random_prime(31)
        q = _random_prime(31)
        if p != q and p * q <= 0x7FFF_FFFF_FFFF_FFFF:
            return (min(p, q), max(p, q))


def _random_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _is_probable_prime(value: int) -> bool:
    if value < 2:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % prime == 0:
            return value == prime
    d, s = value - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in (2, 3, 5, 7, 11, 13, 17):
        if base >= value:
            continue
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True
