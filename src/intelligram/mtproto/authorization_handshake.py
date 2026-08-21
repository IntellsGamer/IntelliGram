"""MTProto 2.0 authorization-key handshake state machine.

This module ports the public protocol stages used by Telegram Web A:
`req_pq_multi`, `req_DH_params`, and `set_client_DH_params`. It deliberately
uses self-owned RSA keys and validates all nonces, factors, DH public values,
and hashes before recording a resulting authorization key.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
import struct
import time

from intelligram.mtproto.crypto import aes_ige_decrypt, aes_ige_encrypt, auth_key_id
from intelligram.mtproto.keys import ServerKeyPair
from intelligram.mtproto.plain_handshake import (
    REQ_PQ_CONSTRUCTOR,
    REQ_PQ_MULTI_CONSTRUCTOR,
    RES_PQ_CONSTRUCTOR,
    PlainHandshakeError,
    PlainPacket,
    decode_plain_packet,
    encode_plain_packet,
)
from intelligram.mtproto.tl import MSGS_ACK_CONSTRUCTOR, TLDecodeError, TLReader, encode_int32, encode_int64, encode_tl_bytes, encode_uint32, encode_vector_longs


REQ_DH_PARAMS_CONSTRUCTOR = 0xD712E4BE
SERVER_DH_PARAMS_OK_CONSTRUCTOR = 0xD0E8075C
SET_CLIENT_DH_PARAMS_CONSTRUCTOR = 0xF5045F1F
DH_GEN_OK_CONSTRUCTOR = 0x3BCBF734
PQ_INNER_CONSTRUCTORS = {0x83C95AEC, 0xA9F55F95, 0x3C6A84D4, 0x56FDDf88}
SERVER_DH_INNER_DATA_CONSTRUCTOR = 0xB5890DBA
CLIENT_DH_INNER_DATA_CONSTRUCTOR = 0x6643B654

# The Telegram-documented safe 2048-bit DH prime used by Telegram Web A.
DH_PRIME = int(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f"
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37"
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64"
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4fa9060bee7cf9a4a4"
    "a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754"
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae"
    "4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851"
    "f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b",
    16,
)
DH_PRIME_BYTES = DH_PRIME.to_bytes(256, "big")
DH_GENERATOR = 3


@dataclass(slots=True)
class AuthorizationHandshakeState:
    nonce: bytes
    server_nonce: bytes
    new_nonce: bytes | None = None
    exponent_a: int | None = None


@dataclass(frozen=True, slots=True)
class CompletedAuthKey:
    key_id: int
    auth_key: bytes
    server_salt: int


class AuthorizationHandshake:
    def __init__(self, server_key_pair: ServerKeyPair):
        self.server_key_pair = server_key_pair
        self.p, self.q = _generate_factor_pair()
        self.pq = self.p * self.q
        self.states: dict[bytes, AuthorizationHandshakeState] = {}
        self.completed_keys: dict[int, CompletedAuthKey] = {}
        self.last_server_message_id = 0

    def handle_packet(self, packet: bytes) -> bytes | None:
        incoming = decode_plain_packet(packet)
        reader = TLReader(incoming.body)
        constructor = reader.uint32()
        try:
            if constructor in {REQ_PQ_CONSTRUCTOR, REQ_PQ_MULTI_CONSTRUCTOR}:
                return self._handle_req_pq(incoming, reader)
            if constructor == REQ_DH_PARAMS_CONSTRUCTOR:
                return self._handle_req_dh_params(incoming, reader)
            if constructor == SET_CLIENT_DH_PARAMS_CONSTRUCTOR:
                return self._handle_set_client_dh_params(incoming, reader)
            if constructor == MSGS_ACK_CONSTRUCTOR:
                reader.vector_longs()
                if reader.remaining:
                    raise PlainHandshakeError("Trailing data in msgs_ack")
                return None
        except TLDecodeError as exc:
            raise PlainHandshakeError(str(exc)) from exc
        raise PlainHandshakeError(f"Unsupported plaintext handshake constructor: 0x{constructor:08x}")

    def _handle_req_pq(self, incoming: PlainPacket, reader: TLReader) -> bytes:
        nonce = reader.raw_bytes(16)
        if reader.remaining:
            raise PlainHandshakeError("Trailing data in req_pq")
        server_nonce = secrets.token_bytes(16)
        self.states[nonce] = AuthorizationHandshakeState(nonce=nonce, server_nonce=server_nonce)
        body = (
            encode_uint32(RES_PQ_CONSTRUCTOR)
            + nonce
            + server_nonce
            + encode_tl_bytes(self.pq.to_bytes(8, "big"))
            + encode_vector_longs([self.server_key_pair.fingerprint])
        )
        return encode_plain_packet(self._next_server_message_id(), body)

    def _handle_req_dh_params(self, incoming: PlainPacket, reader: TLReader) -> bytes:
        nonce = reader.raw_bytes(16)
        server_nonce = reader.raw_bytes(16)
        p = reader.bytes()
        q = reader.bytes()
        fingerprint = reader.int64()
        encrypted_data = reader.bytes()
        if reader.remaining:
            raise PlainHandshakeError("Trailing data in req_DH_params")
        state = self._state(nonce, server_nonce)
        if p != self.p.to_bytes(4, "big") or q != self.q.to_bytes(4, "big"):
            raise PlainHandshakeError("PQ_FACTORS_INVALID")
        if fingerprint != self.server_key_pair.fingerprint:
            raise PlainHandshakeError("PUBLIC_KEY_FINGERPRINT_NOT_FOUND")
        inner = self._decrypt_rsa_pad(encrypted_data)
        parsed = self._parse_pq_inner(inner, nonce, server_nonce)
        state.new_nonce = parsed.new_nonce
        state.exponent_a = _dh_private_exponent()
        g_a = pow(DH_GENERATOR, state.exponent_a, DH_PRIME).to_bytes(256, "big")
        server_inner = (
            encode_uint32(SERVER_DH_INNER_DATA_CONSTRUCTOR)
            + nonce
            + server_nonce
            + encode_int32(DH_GENERATOR)
            + encode_tl_bytes(DH_PRIME_BYTES)
            + encode_tl_bytes(g_a)
            + encode_int32(int(time.time()))
        )
        key, iv = _nonce_aes_key_iv(server_nonce, parsed.new_nonce)
        padded = hashlib.sha1(server_inner).digest() + server_inner
        padded += secrets.token_bytes((-len(padded)) % 16)
        response = (
            encode_uint32(SERVER_DH_PARAMS_OK_CONSTRUCTOR)
            + nonce
            + server_nonce
            + encode_tl_bytes(aes_ige_encrypt(key, iv, padded))
        )
        return encode_plain_packet(self._next_server_message_id(), response)

    def _handle_set_client_dh_params(self, incoming: PlainPacket, reader: TLReader) -> bytes:
        nonce = reader.raw_bytes(16)
        server_nonce = reader.raw_bytes(16)
        encrypted_data = reader.bytes()
        if reader.remaining:
            raise PlainHandshakeError("Trailing data in set_client_DH_params")
        state = self._state(nonce, server_nonce)
        if state.new_nonce is None or state.exponent_a is None:
            raise PlainHandshakeError("HANDSHAKE_STATE_INVALID")
        key, iv = _nonce_aes_key_iv(server_nonce, state.new_nonce)
        decrypted = aes_ige_decrypt(key, iv, encrypted_data)
        client_inner = self._parse_client_dh_inner(decrypted, nonce, server_nonce)
        g_b = int.from_bytes(client_inner.g_b, "big")
        _validate_dh_public_value(g_b)
        auth_key_int = pow(g_b, state.exponent_a, DH_PRIME)
        auth_key = auth_key_int.to_bytes(256, "big")
        key_id = auth_key_id(auth_key)
        server_salt = int.from_bytes(bytes(a ^ b for a, b in zip(state.new_nonce[:8], server_nonce[:8], strict=True)), "little", signed=True)
        completed = CompletedAuthKey(key_id=key_id, auth_key=auth_key, server_salt=server_salt)
        if key_id in self.completed_keys:
            # Collisions are exceptionally unlikely; forcing a retry avoids
            # associating an existing key with a fresh client handshake.
            raise PlainHandshakeError("AUTH_KEY_DUPLICATE")
        self.completed_keys[key_id] = completed
        response = (
            encode_uint32(DH_GEN_OK_CONSTRUCTOR)
            + nonce
            + server_nonce
            + _new_nonce_hash(state.new_nonce, auth_key, 1)
        )
        return encode_plain_packet(self._next_server_message_id(), response)

    def _decrypt_rsa_pad(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) != 256:
            raise PlainHandshakeError("RSA_ENCRYPTED_DATA_INVALID")
        numbers = self.server_key_pair.private_key.private_numbers()
        encoded = pow(int.from_bytes(encrypted_data, "big"), numbers.d, numbers.public_numbers.n).to_bytes(256, "big")
        temp_key_xor = encoded[:32]
        aes_encrypted = encoded[32:]
        temp_key = bytes(a ^ b for a, b in zip(temp_key_xor, hashlib.sha256(aes_encrypted).digest(), strict=True))
        decrypted = aes_ige_decrypt(temp_key, b"\x00" * 32, aes_encrypted)
        reversed_data, received_hash = decrypted[:192], decrypted[192:]
        data_with_padding = reversed_data[::-1]
        expected_hash = hashlib.sha256(temp_key + data_with_padding).digest()
        if not secrets.compare_digest(received_hash, expected_hash):
            raise PlainHandshakeError("RSA_PAD_HASH_INVALID")
        return data_with_padding

    def _parse_pq_inner(self, data: bytes, nonce: bytes, server_nonce: bytes) -> "PQInnerData":
        reader = TLReader(data)
        constructor = reader.uint32()
        if constructor not in PQ_INNER_CONSTRUCTORS:
            raise PlainHandshakeError("PQ_INNER_DATA_INVALID")
        pq = reader.bytes()
        p = reader.bytes()
        q = reader.bytes()
        inner_nonce = reader.raw_bytes(16)
        inner_server_nonce = reader.raw_bytes(16)
        new_nonce = reader.raw_bytes(32)
        if constructor in {0xA9F55F95, 0x56FDDf88}:
            reader.int32()  # data-center id
        if constructor in {0x3C6A84D4, 0x56FDDf88}:
            reader.int32()  # temporary-key expiry
        if pq != self.pq.to_bytes(8, "big") or p != self.p.to_bytes(4, "big") or q != self.q.to_bytes(4, "big"):
            raise PlainHandshakeError("PQ_INNER_FACTORS_INVALID")
        if inner_nonce != nonce or inner_server_nonce != server_nonce:
            raise PlainHandshakeError("PQ_INNER_NONCE_INVALID")
        return PQInnerData(new_nonce=new_nonce)

    def _parse_client_dh_inner(self, data: bytes, nonce: bytes, server_nonce: bytes) -> "ClientDHInnerData":
        if len(data) < 20:
            raise PlainHandshakeError("CLIENT_DH_DATA_TRUNCATED")
        reader = TLReader(data[20:])
        constructor = reader.uint32()
        if constructor != CLIENT_DH_INNER_DATA_CONSTRUCTOR:
            raise PlainHandshakeError("CLIENT_DH_INNER_INVALID")
        inner_nonce = reader.raw_bytes(16)
        inner_server_nonce = reader.raw_bytes(16)
        reader.int64()  # retry_id
        g_b = reader.bytes()
        consumed = reader.offset
        expected_hash = hashlib.sha1(data[20:20 + consumed]).digest()
        if not secrets.compare_digest(data[:20], expected_hash):
            raise PlainHandshakeError("CLIENT_DH_HASH_INVALID")
        if inner_nonce != nonce or inner_server_nonce != server_nonce:
            raise PlainHandshakeError("CLIENT_DH_NONCE_INVALID")
        return ClientDHInnerData(g_b=g_b)

    def _state(self, nonce: bytes, server_nonce: bytes) -> AuthorizationHandshakeState:
        state = self.states.get(nonce)
        if state is None or state.server_nonce != server_nonce:
            raise PlainHandshakeError("HANDSHAKE_NONCE_INVALID")
        return state

    def _next_server_message_id(self) -> int:
        candidate = ((int(time.time()) << 32) | secrets.randbits(30))
        candidate = (candidate & ~0b11) | 0b01
        if candidate <= self.last_server_message_id:
            candidate = self.last_server_message_id + 4
        self.last_server_message_id = candidate
        return candidate


@dataclass(frozen=True, slots=True)
class PQInnerData:
    new_nonce: bytes


@dataclass(frozen=True, slots=True)
class ClientDHInnerData:
    g_b: bytes


def _nonce_aes_key_iv(server_nonce: bytes, new_nonce: bytes) -> tuple[bytes, bytes]:
    if len(server_nonce) != 16 or len(new_nonce) != 32:
        raise PlainHandshakeError("NONCE_LENGTH_INVALID")
    sha1_a = hashlib.sha1(new_nonce + server_nonce).digest()
    sha1_b = hashlib.sha1(server_nonce + new_nonce).digest()
    sha1_c = hashlib.sha1(new_nonce + new_nonce).digest()
    return sha1_a + sha1_b[:12], sha1_b[12:20] + sha1_c + new_nonce[:4]


def _new_nonce_hash(new_nonce: bytes, auth_key: bytes, number: int) -> bytes:
    return hashlib.sha1(new_nonce + bytes([number]) + hashlib.sha1(auth_key).digest()[:8]).digest()[4:20]


def _dh_private_exponent() -> int:
    # Reject values outside the legal public DH-value range by keeping the
    # server exponent itself in the high 1984-bit interval.
    return (1 << 1984) + secrets.randbits(64)


def _validate_dh_public_value(value: int) -> None:
    minimum = 1 << (2048 - 64)
    if not (minimum <= value <= DH_PRIME - minimum):
        raise PlainHandshakeError("DH_PUBLIC_VALUE_INVALID")


def _generate_factor_pair() -> tuple[int, int]:
    # Reuse the bounded public pq convention used by Telegram clients. These
    # factors are protocol inputs, not secrecy-bearing key material.
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
