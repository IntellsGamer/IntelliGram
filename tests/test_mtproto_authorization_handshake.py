from __future__ import annotations

import hashlib
import os
import secrets
import struct

from intelligram.mtproto.authorization_handshake import (
    CLIENT_DH_INNER_DATA_CONSTRUCTOR,
    DH_GEN_OK_CONSTRUCTOR,
    DH_GENERATOR,
    DH_PRIME,
    REQ_DH_PARAMS_CONSTRUCTOR,
    SERVER_DH_PARAMS_OK_CONSTRUCTOR,
    SERVER_DH_INNER_DATA_CONSTRUCTOR,
    SET_CLIENT_DH_PARAMS_CONSTRUCTOR,
    AuthorizationHandshake,
    _nonce_aes_key_iv,
)
from intelligram.mtproto.crypto import aes_ige_decrypt, aes_ige_encrypt, auth_key_id
from intelligram.mtproto.keys import load_or_create_server_keypair
from intelligram.mtproto.plain_handshake import REQ_PQ_MULTI_CONSTRUCTOR, RES_PQ_CONSTRUCTOR, decode_plain_packet, encode_plain_packet
from intelligram.mtproto.tl import TLReader, encode_int32, encode_int64, encode_tl_bytes, encode_uint32


PQ_INNER_DATA_DC_CONSTRUCTOR = 0xA9F55F95


def _request(engine: AuthorizationHandshake, message_id: int, body: bytes) -> bytes:
    return decode_plain_packet(engine.handle_packet(encode_plain_packet(message_id, body))).body


def _rsa_pad_encrypt(public_key, data: bytes) -> bytes:
    data_with_padding = data + os.urandom(192 - len(data))
    numbers = public_key.public_numbers()
    while True:
        temp_key = os.urandom(32)
        aes_encrypted = aes_ige_encrypt(temp_key, b"\x00" * 32, data_with_padding[::-1] + hashlib.sha256(temp_key + data_with_padding).digest())
        encoded = bytes(a ^ b for a, b in zip(temp_key, hashlib.sha256(aes_encrypted).digest(), strict=True)) + aes_encrypted
        encoded_int = int.from_bytes(encoded, "big")
        if encoded_int < numbers.n:
            return pow(encoded_int, numbers.e, numbers.n).to_bytes(256, "big")


def test_complete_public_mtproto_authorization_key_handshake(tmp_path) -> None:
    pair = load_or_create_server_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    engine = AuthorizationHandshake(pair)
    nonce = os.urandom(16)

    res_pq = _request(engine, 4, encode_uint32(REQ_PQ_MULTI_CONSTRUCTOR) + nonce)
    reader = TLReader(res_pq)
    assert reader.uint32() == RES_PQ_CONSTRUCTOR
    assert reader.raw_bytes(16) == nonce
    server_nonce = reader.raw_bytes(16)
    pq = reader.bytes()
    fingerprints = reader.vector_longs()
    assert fingerprints == [pair.fingerprint]

    p, q = engine.p.to_bytes(4, "big"), engine.q.to_bytes(4, "big")
    new_nonce = os.urandom(32)
    pq_inner = (
        encode_uint32(PQ_INNER_DATA_DC_CONSTRUCTOR)
        + encode_tl_bytes(pq)
        + encode_tl_bytes(p)
        + encode_tl_bytes(q)
        + nonce
        + server_nonce
        + new_nonce
        + encode_int32(1)
    )
    encrypted_pq_inner = _rsa_pad_encrypt(pair.public_key, pq_inner)
    server_dh = _request(
        engine,
        8,
        encode_uint32(REQ_DH_PARAMS_CONSTRUCTOR)
        + nonce
        + server_nonce
        + encode_tl_bytes(p)
        + encode_tl_bytes(q)
        + encode_int64(pair.fingerprint)
        + encode_tl_bytes(encrypted_pq_inner),
    )

    reader = TLReader(server_dh)
    assert reader.uint32() == SERVER_DH_PARAMS_OK_CONSTRUCTOR
    assert reader.raw_bytes(16) == nonce
    assert reader.raw_bytes(16) == server_nonce
    encrypted_answer = reader.bytes()
    key, iv = _nonce_aes_key_iv(server_nonce, new_nonce)
    answer = aes_ige_decrypt(key, iv, encrypted_answer)
    answer_hash, answer_body = answer[:20], answer[20:]
    answer_reader = TLReader(answer_body)
    assert answer_reader.uint32() == SERVER_DH_INNER_DATA_CONSTRUCTOR
    assert answer_reader.raw_bytes(16) == nonce
    assert answer_reader.raw_bytes(16) == server_nonce
    assert answer_reader.int32() == DH_GENERATOR
    dh_prime = int.from_bytes(answer_reader.bytes(), "big")
    g_a = int.from_bytes(answer_reader.bytes(), "big")
    answer_reader.int32()
    server_inner_length = answer_reader.offset
    assert answer_hash == hashlib.sha1(answer_body[:server_inner_length]).digest()
    assert dh_prime == DH_PRIME

    exponent_b = (1 << 1984) + secrets.randbits(64)
    g_b = pow(DH_GENERATOR, exponent_b, dh_prime).to_bytes(256, "big")
    client_inner = (
        encode_uint32(CLIENT_DH_INNER_DATA_CONSTRUCTOR)
        + nonce
        + server_nonce
        + encode_int64(0)
        + encode_tl_bytes(g_b)
    )
    encrypted_client_inner = aes_ige_encrypt(key, iv, hashlib.sha1(client_inner).digest() + client_inner + b"\x00" * 12)
    dh_gen = _request(
        engine,
        12,
        encode_uint32(SET_CLIENT_DH_PARAMS_CONSTRUCTOR)
        + nonce
        + server_nonce
        + encode_tl_bytes(encrypted_client_inner),
    )
    reader = TLReader(dh_gen)
    assert reader.uint32() == DH_GEN_OK_CONSTRUCTOR
    assert reader.raw_bytes(16) == nonce
    assert reader.raw_bytes(16) == server_nonce
    new_nonce_hash1 = reader.raw_bytes(16)
    auth_key = pow(g_a, exponent_b, dh_prime).to_bytes(256, "big")
    assert new_nonce_hash1 == hashlib.sha1(new_nonce + b"\x01" + hashlib.sha1(auth_key).digest()[:8]).digest()[4:20]
    assert auth_key_id(auth_key) in engine.completed_keys
