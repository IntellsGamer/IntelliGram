"""Minimal Telegram TL codec used by the IntelliGram MTProto adapter.

The codec starts with the MTProto service constructors required to establish a
transport and prove encrypted request/response behavior. Application-layer API
constructors are added as their handlers become compatible.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable


VECTOR_CONSTRUCTOR = 0x1CB5C415
RPC_RESULT_CONSTRUCTOR = 0xF35C6D01
RPC_ERROR_CONSTRUCTOR = 0x2144CA19
PONG_CONSTRUCTOR = 0x347773C5
PING_CONSTRUCTOR = 0x7ABE77EC
MSGS_ACK_CONSTRUCTOR = 0x62D6B459
NEW_SESSION_CREATED_CONSTRUCTOR = 0x9EC20908
BAD_SERVER_SALT_CONSTRUCTOR = 0xEDAB447B


class TLDecodeError(ValueError):
    """A TL payload is malformed or unsupported by the active adapter."""


@dataclass(frozen=True, slots=True)
class TLRequest:
    constructor_id: int
    name: str
    fields: dict[str, int | list[int]]


class TLReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def int32(self) -> int:
        self._require(4)
        value = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        return value

    def uint32(self) -> int:
        self._require(4)
        value = struct.unpack_from("<I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def int64(self) -> int:
        self._require(8)
        value = struct.unpack_from("<q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def raw_bytes(self, length: int) -> bytes:
        self._require(length)
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def bytes(self) -> bytes:
        self._require(1)
        first = self.data[self.offset]
        self.offset += 1
        if first == 254:
            self._require(3)
            length = int.from_bytes(self.data[self.offset:self.offset + 3], "little")
            self.offset += 3
            header_size = 4
        elif first < 254:
            length = first
            header_size = 1
        else:
            raise TLDecodeError("TL bytes length marker is invalid")
        self._require(length)
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        padding = (-((header_size + length) % 4)) % 4
        self._require(padding)
        self.offset += padding
        return value

    def vector_longs(self) -> list[int]:
        if self.uint32() != VECTOR_CONSTRUCTOR:
            raise TLDecodeError("Expected a Vector constructor")
        count = self.int32()
        if count < 0 or count > 8192:
            raise TLDecodeError("Vector length is invalid")
        return [self.int64() for _ in range(count)]

    def _require(self, length: int) -> None:
        if length < 0 or self.remaining < length:
            raise TLDecodeError("Truncated TL payload")


def encode_int32(value: int) -> bytes:
    return struct.pack("<i", value)


def encode_uint32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def encode_int64(value: int) -> bytes:
    return struct.pack("<q", value)


def encode_tl_bytes(value: bytes) -> bytes:
    length = len(value)
    if length < 254:
        encoded = bytes([length]) + value
    elif length < 1 << 24:
        encoded = b"\xfe" + length.to_bytes(3, "little") + value
    else:
        raise ValueError("TL byte string is larger than 16 MiB")
    return encoded + b"\x00" * (-len(encoded) % 4)


def encode_tl_string(value: str) -> bytes:
    return encode_tl_bytes(value.encode("utf-8"))


def encode_vector_longs(values: Iterable[int]) -> bytes:
    sequence = list(values)
    return encode_uint32(VECTOR_CONSTRUCTOR) + encode_int32(len(sequence)) + b"".join(encode_int64(value) for value in sequence)


def parse_request(data: bytes) -> TLRequest:
    reader = TLReader(data)
    constructor_id = reader.uint32()
    if constructor_id == PING_CONSTRUCTOR:
        request = TLRequest(constructor_id, "ping", {"ping_id": reader.int64()})
    elif constructor_id == MSGS_ACK_CONSTRUCTOR:
        request = TLRequest(constructor_id, "msgs_ack", {"msg_ids": reader.vector_longs()})
    else:
        raise TLDecodeError(f"Unsupported TL constructor: 0x{constructor_id:08x}")
    if reader.remaining:
        raise TLDecodeError("Trailing data after TL request")
    return request


def encode_pong(*, message_id: int, ping_id: int) -> bytes:
    return encode_uint32(PONG_CONSTRUCTOR) + encode_int64(message_id) + encode_int64(ping_id)


def encode_rpc_error(*, code: int, message: str) -> bytes:
    return encode_uint32(RPC_ERROR_CONSTRUCTOR) + encode_int32(code) + encode_tl_string(message)


def encode_rpc_result(*, request_message_id: int, result: bytes) -> bytes:
    return encode_uint32(RPC_RESULT_CONSTRUCTOR) + encode_int64(request_message_id) + result


def encode_new_session_created(*, first_message_id: int, unique_id: int, server_salt: int) -> bytes:
    return (
        encode_uint32(NEW_SESSION_CREATED_CONSTRUCTOR)
        + encode_int64(first_message_id)
        + encode_int64(unique_id)
        + encode_int64(server_salt)
    )


def encode_bad_server_salt(*, bad_message_id: int, bad_message_seq_no: int, new_server_salt: int) -> bytes:
    return (
        encode_uint32(BAD_SERVER_SALT_CONSTRUCTOR)
        + encode_int64(bad_message_id)
        + encode_int32(bad_message_seq_no)
        + encode_int32(48)
        + encode_int64(new_server_salt)
    )
