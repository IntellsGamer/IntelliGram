"""Stateful encrypted MTProto service-message adapter.

This is the protocol adapter beneath the future TCP/WSS gateway. It currently
implements service-level ping and acknowledgement semantics and returns
standards-shaped RPC envelopes. Application TL methods are registered here as
the Python Teamgram port grows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import time

from intelligram.mtproto.crypto import EncryptedMessage, MTProtoSecurityError, decrypt_client_message, encrypt_server_message
from intelligram.mtproto.tl import (
    TLDecodeError,
    encode_pong,
    encode_rpc_error,
    encode_rpc_result,
    parse_request,
)


MAX_PAST_SECONDS = 300
MAX_FUTURE_SECONDS = 30


@dataclass(slots=True)
class MTProtoSessionAdapter:
    auth_key: bytes
    server_salt: int
    session_id: int | None = None
    sequence: int = 0
    last_server_message_id: int = 0
    recent_client_message_ids: set[int] = field(default_factory=set)

    def handle_encrypted(self, envelope: bytes) -> bytes | None:
        message = decrypt_client_message(auth_key=self.auth_key, envelope=envelope)
        self._validate_client_message(message)
        self.session_id = message.session_id if self.session_id is None else self.session_id
        if message.server_salt != self.server_salt:
            # The exact bad_server_salt response is added when the gateway has
            # its service-message wrapper. Refusing stale salts prevents
            # processing a potentially replayed request meanwhile.
            raise MTProtoSecurityError("BAD_SERVER_SALT")
        try:
            request = parse_request(message.body)
        except TLDecodeError as exc:
            return self._encrypt_rpc_error(message, "CONSTRUCTOR_INVALID")

        if request.name == "msgs_ack":
            return None
        if request.name == "ping":
            result = encode_pong(message_id=message.msg_id, ping_id=int(request.fields["ping_id"]))
            return self._encrypt_result(message, result)
        return self._encrypt_rpc_error(message, "METHOD_INVALID")

    def _encrypt_result(self, request: EncryptedMessage, result: bytes) -> bytes:
        response_body = encode_rpc_result(request_message_id=request.msg_id, result=result)
        return self._encrypt_response(response_body)

    def _encrypt_rpc_error(self, request: EncryptedMessage, message: str) -> bytes:
        return self._encrypt_result(request, encode_rpc_error(code=400, message=message))

    def _encrypt_response(self, body: bytes) -> bytes:
        if self.session_id is None:
            raise MTProtoSecurityError("SESSION_ID_UNSET")
        msg_id = self._next_server_message_id()
        # A response to a client request has message-id modulo 4 == 1. The
        # response is content-related because it carries an RPC result.
        seq_no = self.sequence * 2 + 1
        self.sequence += 1
        return encrypt_server_message(
            auth_key=self.auth_key,
            server_salt=self.server_salt,
            session_id=self.session_id,
            msg_id=msg_id,
            seq_no=seq_no,
            body=body,
        )

    def _validate_client_message(self, message: EncryptedMessage) -> None:
        if message.msg_id % 4:
            raise MTProtoSecurityError("MESSAGE_ID_INVALID")
        now = int(time.time())
        message_time = message.msg_id >> 32
        if message_time < now - MAX_PAST_SECONDS or message_time > now + MAX_FUTURE_SECONDS:
            raise MTProtoSecurityError("MESSAGE_ID_TIME_INVALID")
        if self.session_id is not None and message.session_id != self.session_id:
            raise MTProtoSecurityError("SESSION_ID_INVALID")
        if message.msg_id in self.recent_client_message_ids:
            raise MTProtoSecurityError("MESSAGE_REPLAY")
        self.recent_client_message_ids.add(message.msg_id)
        if len(self.recent_client_message_ids) > 8192:
            self.recent_client_message_ids = set(sorted(self.recent_client_message_ids)[-4096:])

    def _next_server_message_id(self) -> int:
        candidate = (int(time.time()) << 32) | secrets.randbits(30)
        candidate = (candidate & ~0b11) | 0b01
        if candidate <= self.last_server_message_id:
            candidate = self.last_server_message_id + 4
            candidate = (candidate & ~0b11) | 0b01
        self.last_server_message_id = candidate
        return candidate
