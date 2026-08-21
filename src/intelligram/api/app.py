from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from intelligram.auth.tokens import TokenError, create_session_id, issue_token, verify_token
from intelligram.config import Settings
from intelligram.database import Database, now_unix
from intelligram.mtproto.adapter import MTProtoSessionAdapter
from intelligram.mtproto.authorization_handshake import AuthorizationHandshake, CompletedAuthKey
from intelligram.mtproto.crypto import MTProtoSecurityError
from intelligram.mtproto.keys import load_or_create_server_keypair
from intelligram.mtproto.plain_handshake import PlainHandshakeError
from intelligram.mtproto.transport import AbridgedFrameBuffer, TransportError, encode_abridged_packet
from intelligram.services.accounts import (
    AccountAuthError,
    active_login_challenges,
    complete_device_login,
    password_login,
    register_password_account,
    start_device_login,
)
from intelligram.services.messaging import (
    MessagingError,
    create_group,
    get_dialogs,
    get_history,
    send_message,
)
from intelligram.services.updates import UpdateEnvelope, get_difference, get_state


LOGGER = logging.getLogger("uvicorn.error")


class RegisterAccountRequest(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=1024)
    first_name: str = Field(min_length=1, max_length=128)
    last_name: str = Field(default="", max_length=128)
    username: str | None = Field(default=None, max_length=32)
    device_label: str = Field(default="IntelliGram Web K", min_length=1, max_length=255)


class PasswordLoginRequest(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    device_label: str = Field(default="IntelliGram Web K", min_length=1, max_length=255)


class StartDeviceLoginRequest(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    device_label: str = Field(default="IntelliGram Web K", min_length=1, max_length=255)


class CompleteDeviceLoginRequest(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    challenge_id: str = Field(min_length=16, max_length=255)
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")
    device_label: str = Field(default="IntelliGram Web K", min_length=1, max_length=255)


class CreateGroupRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    member_user_ids: list[int] = Field(default_factory=list, max_length=200_000)


class SendMessageRequest(BaseModel):
    peer_id: int
    body: str = Field(min_length=1, max_length=4096)
    client_random_id: str = Field(min_length=1, max_length=128)
    reply_to_message_id: int | None = None


@dataclass
class ConnectionHub:
    connections: dict[int, set[WebSocket]]
    lock: asyncio.Lock

    @classmethod
    def create(cls) -> "ConnectionHub":
        return cls(connections={}, lock=asyncio.Lock())

    async def add(self, user_id: int, websocket: WebSocket) -> None:
        async with self.lock:
            self.connections.setdefault(user_id, set()).add(websocket)

    async def remove(self, user_id: int, websocket: WebSocket) -> None:
        async with self.lock:
            connections = self.connections.get(user_id)
            if not connections:
                return
            connections.discard(websocket)
            if not connections:
                self.connections.pop(user_id, None)

    async def publish(self, envelopes: list[UpdateEnvelope]) -> None:
        for envelope in envelopes:
            async with self.lock:
                sockets = list(self.connections.get(envelope.user_id, set()))
            stale: list[WebSocket] = []
            for websocket in sockets:
                try:
                    await websocket.send_json(envelope.as_dict())
                except Exception:
                    stale.append(websocket)
            for websocket in stale:
                await self.remove(envelope.user_id, websocket)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    restored_mtproto_auth_keys: dict[int, CompletedAuthKey] = {}
    with database.transaction() as connection:
        key_rows = connection.execute(
            """
            SELECT auth_key_id, key_material, server_salt
            FROM auth_keys
            WHERE key_material IS NOT NULL AND server_salt IS NOT NULL
            AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at >= ?)
            """,
            (now_unix(),),
        ).fetchall()
    for row in key_rows:
        try:
            key_id = int(row["auth_key_id"])
            key_material = bytes(row["key_material"])
            server_salt = int(str(row["server_salt"]))
        except (TypeError, ValueError):
            LOGGER.warning("Ignoring malformed persisted MTProto authorization key")
            continue
        restored_mtproto_auth_keys[key_id] = CompletedAuthKey(
            key_id=key_id,
            auth_key=key_material,
            server_salt=server_salt,
        )
    server_key_pair = load_or_create_server_keypair(
        settings.mtproto_rsa_private_key_path,
        settings.mtproto_rsa_public_key_path,
    )
    hub = ConnectionHub.create()

    app = FastAPI(
        title="IntelliGram Server",
        version="0.1.0",
        description="Self-hosted Python messaging server foundation. The HTTP API is a development and verification interface; MTProto transport is implemented separately.",
    )
    # Public bootstrap data contains only the MTProto public key and endpoint;
    # authenticated HTTP operations remain protected by signed bearer tokens.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.state.settings = settings
    app.state.database = database
    app.state.server_key_pair = server_key_pair
    app.state.hub = hub
    app.state.mtproto_auth_keys: dict[int, CompletedAuthKey] = restored_mtproto_auth_keys

    def current_user_id(authorization: str | None = Header(default=None)) -> int:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="AUTH_KEY_UNREGISTERED")
        try:
            claims = verify_token(authorization[7:], settings.token_secret)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        with database.transaction() as connection:
            session = connection.execute(
                """
                SELECT user_id FROM sessions
                WHERE id = ? AND revoked_at IS NULL AND expires_at >= ?
                """,
                (claims["sid"], now_unix()),
            ).fetchone()
        if session is None or int(session["user_id"]) != claims["sub"]:
            raise HTTPException(status_code=401, detail="SESSION_REVOKED")
        return int(session["user_id"])

    def development_only() -> None:
        if not settings.development_mode:
            raise HTTPException(status_code=404, detail="NOT_FOUND")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "service": "intelligram-server", "development_mode": settings.development_mode}

    @app.get("/v1/bootstrap")
    def bootstrap() -> dict[str, Any]:
        return {
            "product": "IntelliGram",
            "network": "self-hosted",
            "development_mode": settings.development_mode,
            "http_api": {"base_url": settings.public_base_url},
            "mtproto": {
                "status": "foundation-in-progress",
                "dc_id": settings.mtproto_dc_id,
                "server_public_key_fingerprint": str(server_key_pair.fingerprint),
                "server_public_key": {
                    "modulus_hex": format(server_key_pair.public_key.public_numbers().n, "x"),
                    "exponent_hex": format(server_key_pair.public_key.public_numbers().e, "x"),
                },
                "transports_target": ["abridged", "intermediate", "padded_intermediate", "full", "websocket"],
            },
        }

    def session_payload(session_id: str, user_id: int, expires_at: int) -> dict[str, Any]:
        return {
            "access_token": issue_token(
                session_id=session_id,
                user_id=user_id,
                secret=settings.token_secret,
                expires_at=expires_at,
            ),
            "token_type": "bearer",
            "expires_at": expires_at,
            "user_id": user_id,
        }

    @app.post("/v1/auth/register", status_code=201)
    async def register_account(request: RegisterAccountRequest) -> dict[str, Any]:
        """Create the first IntelliGram session without SMS verification.

        The phone-like value is a unique account identifier. Password possession,
        not phone-number ownership, authenticates this self-hosted mode.
        """
        try:
            with database.transaction(immediate=True) as connection:
                issued = register_password_account(
                    connection,
                    phone=request.phone,
                    password=request.password,
                    first_name=request.first_name,
                    last_name=request.last_name,
                    username=request.username,
                    device_label=request.device_label,
                )
            return session_payload(issued.session_id, issued.user_id, issued.expires_at)
        except AccountAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/auth/login/password")
    async def login_with_password(request: PasswordLoginRequest) -> dict[str, Any]:
        try:
            with database.transaction(immediate=True) as connection:
                issued = password_login(
                    connection,
                    phone=request.phone,
                    password=request.password,
                    device_label=request.device_label,
                )
            return session_payload(issued.session_id, issued.user_id, issued.expires_at)
        except AccountAuthError as exc:
            status = 404 if str(exc) == "PHONE_NUMBER_UNOCCUPIED" else 401
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    @app.post("/v1/auth/login/start")
    async def start_login_from_existing_session(request: StartDeviceLoginRequest) -> dict[str, Any]:
        try:
            with database.transaction(immediate=True) as connection:
                result = start_device_login(
                    connection,
                    phone=request.phone,
                    device_label=request.device_label,
                )
            await hub.publish(result.updates)
            return {
                "status": result.status,
                "challenge_id": result.challenge_id,
                "expires_at": result.expires_at,
            }
        except AccountAuthError as exc:
            status = 404 if str(exc) == "PHONE_NUMBER_UNOCCUPIED" else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    @app.post("/v1/auth/login/complete")
    async def complete_login_from_existing_session(request: CompleteDeviceLoginRequest) -> dict[str, Any]:
        try:
            with database.transaction(immediate=True) as connection:
                issued = complete_device_login(
                    connection,
                    phone=request.phone,
                    challenge_id=request.challenge_id,
                    code=request.code,
                    device_label=request.device_label,
                )
            return session_payload(issued.session_id, issued.user_id, issued.expires_at)
        except AccountAuthError as exc:
            status = 401 if str(exc) in {"PHONE_CODE_INVALID", "PHONE_CODE_EXPIRED"} else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    @app.get("/v1/auth/login-challenges")
    def login_challenges(user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        with database.transaction() as connection:
            return {"challenges": active_login_challenges(connection, user_id=user_id)}

    @app.get("/v1/dialogs")
    def dialogs(offset: int = Query(default=0, ge=0), limit: int = Query(default=30, ge=1, le=100), user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        try:
            with database.transaction() as connection:
                return {"dialogs": get_dialogs(connection, user_id=user_id, offset=offset, limit=limit)}
        except MessagingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/peers/groups", status_code=201)
    async def groups(request: CreateGroupRequest, user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        try:
            with database.transaction(immediate=True) as connection:
                peer_id, emitted = create_group(
                    connection,
                    owner_user_id=user_id,
                    title=request.title,
                    member_user_ids=request.member_user_ids,
                )
            await hub.publish(emitted)
            return {"peer_id": peer_id}
        except MessagingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/peers/{peer_id}/history")
    def history(peer_id: int, before_id: int | None = Query(default=None, ge=1), limit: int = Query(default=60, ge=1, le=100), user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        try:
            with database.transaction() as connection:
                return {"messages": get_history(connection, peer_id=peer_id, user_id=user_id, before_id=before_id, limit=limit)}
        except MessagingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/messages", status_code=201)
    async def messages(request: SendMessageRequest, user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        try:
            with database.transaction(immediate=True) as connection:
                message, emitted = send_message(
                    connection,
                    peer_id=request.peer_id,
                    sender_user_id=user_id,
                    body=request.body,
                    client_random_id=request.client_random_id,
                    reply_to_message_id=request.reply_to_message_id,
                )
            await hub.publish(emitted)
            return {"message": message, "updates_emitted": len(emitted)}
        except MessagingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/updates/state")
    def updates_state(user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        with database.transaction() as connection:
            return get_state(connection, user_id)

    @app.get("/v1/updates/difference")
    def updates_difference(after_pts: int = Query(ge=0), limit: int = Query(default=100, ge=1, le=1000), user_id: int = Depends(current_user_id)) -> dict[str, Any]:
        with database.transaction() as connection:
            updates = get_difference(connection, user_id=user_id, after_pts=after_pts, limit=limit)
            state = get_state(connection, user_id)
        return {"updates": [update.as_dict() for update in updates], "state": state}

    @app.websocket("/apiws")
    async def mtproto_websocket(websocket: WebSocket) -> None:
        # Telegram Web A requests the `binary` subprotocol and sends the
        # abridged transport tag as its first binary write after connecting.
        await websocket.accept(subprotocol="binary")
        frame_buffer = AbridgedFrameBuffer(require_tag=True)
        handshake = AuthorizationHandshake(server_key_pair)
        encrypted_sessions: dict[int, MTProtoSessionAdapter] = {}
        shared_auth_keys: dict[int, CompletedAuthKey] = app.state.mtproto_auth_keys
        try:
            while True:
                data = await websocket.receive_bytes()
                if settings.development_mode:
                    LOGGER.info("MTProto WebSocket received %d bytes", len(data))
                for packet in frame_buffer.feed(data):
                    auth_key_id = struct.unpack_from("<Q", packet, 0)[0] if len(packet) >= 8 else None
                    if auth_key_id == 0:
                        response = handshake.handle_packet(packet)
                        for key_id, completed in handshake.completed_keys.items():
                            shared_auth_keys[key_id] = completed
                            encrypted_sessions.setdefault(
                                key_id,
                                MTProtoSessionAdapter(
                                    auth_key=completed.auth_key,
                                    server_salt=completed.server_salt,
                                    database=database,
                                ),
                            )
                    else:
                        if auth_key_id is None:
                            raise MTProtoSecurityError("AUTH_KEY_UNREGISTERED")
                        if auth_key_id not in encrypted_sessions:
                            completed = shared_auth_keys.get(auth_key_id)
                            if completed is None:
                                raise MTProtoSecurityError("AUTH_KEY_UNREGISTERED")
                            adapter = MTProtoSessionAdapter(
                                auth_key=completed.auth_key,
                                server_salt=completed.server_salt,
                                database=database,
                            )
                            with database.transaction() as connection:
                                binding = connection.execute(
                                    """
                                    SELECT user_id FROM auth_keys
                                    WHERE auth_key_id = ? AND revoked_at IS NULL
                                    AND (expires_at IS NULL OR expires_at >= ?)
                                    """,
                                    (str(auth_key_id), now_unix()),
                                ).fetchone()
                            if binding is not None:
                                adapter.user_id = int(binding["user_id"])
                            encrypted_sessions[auth_key_id] = adapter
                        response = encrypted_sessions[auth_key_id].handle_encrypted(packet)
                    if response is not None:
                        encoded_response = encode_abridged_packet(response)
                        if settings.development_mode:
                            LOGGER.info("MTProto WebSocket sent %d bytes", len(encoded_response))
                        await websocket.send_bytes(encoded_response)
        except WebSocketDisconnect:
            pass
        except (PlainHandshakeError, MTProtoSecurityError, TransportError) as exc:
            LOGGER.warning("MTProto WebSocket protocol failure: %s", exc)
            await websocket.close(code=1008)
        except Exception:
            LOGGER.exception("MTProto WebSocket unexpected failure")
            await websocket.close(code=1011)

    @app.websocket("/v1/realtime")
    async def realtime(websocket: WebSocket, token: str = Query(...)) -> None:
        try:
            claims = verify_token(token, settings.token_secret)
        except TokenError:
            await websocket.close(code=4401)
            return
        user_id = int(claims["sub"])
        with database.transaction() as connection:
            session = connection.execute(
                "SELECT id FROM sessions WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at >= ?",
                (claims["sid"], user_id, now_unix()),
            ).fetchone()
            if session is None:
                await websocket.close(code=4401)
                return
            initial_state = get_state(connection, user_id)
        await websocket.accept()
        await hub.add(user_id, websocket)
        await websocket.send_json({"@type": "updateConnectionState", "connectionState": "connectionStateReady", "state": initial_state})
        try:
            while True:
                message = await websocket.receive_json()
                if isinstance(message, dict) and message.get("@type") == "ping":
                    await websocket.send_json({"@type": "pong", "timestamp": now_unix()})
        except WebSocketDisconnect:
            pass
        finally:
            await hub.remove(user_id, websocket)

    return app
