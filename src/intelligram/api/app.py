from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from intelligram.auth.tokens import TokenError, create_session_id, issue_token, verify_token
from intelligram.config import Settings
from intelligram.database import Database, now_unix
from intelligram.mtproto.keys import load_or_create_server_keypair
from intelligram.services.messaging import (
    MessagingError,
    create_group,
    create_user,
    get_dialogs,
    get_history,
    send_message,
)
from intelligram.services.updates import UpdateEnvelope, get_difference, get_state


class RegisterDevelopmentUserRequest(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    first_name: str = Field(min_length=1, max_length=128)
    last_name: str = Field(default="", max_length=128)
    username: str | None = Field(default=None, max_length=32)


class DevelopmentLoginRequest(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    device_label: str = Field(default="IntelliGram development client", min_length=1, max_length=255)


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
    app.state.settings = settings
    app.state.database = database
    app.state.server_key_pair = server_key_pair
    app.state.hub = hub

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
                "server_public_key_fingerprint": server_key_pair.fingerprint,
                "transports_target": ["abridged", "intermediate", "padded_intermediate", "full", "websocket"],
            },
        }

    @app.post("/v1/development/users", status_code=201)
    async def register_development_user(request: RegisterDevelopmentUserRequest) -> dict[str, Any]:
        development_only()
        try:
            with database.transaction(immediate=True) as connection:
                user_id = create_user(
                    connection,
                    phone=request.phone,
                    first_name=request.first_name,
                    last_name=request.last_name,
                    username=request.username,
                )
            return {"id": user_id, "phone": request.phone, "first_name": request.first_name}
        except MessagingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/development/login")
    async def development_login(request: DevelopmentLoginRequest) -> dict[str, Any]:
        development_only()
        expires_at = now_unix() + 60 * 60 * 24
        with database.transaction(immediate=True) as connection:
            user = connection.execute("SELECT id FROM users WHERE phone = ?", (request.phone.strip(),)).fetchone()
            if user is None:
                raise HTTPException(status_code=404, detail="PHONE_NUMBER_UNOCCUPIED")
            session_id = create_session_id()
            connection.execute(
                """
                INSERT INTO sessions(id, user_id, device_label, created_at, last_seen_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, int(user["id"]), request.device_label, now_unix(), now_unix(), expires_at),
            )
        return {
            "access_token": issue_token(session_id=session_id, user_id=int(user["id"]), secret=settings.token_secret, expires_at=expires_at),
            "token_type": "bearer",
            "expires_at": expires_at,
            "user_id": int(user["id"]),
        }

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
