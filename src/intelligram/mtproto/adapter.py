"""Stateful encrypted MTProto service-message adapter.

This is the protocol adapter beneath the future TCP/WSS gateway. It currently
implements service-level ping and acknowledgement semantics and returns
standards-shaped RPC envelopes. Application TL methods are registered here as
the Python Teamgram port grows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import base64
import logging
import secrets
import time

from intelligram.database import Database
from intelligram.mtproto.crypto import EncryptedMessage, MTProtoSecurityError, auth_key_id, decrypt_client_message, encrypt_server_message
from intelligram.services.accounts import (
    AccountAuthError,
    complete_device_login,
    normalize_phone,
    register_password_account,
    start_device_login,
)
from intelligram.services.messaging import (
    MessagingError,
    create_group,
    get_dialogs,
    get_history,
    get_or_create_direct_peer,
    get_peer,
    send_message,
)
from intelligram.services.updates import get_state
from intelligram.mtproto.tl import (
    TLDecodeError,
    encode_account_privacy_rules,
    encode_chat,
    encode_auth_authorization,
    encode_auth_login_token,
    encode_auth_sent_code,
    encode_auth_sent_code_success_for_sign_up,
    encode_config,
    encode_contacts_contacts,
    encode_contact,
    encode_dialog,
    encode_message,
    encode_messages_dialogs,
    encode_messages_invited_users,
    encode_messages_messages,
    encode_messages_peer_dialogs,
    encode_peer_chat,
    encode_peer_user,
    encode_updates,
    encode_update_message_id,
    encode_update_new_message,
    encode_user,
    encode_users_user_full,
    encode_pong,
    encode_rpc_error,
    encode_rpc_result,
    encode_updates_state,
    encode_vector,
    parse_request,
    unwrap_client_query,
)


MAX_PAST_SECONDS = 300
MAX_FUTURE_SECONDS = 30
LOGGER = logging.getLogger("intelligram.mtproto.adapter")


@dataclass(slots=True)
class MTProtoSessionAdapter:
    auth_key: bytes
    server_salt: int
    session_id: int | None = None
    sequence: int = 0
    last_server_message_id: int = 0
    recent_client_message_ids: set[int] = field(default_factory=set)
    dc_host: str = "127.0.0.1"
    dc_port: int = 8080
    login_tokens: dict[bytes, int] = field(default_factory=dict)
    database: Database | None = None
    user_id: int | None = None

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
            request = parse_request(unwrap_client_query(message.body))
        except TLDecodeError as exc:
            return self._encrypt_rpc_error(message, "CONSTRUCTOR_INVALID")

        LOGGER.warning("MTProto encrypted request: %s (0x%08x)", request.name, request.constructor_id)
        if request.name == "msgs_ack":
            return None
        if request.name == "ping":
            result = encode_pong(message_id=message.msg_id, ping_id=int(request.fields["ping_id"]))
            return self._encrypt_result(message, result)
        if request.name == "help_get_config":
            now = int(time.time())
            result = encode_config(
                dc_id=1,
                host=self.dc_host,
                port=self.dc_port,
                date=now,
                expires=now + 3_600,
            )
            return self._encrypt_result(message, result)
        if request.name == "updates_get_state":
            if self.database is not None and self.user_id is not None:
                with self.database.transaction() as connection:
                    state = get_state(connection, self.user_id)
                return self._encrypt_result(
                    message,
                    encode_updates_state(
                        pts=state["pts"], qts=state["qts"], date=state["date"], seq=state["seq"], unread_count=0,
                    ),
                )
            return self._encrypt_result(
                message,
                encode_updates_state(pts=0, qts=0, date=int(time.time()), seq=0, unread_count=0),
            )
        if request.name == "auth_send_code":
            return self._handle_auth_send_code(message, phone_number=str(request.fields["phone_number"]))
        if request.name == "auth_sign_up":
            return self._handle_auth_sign_up(
                message,
                phone_number=str(request.fields["phone_number"]),
                phone_code_hash=str(request.fields["phone_code_hash"]),
                first_name=str(request.fields["first_name"]),
                last_name=str(request.fields["last_name"]),
            )
        if request.name == "auth_sign_in":
            return self._handle_auth_sign_in(
                message,
                phone_number=str(request.fields["phone_number"]),
                phone_code_hash=str(request.fields["phone_code_hash"]),
                phone_code=str(request.fields["phone_code"]),
            )
        if request.name == "auth_export_login_token":
            token = secrets.token_bytes(32)
            expires = int(time.time()) + 60
            self.login_tokens[token] = expires
            return self._encrypt_result(message, encode_auth_login_token(expires=expires, token=token))
        if request.name == "auth_import_login_token":
            token = request.fields["token"]
            if not isinstance(token, bytes) or self.login_tokens.get(token, 0) < int(time.time()):
                return self._encrypt_rpc_error(message, "AUTH_TOKEN_INVALID")
            return self._encrypt_result(
                message,
                encode_auth_login_token(expires=self.login_tokens[token], token=token),
            )
        if request.name == "users_get_users":
            return self._handle_users_get_users(message, request.fields["users"])
        if request.name == "users_get_full_user":
            return self._handle_users_get_full_user(message, request.fields["user"])
        if request.name == "contacts_get_contacts":
            return self._handle_contacts_get_contacts(message)
        if request.name == "messages_get_dialogs":
            return self._handle_messages_get_dialogs(message, limit=int(request.fields["limit"]))
        if request.name == "messages_get_peer_dialogs":
            return self._handle_messages_get_peer_dialogs(message, request.fields["peers"])
        if request.name == "messages_get_history":
            return self._handle_messages_get_history(
                message,
                peer=request.fields["peer"],
                offset_id=int(request.fields["offset_id"]),
                limit=int(request.fields["limit"]),
            )
        if request.name == "messages_create_chat":
            return self._handle_messages_create_chat(
                message,
                inputs=request.fields["users"],
                title=str(request.fields["title"]),
            )
        if request.name == "messages_send_message":
            return self._handle_messages_send_message(
                message,
                peer=request.fields["peer"],
                body=str(request.fields["message"]),
                random_id=int(request.fields["random_id"]),
            )
        if request.name == "account_update_profile":
            return self._handle_account_update_profile(
                message,
                first_name=request.fields["first_name"],
                last_name=request.fields["last_name"],
                about=request.fields["about"],
            )
        if request.name == "account_update_status":
            return self._encrypt_result(message, b"\xb5\x75\x72\x99")
        if request.name == "account_get_privacy":
            return self._encrypt_result(message, encode_account_privacy_rules())
        LOGGER.warning("Unsupported MTProto encrypted request: %s (0x%08x)", request.name, request.constructor_id)
        return self._encrypt_rpc_error(message, "METHOD_INVALID")

    def _handle_auth_send_code(self, message: EncryptedMessage, *, phone_number: str) -> bytes:
        if self.database is None:
            return self._encrypt_rpc_error(message, "AUTH_RESTART")
        try:
            normalized_phone = normalize_phone(phone_number)
        except AccountAuthError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        with self.database.transaction() as connection:
            user = connection.execute("SELECT id FROM users WHERE phone = ?", (normalized_phone,)).fetchone()
            if user is None:
                return self._encrypt_result(message, encode_auth_sent_code_success_for_sign_up())
            result = start_device_login(
                connection,
                phone=normalized_phone,
                device_label="IntelliGram Web K MTProto browser",
            )
        if result.status == "password_required" or result.challenge_id is None:
            return self._encrypt_rpc_error(message, "SESSION_PASSWORD_NEEDED")
        # The one-time value itself is persisted as a durable login-code update
        # for existing IntelliGram sessions. This response exposes only the
        # opaque challenge identifier mandated by auth.sentCode.
        return self._encrypt_result(message, encode_auth_sent_code(phone_code_hash=result.challenge_id))

    def _handle_auth_sign_up(
        self,
        message: EncryptedMessage,
        *,
        phone_number: str,
        phone_code_hash: str,
        first_name: str,
        last_name: str,
    ) -> bytes:
        if self.database is None:
            return self._encrypt_rpc_error(message, "AUTH_RESTART")
        prefix = "intelligram-register:"
        if not phone_code_hash.startswith(prefix):
            return self._encrypt_rpc_error(message, "PHONE_CODE_INVALID")
        try:
            password = base64.b64decode(phone_code_hash[len(prefix):].encode("ascii"), validate=True).decode("utf-8")
            with self.database.transaction(immediate=True) as connection:
                issued = register_password_account(
                    connection,
                    phone=phone_number,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                    device_label="IntelliGram Web K MTProto",
                )
        except (AccountAuthError, ValueError, UnicodeError) as exc:
            error = str(exc) if isinstance(exc, AccountAuthError) else "PHONE_CODE_INVALID"
            return self._encrypt_rpc_error(message, error)
        self.user_id = issued.user_id
        self._associate_auth_key(issued.user_id)
        return self._encrypt_result(message, encode_auth_authorization(user=self._load_user(issued.user_id)))

    def _handle_auth_sign_in(
        self,
        message: EncryptedMessage,
        *,
        phone_number: str,
        phone_code_hash: str,
        phone_code: str,
    ) -> bytes:
        if self.database is None:
            return self._encrypt_rpc_error(message, "AUTH_RESTART")
        try:
            with self.database.transaction(immediate=True) as connection:
                issued = complete_device_login(
                    connection,
                    phone=phone_number,
                    challenge_id=phone_code_hash,
                    code=phone_code,
                    device_label="IntelliGram Web K MTProto browser",
                )
        except AccountAuthError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        self.user_id = issued.user_id
        self._associate_auth_key(issued.user_id)
        return self._encrypt_result(message, encode_auth_authorization(user=self._load_user(issued.user_id)))

    def _require_authenticated(self, message: EncryptedMessage) -> tuple[Database, int] | bytes:
        if self.database is None or self.user_id is None:
            return self._encrypt_rpc_error(message, "AUTH_KEY_UNREGISTERED")
        return self.database, self.user_id

    def _load_user(self, user_id: int) -> dict[str, object]:
        if self.database is None:
            raise RuntimeError("Database is required for a signed-in user")
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT id, phone, username, first_name, last_name, about FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("Authenticated IntelliGram user no longer exists")
        return dict(row)

    @staticmethod
    def _message_from_row(row: object) -> dict[str, object]:
        return {
            "id": int(row["id"]),
            "peer_id": int(row["peer_id"]),
            "sender_user_id": int(row["sender_user_id"]),
            "body": str(row["body"]),
            "sent_at": int(row["sent_at"]),
        }

    def _load_users(self, connection: object, user_ids: set[int]) -> dict[int, dict[str, object]]:
        if not user_ids:
            return {}
        placeholders = ",".join("?" for _ in user_ids)
        rows = connection.execute(
            f"SELECT id, phone, username, first_name, last_name, about FROM users WHERE id IN ({placeholders})",
            sorted(user_ids),
        ).fetchall()
        return {int(row["id"]): dict(row) for row in rows}

    def _resolve_input_peer(self, connection: object, *, user_id: int, peer: dict[str, object]) -> dict[str, object]:
        kind = str(peer.get("kind"))
        if kind == "self":
            peer_id = get_or_create_direct_peer(connection, user_id=user_id, other_user_id=user_id)
        elif kind == "user":
            peer_id = get_or_create_direct_peer(connection, user_id=user_id, other_user_id=int(peer["user_id"]))
        elif kind == "chat":
            peer_id = int(peer["chat_id"])
        else:
            raise MessagingError("PEER_ID_INVALID")
        return get_peer(connection, peer_id=peer_id, user_id=user_id)

    @staticmethod
    def _encode_peer(summary: dict[str, object]) -> bytes:
        kind = str(summary["kind"])
        if kind == "user":
            return encode_peer_user(user_id=int(summary["direct_user_id"]))
        if kind == "chat":
            return encode_peer_chat(chat_id=int(summary["peer_id"]))
        raise MessagingError("PEER_ID_INVALID")

    def _encode_users(self, users: dict[int, dict[str, object]], *, self_user_id: int) -> list[bytes]:
        return [
            encode_user(user=user, self_user_id=self_user_id, contact=user_id != self_user_id)
            for user_id, user in sorted(users.items())
        ]

    def _encode_chats(self, connection: object, *, chat_ids: set[int], self_user_id: int) -> list[bytes]:
        if not chat_ids:
            return []
        placeholders = ",".join("?" for _ in chat_ids)
        rows = connection.execute(
            f"""
            SELECT p.id, p.title, p.created_at, p.created_by_user_id, COUNT(pm.user_id) AS participants_count
            FROM peers p
            JOIN peer_memberships pm ON pm.peer_id = p.id AND pm.left_at IS NULL
            WHERE p.kind = 'chat' AND p.id IN ({placeholders})
            GROUP BY p.id, p.title, p.created_at, p.created_by_user_id
            ORDER BY p.id
            """,
            sorted(chat_ids),
        ).fetchall()
        return [
            encode_chat(
                chat_id=int(row["id"]),
                title=str(row["title"]),
                participants_count=int(row["participants_count"]),
                date=int(row["created_at"]),
                creator=int(row["created_by_user_id"] or 0) == self_user_id,
            )
            for row in rows
        ]

    def _handle_users_get_users(self, message: EncryptedMessage, inputs: list[dict[str, object]]) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        requested_ids: set[int] = set()
        for input_user in inputs:
            if input_user.get("kind") == "self":
                requested_ids.add(self_user_id)
            elif input_user.get("kind") == "user":
                requested_ids.add(int(input_user["user_id"]))
        with database.transaction() as connection:
            users = self._load_users(connection, requested_ids)
        return self._encrypt_result(message, encode_vector(self._encode_users(users, self_user_id=self_user_id)))

    def _handle_users_get_full_user(self, message: EncryptedMessage, input_user: dict[str, object]) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        target_user_id = self_user_id if input_user.get("kind") == "self" else int(input_user.get("user_id", 0))
        with database.transaction() as connection:
            users = self._load_users(connection, {target_user_id})
        user = users.get(target_user_id)
        if user is None:
            return self._encrypt_rpc_error(message, "USER_ID_INVALID")
        return self._encrypt_result(message, encode_users_user_full(user=user, self_user_id=self_user_id))

    def _handle_account_update_profile(
        self,
        message: EncryptedMessage,
        *,
        first_name: object,
        last_name: object,
        about: object,
    ) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        updates: dict[str, object] = {}
        if first_name is not None:
            normalized = str(first_name).strip()
            if not normalized:
                return self._encrypt_rpc_error(message, "FIRSTNAME_INVALID")
            updates["first_name"] = normalized
        if last_name is not None:
            updates["last_name"] = str(last_name).strip()
        if about is not None:
            normalized_about = str(about).strip()
            if len(normalized_about) > 70:
                return self._encrypt_rpc_error(message, "ABOUT_TOO_LONG")
            updates["about"] = normalized_about
        with database.transaction(immediate=True) as connection:
            if updates:
                assignments = ", ".join(f"{column} = ?" for column in updates)
                connection.execute(
                    f"UPDATE users SET {assignments}, updated_at = ? WHERE id = ?",
                    [*updates.values(), int(time.time()), self_user_id],
                )
            user = connection.execute(
                "SELECT id, phone, username, first_name, last_name, about FROM users WHERE id = ?",
                (self_user_id,),
            ).fetchone()
        if user is None:
            return self._encrypt_rpc_error(message, "USER_ID_INVALID")
        return self._encrypt_result(
            message,
            encode_user(user=dict(user), self_user_id=self_user_id),
        )

    def _handle_contacts_get_contacts(self, message: EncryptedMessage) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        with database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT CASE WHEN dpu.user_low_id = ? THEN dpu.user_high_id ELSE dpu.user_low_id END AS user_id
                FROM direct_peer_users dpu
                JOIN peer_memberships pm ON pm.peer_id = dpu.peer_id
                WHERE pm.user_id = ? AND pm.left_at IS NULL
                AND (dpu.user_low_id = ? OR dpu.user_high_id = ?)
                """,
                (self_user_id, self_user_id, self_user_id, self_user_id),
            ).fetchall()
            contact_ids = {int(row["user_id"]) for row in rows if int(row["user_id"]) != self_user_id}
            users = self._load_users(connection, contact_ids)
        contacts = [encode_contact(user_id=user_id, mutual=True) for user_id in sorted(users)]
        return self._encrypt_result(
            message,
            encode_contacts_contacts(contacts=contacts, users=self._encode_users(users, self_user_id=self_user_id)),
        )

    def _dialog_payloads(
        self,
        connection: object,
        *,
        self_user_id: int,
        dialogs: list[dict[str, object]],
    ) -> tuple[list[bytes], list[bytes], list[bytes], list[bytes]]:
        encoded_dialogs: list[bytes] = []
        encoded_messages: list[bytes] = []
        user_ids: set[int] = {self_user_id}
        chat_ids: set[int] = set()
        for dialog in dialogs:
            peer = self._encode_peer(dialog)
            if dialog.get("direct_user_id") is not None:
                user_ids.add(int(dialog["direct_user_id"]))
            elif str(dialog.get("kind")) == "chat":
                chat_ids.add(int(dialog["peer_id"]))
            top_message_id = int(dialog["top_message_id"] or 0)
            encoded_dialogs.append(
                encode_dialog(
                    peer=peer,
                    top_message_id=top_message_id,
                    read_inbox_max_id=int(dialog.get("read_inbox_max_id", 0)),
                    read_outbox_max_id=int(dialog.get("read_outbox_max_id", 0)),
                    unread_count=int(dialog["unread_count"]),
                    pinned=dialog.get("pinned_order") is not None,
                )
            )
            if top_message_id:
                row = connection.execute(
                    """
                    SELECT id, peer_id, sender_user_id, body, sent_at
                    FROM messages WHERE id = ? AND deleted_at IS NULL
                    """,
                    (top_message_id,),
                ).fetchone()
                if row is not None:
                    stored = self._message_from_row(row)
                    user_ids.add(int(stored["sender_user_id"]))
                    encoded_messages.append(
                        encode_message(
                            message=stored,
                            recipient_peer=peer,
                            outgoing=int(stored["sender_user_id"]) == self_user_id,
                        )
                    )
        users = self._load_users(connection, user_ids)
        return (
            encoded_dialogs,
            encoded_messages,
            self._encode_chats(connection, chat_ids=chat_ids, self_user_id=self_user_id),
            self._encode_users(users, self_user_id=self_user_id),
        )

    def _handle_messages_get_dialogs(self, message: EncryptedMessage, *, limit: int) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        try:
            with database.transaction() as connection:
                dialogs = get_dialogs(connection, user_id=self_user_id, offset=0, limit=min(max(limit, 1), 100))
                encoded_dialogs, encoded_messages, encoded_chats, encoded_users = self._dialog_payloads(
                    connection, self_user_id=self_user_id, dialogs=dialogs,
                )
        except MessagingError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        return self._encrypt_result(
            message,
            encode_messages_dialogs(dialogs=encoded_dialogs, messages=encoded_messages, chats=encoded_chats, users=encoded_users),
        )

    def _handle_messages_get_peer_dialogs(self, message: EncryptedMessage, peers: list[dict[str, object]]) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        try:
            with database.transaction(immediate=True) as connection:
                summaries = [self._resolve_input_peer(connection, user_id=self_user_id, peer=peer) for peer in peers]
                all_dialogs = get_dialogs(connection, user_id=self_user_id, offset=0, limit=100)
                wanted_peer_ids = {int(summary["peer_id"]) for summary in summaries}
                dialogs = [dialog for dialog in all_dialogs if int(dialog["peer_id"]) in wanted_peer_ids]
                encoded_dialogs, encoded_messages, encoded_chats, encoded_users = self._dialog_payloads(
                    connection, self_user_id=self_user_id, dialogs=dialogs,
                )
                state = get_state(connection, self_user_id)
        except MessagingError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        return self._encrypt_result(
            message,
            encode_messages_peer_dialogs(
                dialogs=encoded_dialogs,
                messages=encoded_messages,
                chats=encoded_chats,
                users=encoded_users,
                pts=state["pts"],
                qts=state["qts"],
                date=state["date"],
                seq=state["seq"],
                unread_count=0,
            ),
        )

    def _handle_messages_get_history(
        self, message: EncryptedMessage, *, peer: dict[str, object], offset_id: int, limit: int,
    ) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        try:
            with database.transaction(immediate=True) as connection:
                summary = self._resolve_input_peer(connection, user_id=self_user_id, peer=peer)
                stored_messages = get_history(
                    connection,
                    peer_id=int(summary["peer_id"]),
                    user_id=self_user_id,
                    before_id=offset_id if offset_id > 0 else None,
                    limit=min(max(limit, 1), 100),
                )
                encoded_peer = self._encode_peer(summary)
                user_ids = {self_user_id, *(int(item["sender_user_id"]) for item in stored_messages)}
                if summary.get("direct_user_id") is not None:
                    user_ids.add(int(summary["direct_user_id"]))
                users = self._load_users(connection, user_ids)
                encoded_chats = self._encode_chats(
                    connection,
                    chat_ids={int(summary["peer_id"])} if str(summary.get("kind")) == "chat" else set(),
                    self_user_id=self_user_id,
                )
                encoded_messages = [
                    encode_message(
                        message=stored,
                        recipient_peer=encoded_peer,
                        outgoing=int(stored["sender_user_id"]) == self_user_id,
                    )
                    for stored in stored_messages
                ]
        except MessagingError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        return self._encrypt_result(
            message,
            encode_messages_messages(
                messages=encoded_messages,
                chats=encoded_chats,
                users=self._encode_users(users, self_user_id=self_user_id),
            ),
        )

    def _handle_messages_create_chat(
        self, message: EncryptedMessage, *, inputs: list[dict[str, object]], title: str,
    ) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        try:
            member_ids: list[int] = []
            for input_user in inputs:
                kind = input_user.get("kind")
                if kind == "self":
                    member_ids.append(self_user_id)
                elif kind == "user":
                    member_ids.append(int(input_user["user_id"]))
                else:
                    raise MessagingError("USER_ID_INVALID")
            invited_ids = sorted({user_id for user_id in member_ids if user_id != self_user_id})
            if not invited_ids:
                raise MessagingError("USERS_TOO_FEW")
            with database.transaction(immediate=True) as connection:
                chat_id, emitted = create_group(
                    connection,
                    owner_user_id=self_user_id,
                    title=title,
                    member_user_ids=invited_ids,
                )
                chat = connection.execute(
                    "SELECT id, title, created_at FROM peers WHERE id = ? AND kind = 'chat'", (chat_id,)
                ).fetchone()
                members = connection.execute(
                    "SELECT user_id FROM peer_memberships WHERE peer_id = ? AND left_at IS NULL ORDER BY user_id",
                    (chat_id,),
                ).fetchall()
                if chat is None:
                    raise RuntimeError("Created chat disappeared")
                users = self._load_users(connection, {int(row["user_id"]) for row in members})
                owner_update = next((update for update in emitted if update.user_id == self_user_id), None)
                if owner_update is None:
                    raise RuntimeError("Group creator update was not emitted")
                encoded_chat = encode_chat(
                    chat_id=chat_id,
                    title=str(chat["title"]),
                    participants_count=len(members),
                    date=int(chat["created_at"]),
                    creator=True,
                )
                updates = encode_updates(
                    updates=[],
                    users=self._encode_users(users, self_user_id=self_user_id),
                    chats=[encoded_chat],
                    date=owner_update.date,
                    seq=owner_update.seq,
                )
        except MessagingError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        return self._encrypt_result(
            message,
            encode_messages_invited_users(updates=updates),
        )

    def _handle_messages_send_message(
        self, message: EncryptedMessage, *, peer: dict[str, object], body: str, random_id: int,
    ) -> bytes:
        authenticated = self._require_authenticated(message)
        if isinstance(authenticated, bytes):
            return authenticated
        database, self_user_id = authenticated
        try:
            with database.transaction(immediate=True) as connection:
                summary = self._resolve_input_peer(connection, user_id=self_user_id, peer=peer)
                stored, emitted = send_message(
                    connection,
                    peer_id=int(summary["peer_id"]),
                    sender_user_id=self_user_id,
                    body=body,
                    client_random_id=str(random_id),
                )
                sender_update = next((update for update in emitted if update.user_id == self_user_id), None)
                if sender_update is None:
                    raise RuntimeError("Sender update was not emitted")
                encoded_peer = self._encode_peer(summary)
                user_ids = {self_user_id, int(stored["sender_user_id"])}
                if summary.get("direct_user_id") is not None:
                    user_ids.add(int(summary["direct_user_id"]))
                users = self._load_users(connection, user_ids)
                encoded_message = encode_message(message=stored, recipient_peer=encoded_peer, outgoing=True)
                encoded_chats = self._encode_chats(
                    connection,
                    chat_ids={int(summary["peer_id"])} if str(summary.get("kind")) == "chat" else set(),
                    self_user_id=self_user_id,
                )
                updates = [
                    encode_update_message_id(message_id=int(stored["id"]), random_id=random_id),
                    encode_update_new_message(
                        message=encoded_message,
                        pts=sender_update.pts,
                        pts_count=sender_update.pts_count,
                    ),
                ]
        except MessagingError as exc:
            return self._encrypt_rpc_error(message, str(exc))
        return self._encrypt_result(
            message,
            encode_updates(
                updates=updates,
                users=self._encode_users(users, self_user_id=self_user_id),
                chats=encoded_chats,
                date=sender_update.date,
                seq=sender_update.seq,
            ),
        )

    def _associate_auth_key(self, user_id: int) -> None:
        if self.database is None:
            return
        key_id = str(auth_key_id(self.auth_key))
        now = int(time.time())
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO auth_keys(
                    auth_key_id, user_id, key_fingerprint, key_material, server_salt,
                    created_at, revoked_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                ON CONFLICT(auth_key_id) DO UPDATE SET
                    user_id = excluded.user_id,
                    key_fingerprint = excluded.key_fingerprint,
                    key_material = excluded.key_material,
                    server_salt = excluded.server_salt,
                    revoked_at = NULL,
                    expires_at = NULL
                """,
                (key_id, user_id, f"mtproto:{key_id}", self.auth_key, str(self.server_salt), now),
            )

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
