from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from typing import Any

from intelligram.database import now_unix
from intelligram.services.updates import UpdateEnvelope, append_update


class MessagingError(ValueError):
    """A client-safe domain failure with an MTProto-style error identifier."""


def _require_active_membership(connection: sqlite3.Connection, peer_id: int, user_id: int) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT p.id, p.kind, p.title, pm.role
        FROM peers p
        JOIN peer_memberships pm ON pm.peer_id = p.id
        WHERE p.id = ? AND pm.user_id = ? AND pm.left_at IS NULL
        """,
        (peer_id, user_id),
    ).fetchone()
    if row is None:
        raise MessagingError("PEER_ID_INVALID")
    return row


def create_user(connection: sqlite3.Connection, *, phone: str, first_name: str, last_name: str = "", username: str | None = None) -> int:
    phone = phone.strip()
    first_name = first_name.strip()
    if not phone or not first_name:
        raise MessagingError("PHONE_OR_NAME_INVALID")
    now = now_unix()
    try:
        cursor = connection.execute(
            """
            INSERT INTO users(phone, username, first_name, last_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (phone, username.strip().lstrip("@") if username else None, first_name, last_name.strip(), now, now),
        )
    except sqlite3.IntegrityError as exc:
        raise MessagingError("PHONE_OR_USERNAME_OCCUPIED") from exc
    user_id = int(cursor.lastrowid)
    connection.execute("INSERT INTO update_state(user_id, pts, qts, seq, date) VALUES (?, 0, 0, 0, ?)", (user_id, now))
    return user_id


def get_or_create_direct_peer(connection: sqlite3.Connection, *, user_id: int, other_user_id: int) -> int:
    """Return the durable peer shared by two IntelliGram users.

    A same-user pair is the account's Saved Messages peer. A two-user pair is
    shared in both directions, letting `PeerUser` history and dialogs remain
    stable even when message requests arrive from different devices.
    """

    user_ids = sorted({user_id, other_user_id})
    users = connection.execute(
        f"SELECT id, first_name, last_name FROM users WHERE id IN ({','.join('?' for _ in user_ids)})",
        user_ids,
    ).fetchall()
    if len(users) != len(user_ids):
        raise MessagingError("USER_ID_INVALID")
    low_user_id = min(user_id, other_user_id)
    high_user_id = max(user_id, other_user_id)
    existing = connection.execute(
        """
        SELECT peer_id FROM direct_peer_users
        WHERE user_low_id = ? AND user_high_id = ?
        """,
        (low_user_id, high_user_id),
    ).fetchone()
    if existing is not None:
        peer_id = int(existing["peer_id"])
        if user_id == other_user_id:
            connection.execute(
                """
                INSERT OR IGNORE INTO dialogs(user_id, peer_id, top_message_id, unread_count, updated_at)
                VALUES (?, ?, NULL, 0, ?)
                """,
                (user_id, peer_id, now_unix()),
            )
        return peer_id

    names = {int(row["id"]): f"{str(row['first_name'])} {str(row['last_name'])}".strip() for row in users}
    title = "Saved Messages" if user_id == other_user_id else names[other_user_id]
    now = now_unix()
    cursor = connection.execute(
        "INSERT INTO peers(kind, title, created_by_user_id, created_at) VALUES ('user', ?, ?, ?)",
        (title, user_id, now),
    )
    peer_id = int(cursor.lastrowid)
    connection.execute(
        "INSERT INTO direct_peer_users(peer_id, user_low_id, user_high_id) VALUES (?, ?, ?)",
        (peer_id, low_user_id, high_user_id),
    )
    for member_id in user_ids:
        connection.execute(
            """
            INSERT INTO peer_memberships(peer_id, user_id, role, joined_at)
            VALUES (?, ?, ?, ?)
            """,
            (peer_id, member_id, "owner" if member_id == user_id else "member", now),
        )
    if user_id == other_user_id:
        connection.execute(
            """
            INSERT OR IGNORE INTO dialogs(user_id, peer_id, top_message_id, unread_count, updated_at)
            VALUES (?, ?, NULL, 0, ?)
            """,
            (user_id, peer_id, now),
        )
    return peer_id


def resolve_direct_peer(connection: sqlite3.Connection, *, user_id: int, other_user_id: int) -> int | None:
    low_user_id = min(user_id, other_user_id)
    high_user_id = max(user_id, other_user_id)
    row = connection.execute(
        """
        SELECT peer_id FROM direct_peer_users
        WHERE user_low_id = ? AND user_high_id = ?
        """,
        (low_user_id, high_user_id),
    ).fetchone()
    return int(row["peer_id"]) if row is not None else None


def get_peer(connection: sqlite3.Connection, *, peer_id: int, user_id: int) -> dict[str, Any]:
    row = _require_active_membership(connection, peer_id, user_id)
    direct = connection.execute(
        "SELECT user_low_id, user_high_id FROM direct_peer_users WHERE peer_id = ?",
        (peer_id,),
    ).fetchone()
    result: dict[str, Any] = {
        "peer_id": int(row["id"]),
        "kind": str(row["kind"]),
        "title": str(row["title"]),
    }
    if direct is not None:
        low_user_id = int(direct["user_low_id"])
        high_user_id = int(direct["user_high_id"])
        result["direct_user_id"] = high_user_id if low_user_id == user_id else low_user_id
    return result


def _ensure_dialog(connection: sqlite3.Connection, user_id: int, peer_id: int, message_id: int | None, unread_delta: int) -> None:
    now = now_unix()
    connection.execute(
        """
        INSERT INTO dialogs(user_id, peer_id, top_message_id, unread_count, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id, peer_id) DO UPDATE SET
            top_message_id = excluded.top_message_id,
            unread_count = MAX(0, dialogs.unread_count + excluded.unread_count),
            updated_at = excluded.updated_at
        """,
        (user_id, peer_id, message_id, unread_delta, now),
    )


def create_group(
    connection: sqlite3.Connection, *, owner_user_id: int, title: str, member_user_ids: list[int]
) -> tuple[int, list[UpdateEnvelope]]:
    title = title.strip()
    if not title:
        raise MessagingError("CHAT_TITLE_EMPTY")
    unique_members = sorted(set([owner_user_id, *member_user_ids]))
    existing = connection.execute(
        f"SELECT id FROM users WHERE id IN ({','.join('?' for _ in unique_members)})",
        unique_members,
    ).fetchall()
    if len(existing) != len(unique_members):
        raise MessagingError("USER_ID_INVALID")
    now = now_unix()
    cursor = connection.execute(
        "INSERT INTO peers(kind, title, created_by_user_id, created_at) VALUES ('chat', ?, ?, ?)",
        (title, owner_user_id, now),
    )
    peer_id = int(cursor.lastrowid)
    emitted: list[UpdateEnvelope] = []
    for user_id in unique_members:
        role = "owner" if user_id == owner_user_id else "member"
        connection.execute(
            "INSERT INTO peer_memberships(peer_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (peer_id, user_id, role, now),
        )
        _ensure_dialog(connection, user_id, peer_id, None, 0)
        emitted.append(
            append_update(connection, user_id=user_id, kind="updateNewChat", payload={"chat_id": peer_id, "title": title})
        )
    return peer_id, emitted


def send_message(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    sender_user_id: int,
    body: str,
    client_random_id: str,
    reply_to_message_id: int | None = None,
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    _require_active_membership(connection, peer_id, sender_user_id)
    body = body.strip()
    if not body:
        raise MessagingError("MESSAGE_EMPTY")
    if len(body) > 4096:
        raise MessagingError("MESSAGE_TOO_LONG")
    if not client_random_id or len(client_random_id) > 128:
        raise MessagingError("RANDOM_ID_INVALID")

    existing = connection.execute(
        """
        SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
        FROM messages WHERE sender_user_id = ? AND client_random_id = ?
        """,
        (sender_user_id, client_random_id),
    ).fetchone()
    if existing is not None:
        return _message_row(existing), []

    now = now_unix()
    try:
        cursor = connection.execute(
            """
            INSERT INTO messages(peer_id, sender_user_id, client_random_id, body, reply_to_message_id, sent_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (peer_id, sender_user_id, client_random_id, body, reply_to_message_id, now),
        )
    except sqlite3.IntegrityError as exc:
        raise MessagingError("REPLY_MESSAGE_ID_INVALID") from exc
    message_id = int(cursor.lastrowid)
    row = connection.execute(
        "SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("Message disappeared after insertion")
    message = _message_row(row)

    members = connection.execute(
        "SELECT user_id FROM peer_memberships WHERE peer_id = ? AND left_at IS NULL", (peer_id,)
    ).fetchall()
    emitted: list[UpdateEnvelope] = []
    for member in members:
        recipient_user_id = int(member["user_id"])
        _ensure_dialog(connection, recipient_user_id, peer_id, message_id, 0 if recipient_user_id == sender_user_id else 1)
        emitted.append(
            append_update(
                connection,
                user_id=recipient_user_id,
                kind="updateNewMessage",
                payload={"message": message, "is_outgoing": recipient_user_id == sender_user_id},
            )
        )
    return message, emitted


def read_history(connection: sqlite3.Connection, *, peer_id: int, user_id: int, max_id: int) -> UpdateEnvelope | None:
    """Advance a member's inbox cursor and return its durable update, if changed."""

    _require_active_membership(connection, peer_id, user_id)
    dialog = connection.execute(
        "SELECT read_inbox_max_id FROM dialogs WHERE user_id = ? AND peer_id = ?",
        (user_id, peer_id),
    ).fetchone()
    if dialog is None:
        _ensure_dialog(connection, user_id, peer_id, None, 0)
        current_max_id = 0
    else:
        current_max_id = int(dialog["read_inbox_max_id"])
    effective_max_id = max(current_max_id, max(max_id, 0))
    if effective_max_id == current_max_id:
        return None
    unread_row = connection.execute(
        """
        SELECT COUNT(*) AS unread_count
        FROM messages
        WHERE peer_id = ? AND sender_user_id != ? AND deleted_at IS NULL AND id > ?
        """,
        (peer_id, user_id, effective_max_id),
    ).fetchone()
    unread_count = int(unread_row["unread_count"])
    connection.execute(
        """
        UPDATE dialogs
        SET read_inbox_max_id = ?, unread_count = ?, updated_at = ?
        WHERE user_id = ? AND peer_id = ?
        """,
        (effective_max_id, unread_count, now_unix(), user_id, peer_id),
    )
    return append_update(
        connection,
        user_id=user_id,
        kind="updateReadHistoryInbox",
        payload={"peer_id": peer_id, "max_id": effective_max_id, "still_unread_count": unread_count},
    )


def get_history(connection: sqlite3.Connection, *, peer_id: int, user_id: int, before_id: int | None, limit: int) -> list[dict[str, Any]]:
    _require_active_membership(connection, peer_id, user_id)
    if limit < 1 or limit > 100:
        raise MessagingError("LIMIT_INVALID")
    if before_id is None:
        rows = connection.execute(
            """
            SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
            FROM messages WHERE peer_id = ? AND deleted_at IS NULL
            ORDER BY id DESC LIMIT ?
            """,
            (peer_id, limit),
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
            FROM messages WHERE peer_id = ? AND id < ? AND deleted_at IS NULL
            ORDER BY id DESC LIMIT ?
            """,
            (peer_id, before_id, limit),
        ).fetchall()
    return [_message_row(row) for row in reversed(rows)]


def get_dialogs(connection: sqlite3.Connection, *, user_id: int, offset: int, limit: int) -> list[dict[str, Any]]:
    if offset < 0 or limit < 1 or limit > 100:
        raise MessagingError("OFFSET_OR_LIMIT_INVALID")
    rows = connection.execute(
        """
        SELECT d.peer_id, d.top_message_id, d.read_inbox_max_id, d.read_outbox_max_id,
               d.unread_count, d.pinned_order, d.draft_text, d.updated_at, p.kind, p.title,
               dpu.user_low_id, dpu.user_high_id
        FROM dialogs d
        JOIN peers p ON p.id = d.peer_id
        LEFT JOIN direct_peer_users dpu ON dpu.peer_id = d.peer_id
        WHERE d.user_id = ?
        ORDER BY d.pinned_order IS NULL ASC, d.pinned_order ASC, d.updated_at DESC, d.peer_id DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, limit, offset),
    ).fetchall()
    return [
        {
            "peer_id": int(row["peer_id"]),
            "kind": str(row["kind"]),
            "title": str(row["title"]),
            "top_message_id": int(row["top_message_id"]) if row["top_message_id"] is not None else None,
            "read_inbox_max_id": int(row["read_inbox_max_id"]),
            "read_outbox_max_id": int(row["read_outbox_max_id"]),
            "unread_count": int(row["unread_count"]),
            "direct_user_id": (
                int(row["user_high_id"])
                if row["user_low_id"] is not None and int(row["user_low_id"]) == user_id
                else int(row["user_low_id"])
                if row["user_low_id"] is not None
                else None
            ),
            "draft_text": row["draft_text"],
            "updated_at": int(row["updated_at"]),
        }
        for row in rows
    ]


def _message_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "peer_id": int(row["peer_id"]),
        "sender_user_id": int(row["sender_user_id"]),
        "body": str(row["body"]),
        "reply_to_message_id": int(row["reply_to_message_id"]) if row["reply_to_message_id"] is not None else None,
        "sent_at": int(row["sent_at"]),
        "edited_at": int(row["edited_at"]) if row["edited_at"] is not None else None,
        "deleted_at": int(row["deleted_at"]) if row["deleted_at"] is not None else None,
    }
