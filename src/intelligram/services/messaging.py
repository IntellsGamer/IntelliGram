from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import re
import secrets
import sqlite3
from typing import Any

from intelligram.database import now_unix
from intelligram.services.login_security import invalidate_codes_shared_by_owner
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


def create_user(
    connection: sqlite3.Connection,
    *,
    phone: str,
    first_name: str,
    last_name: str = "",
    username: str | None = None,
    verified: bool = False,
    is_service: bool = False,
) -> int:
    phone = phone.strip()
    first_name = first_name.strip()
    if not phone or not first_name:
        raise MessagingError("PHONE_OR_NAME_INVALID")
    now = now_unix()
    try:
        cursor = connection.execute(
            """
            INSERT INTO users(phone, username, first_name, last_name, verified, is_service, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                phone,
                username.strip().lstrip("@") if username else None,
                first_name,
                last_name.strip(),
                int(verified),
                int(is_service),
                now,
                now,
            ),
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


def _ensure_dialog(
    connection: sqlite3.Connection,
    user_id: int,
    peer_id: int,
    message_id: int | None,
    unread_delta: int,
    *,
    read_outbox_max_id: int = 0,
) -> None:
    now = now_unix()
    connection.execute(
        """
        INSERT INTO dialogs(user_id, peer_id, top_message_id, unread_count, read_outbox_max_id, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, peer_id) DO UPDATE SET
            top_message_id = excluded.top_message_id,
            unread_count = MAX(0, dialogs.unread_count + excluded.unread_count),
            read_outbox_max_id = MAX(dialogs.read_outbox_max_id, excluded.read_outbox_max_id),
            updated_at = excluded.updated_at
        """,
        (user_id, peer_id, message_id, unread_delta, read_outbox_max_id, now),
    )


def _require_chat_manager(connection: sqlite3.Connection, *, chat_id: int, user_id: int) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT p.id, p.title, p.about, pm.role
        FROM peers p
        JOIN peer_memberships pm ON pm.peer_id = p.id
        WHERE p.id = ? AND p.kind = 'chat' AND pm.user_id = ? AND pm.left_at IS NULL
        """,
        (chat_id, user_id),
    ).fetchone()
    if row is None:
        raise MessagingError("CHAT_ID_INVALID")
    if str(row["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    return row


def _active_chat_member_ids(connection: sqlite3.Connection, *, chat_id: int) -> list[int]:
    return [
        int(row["user_id"])
        for row in connection.execute(
            "SELECT user_id FROM peer_memberships WHERE peer_id = ? AND left_at IS NULL ORDER BY user_id",
            (chat_id,),
        ).fetchall()
    ]


def add_chat_user(connection: sqlite3.Connection, *, chat_id: int, actor_user_id: int, added_user_id: int) -> list[UpdateEnvelope]:
    _require_chat_manager(connection, chat_id=chat_id, user_id=actor_user_id)
    user = connection.execute("SELECT id FROM users WHERE id = ?", (added_user_id,)).fetchone()
    if user is None:
        raise MessagingError("USER_ID_INVALID")
    existing = connection.execute(
        "SELECT left_at FROM peer_memberships WHERE peer_id = ? AND user_id = ?",
        (chat_id, added_user_id),
    ).fetchone()
    if existing is not None and existing["left_at"] is None:
        raise MessagingError("USER_ALREADY_PARTICIPANT")
    now = now_unix()
    if existing is None:
        connection.execute(
            "INSERT INTO peer_memberships(peer_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
            (chat_id, added_user_id, now),
        )
    else:
        connection.execute(
            "UPDATE peer_memberships SET role = 'member', joined_at = ?, left_at = NULL WHERE peer_id = ? AND user_id = ?",
            (now, chat_id, added_user_id),
        )
    _ensure_dialog(connection, added_user_id, chat_id, None, 0)
    title_row = connection.execute("SELECT title FROM peers WHERE id = ?", (chat_id,)).fetchone()
    title = str(title_row["title"]) if title_row is not None else ""
    emitted: list[UpdateEnvelope] = []
    for member_id in _active_chat_member_ids(connection, chat_id=chat_id):
        if member_id == added_user_id:
            emitted.append(append_update(connection, user_id=member_id, kind="updateNewChat", payload={"chat_id": chat_id, "title": title}))
        emitted.append(append_update(connection, user_id=member_id, kind="updateChatParticipants", payload={"chat_id": chat_id}))
    return emitted


def delete_chat_user(connection: sqlite3.Connection, *, chat_id: int, actor_user_id: int, deleted_user_id: int) -> list[UpdateEnvelope]:
    if actor_user_id != deleted_user_id:
        _require_chat_manager(connection, chat_id=chat_id, user_id=actor_user_id)
    member = connection.execute(
        "SELECT role FROM peer_memberships WHERE peer_id = ? AND user_id = ? AND left_at IS NULL",
        (chat_id, deleted_user_id),
    ).fetchone()
    if member is None:
        raise MessagingError("USER_NOT_PARTICIPANT")
    if str(member["role"]) == "owner":
        raise MessagingError("USER_CREATOR")
    connection.execute(
        "UPDATE peer_memberships SET left_at = ? WHERE peer_id = ? AND user_id = ?",
        (now_unix(), chat_id, deleted_user_id),
    )
    connection.execute("DELETE FROM dialogs WHERE user_id = ? AND peer_id = ?", (deleted_user_id, chat_id))
    return [
        append_update(connection, user_id=member_id, kind="updateChatParticipants", payload={"chat_id": chat_id})
        for member_id in _active_chat_member_ids(connection, chat_id=chat_id)
    ]


def edit_chat_title(connection: sqlite3.Connection, *, chat_id: int, actor_user_id: int, title: str) -> list[UpdateEnvelope]:
    _require_chat_manager(connection, chat_id=chat_id, user_id=actor_user_id)
    title = title.strip()
    if not title:
        raise MessagingError("CHAT_TITLE_EMPTY")
    connection.execute("UPDATE peers SET title = ? WHERE id = ? AND kind = 'chat'", (title, chat_id))
    return [
        append_update(connection, user_id=member_id, kind="updateChatTitle", payload={"chat_id": chat_id, "title": title})
        for member_id in _active_chat_member_ids(connection, chat_id=chat_id)
    ]


def edit_chat_about(connection: sqlite3.Connection, *, chat_id: int, actor_user_id: int, about: str) -> None:
    membership = _require_active_membership(connection, chat_id, actor_user_id)
    if str(membership["kind"]) not in {"chat", "channel"}:
        raise MessagingError("PEER_ID_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    if len(about) > 255:
        raise MessagingError("CHAT_ABOUT_TOO_LONG")
    connection.execute(
        "UPDATE peers SET about = ? WHERE id = ? AND kind IN ('chat', 'channel')",
        (about, chat_id),
    )


def edit_peer_default_banned_rights(
    connection: sqlite3.Connection, *, peer_id: int, actor_user_id: int, flags: int
) -> list[UpdateEnvelope]:
    if flags < 0 or flags > 0xFFFFFFFF:
        raise MessagingError("BANNED_RIGHTS_INVALID")
    membership = _require_active_membership(connection, peer_id, actor_user_id)
    if str(membership["kind"]) not in {"chat", "channel"}:
        raise MessagingError("PEER_ID_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    connection.execute(
        """
        INSERT INTO peer_permissions(peer_id, default_banned_rights_flags, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(peer_id) DO UPDATE SET
            default_banned_rights_flags = excluded.default_banned_rights_flags,
            updated_at = excluded.updated_at
        """,
        (peer_id, flags, now_unix()),
    )
    return [
        append_update(
            connection,
            user_id=member_id,
            kind="updateChatDefaultBannedRights",
            payload={"peer_id": peer_id, "flags": flags},
        )
        for member_id in _active_member_ids(connection, peer_id=peer_id)
    ]


def migrate_chat_to_channel(
    connection: sqlite3.Connection, *, chat_id: int, actor_user_id: int
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    """Convert an owner-managed legacy chat into a durable megagroup channel.

    IntelliGram retains the peer ID so existing memberships, dialogs, and message
    history remain stable while Web K transitions from `PeerChat` to `PeerChannel`.
    """

    _require_chat_manager(connection, chat_id=chat_id, user_id=actor_user_id)
    row = connection.execute(
        "SELECT id, title, about, created_at, created_by_user_id FROM peers WHERE id = ? AND kind = 'chat'",
        (chat_id,),
    ).fetchone()
    if row is None:
        raise MessagingError("CHAT_ID_INVALID")
    connection.execute("UPDATE peers SET kind = 'channel' WHERE id = ?", (chat_id,))
    connection.execute("INSERT OR IGNORE INTO channel_settings(peer_id, slowmode_seconds) VALUES (?, 0)", (chat_id,))
    connection.execute(
        "INSERT OR IGNORE INTO channel_reaction_settings(peer_id, mode, allow_custom, emoticons_json, updated_at) VALUES (?, 'none', 0, '[]', ?)",
        (chat_id, now_unix()),
    )
    details = get_channel_details(connection, channel_id=chat_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": chat_id})
        for member_id in _active_member_ids(connection, peer_id=chat_id)
    ]
    return details, emitted


def get_channel_details(connection: sqlite3.Connection, *, channel_id: int, user_id: int) -> dict[str, Any]:
    membership = _require_active_membership(connection, channel_id, user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    row = connection.execute(
        """
        SELECT p.id, p.title, p.about, p.username, p.created_at, p.created_by_user_id,
               COUNT(pm.user_id) AS participants_count,
               SUM(CASE WHEN pm.role IN ('owner', 'admin') THEN 1 ELSE 0 END) AS admins_count,
               COALESCE(cs.slowmode_seconds, 0) AS slowmode_seconds,
               COALESCE(cs.noforwards, 0) AS noforwards,
               COALESCE(cs.join_request_enabled, 0) AS join_request_enabled,
               COALESCE(cs.is_broadcast, 0) AS is_broadcast,
               COALESCE(cs.signatures_enabled, 0) AS signatures_enabled,
               COALESCE(crs.mode, 'none') AS reaction_mode,
               COALESCE(crs.allow_custom, 0) AS reaction_allow_custom,
               COALESCE(crs.emoticons_json, '[]') AS reaction_emoticons_json
        FROM peers p
        JOIN peer_memberships pm ON pm.peer_id = p.id AND pm.left_at IS NULL
        LEFT JOIN channel_settings cs ON cs.peer_id = p.id
        LEFT JOIN channel_reaction_settings crs ON crs.peer_id = p.id
        WHERE p.id = ? AND p.kind = 'channel'
        GROUP BY p.id, p.title, p.about, p.username, p.created_at, p.created_by_user_id, cs.slowmode_seconds, cs.noforwards,
                 cs.join_request_enabled, cs.is_broadcast, cs.signatures_enabled, crs.mode, crs.allow_custom, crs.emoticons_json
        """,
        (channel_id,),
    ).fetchone()
    if row is None:
        raise MessagingError("CHANNEL_INVALID")
    details = {
        key: (
            int(row[key])
            if key in {"id", "created_at", "created_by_user_id", "participants_count", "admins_count", "slowmode_seconds", "noforwards", "join_request_enabled", "is_broadcast", "signatures_enabled", "reaction_allow_custom"}
            else row[key]
        )
        for key in row.keys()
    }
    try:
        details["reaction_emoticons"] = [str(item) for item in json.loads(str(details.pop("reaction_emoticons_json")))]
    except (TypeError, ValueError, json.JSONDecodeError):
        details["reaction_emoticons"] = []
    exported_invite = connection.execute(
        """
        SELECT token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
               usage, request_needed, permanent, revoked
        FROM exported_invites
        WHERE peer_id = ? AND permanent = 1 AND revoked = 0
        ORDER BY created_at ASC LIMIT 1
        """,
        (channel_id,),
    ).fetchone()
    if exported_invite is not None:
        details["exported_invite"] = {key: exported_invite[key] for key in exported_invite.keys()}
    else:
        details["exported_invite"] = None
    return details


_CHANNEL_USERNAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{4,31}")


def check_channel_username(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int, username: str
) -> bool:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if not _CHANNEL_USERNAME_RE.fullmatch(username):
        return False
    existing = connection.execute(
        "SELECT id FROM peers WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()
    return existing is None or int(existing["id"]) == channel_id


def update_channel_username(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int, username: str
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    normalized_username = username.strip()
    if normalized_username and not _CHANNEL_USERNAME_RE.fullmatch(normalized_username):
        raise MessagingError("USERNAME_INVALID")
    if normalized_username:
        existing = connection.execute(
            "SELECT id FROM peers WHERE username = ? COLLATE NOCASE", (normalized_username,)
        ).fetchone()
        if existing is not None and int(existing["id"]) != channel_id:
            raise MessagingError("USERNAME_OCCUPIED")
    try:
        connection.execute(
            "UPDATE peers SET username = ? WHERE id = ? AND kind = 'channel'",
            (normalized_username or None, channel_id),
        )
    except sqlite3.IntegrityError as exc:
        raise MessagingError("USERNAME_OCCUPIED") from exc
    details = get_channel_details(connection, channel_id=channel_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]
    return details, emitted


def deactivate_all_channel_usernames(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    return update_channel_username(
        connection, channel_id=channel_id, actor_user_id=actor_user_id, username=""
    )


def set_channel_noforwards(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int, enabled: bool
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    connection.execute(
        "INSERT INTO channel_settings(peer_id, noforwards) VALUES (?, ?) ON CONFLICT(peer_id) DO UPDATE SET noforwards = excluded.noforwards",
        (channel_id, int(enabled)),
    )
    details = get_channel_details(connection, channel_id=channel_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]
    return details, emitted


def set_channel_join_request(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int, enabled: bool
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    connection.execute(
        "INSERT INTO channel_settings(peer_id, join_request_enabled) VALUES (?, ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET join_request_enabled = excluded.join_request_enabled",
        (channel_id, int(enabled)),
    )
    details = get_channel_details(connection, channel_id=channel_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]
    return details, emitted


def set_channel_signatures(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int, enabled: bool
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    connection.execute(
        "INSERT INTO channel_settings(peer_id, signatures_enabled) VALUES (?, ?) "
        "ON CONFLICT(peer_id) DO UPDATE SET signatures_enabled = excluded.signatures_enabled",
        (channel_id, int(enabled)),
    )
    details = get_channel_details(connection, channel_id=channel_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]
    return details, emitted


def set_channel_slow_mode(
    connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int, seconds: int
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    if seconds not in {0, 5, 10, 30, 60, 300, 900, 3600}:
        raise MessagingError("SLOWMODE_INVALID")
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    connection.execute(
        "INSERT INTO channel_settings(peer_id, slowmode_seconds) VALUES (?, ?) ON CONFLICT(peer_id) DO UPDATE SET slowmode_seconds = excluded.slowmode_seconds",
        (channel_id, seconds),
    )
    details = get_channel_details(connection, channel_id=channel_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]
    return details, emitted


def export_chat_invite(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    actor_user_id: int,
    expire_date: int | None,
    usage_limit: int | None,
    request_needed: bool,
    title: str | None,
    public_link_base_url: str = "https://intelligram.local",
) -> dict[str, Any]:
    expire_date = expire_date or None
    usage_limit = usage_limit or None
    membership = _require_active_membership(connection, peer_id, actor_user_id)
    if str(membership["kind"]) not in {"chat", "channel"}:
        raise MessagingError("PEER_ID_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    now = now_unix()
    if expire_date is not None and expire_date <= now:
        raise MessagingError("INVITE_EXPIRE_INVALID")
    if usage_limit is not None and not 0 < usage_limit <= 100000:
        raise MessagingError("INVITE_USAGE_LIMIT_INVALID")
    normalized_title = (title or "").strip() or None
    if normalized_title is not None and len(normalized_title) > 64:
        raise MessagingError("INVITE_TITLE_INVALID")
    is_permanent = not any((expire_date, usage_limit, request_needed, normalized_title))
    if is_permanent:
        existing = connection.execute(
            """
            SELECT token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
                   usage, request_needed, permanent, revoked
            FROM exported_invites
            WHERE peer_id = ? AND admin_user_id = ? AND permanent = 1 AND revoked = 0
            ORDER BY created_at ASC LIMIT 1
            """,
            (peer_id, actor_user_id),
        ).fetchone()
        if existing is not None:
            return {key: existing[key] for key in existing.keys()}
    token = secrets.token_urlsafe(18).replace("-", "").replace("_", "")
    link = f"{public_link_base_url.rstrip('/')}/+{token}"
    connection.execute(
        """
        INSERT INTO exported_invites(
            token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
            usage, request_needed, permanent, revoked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)
        """,
        (
            token,
            peer_id,
            actor_user_id,
            link,
            normalized_title,
            now,
            expire_date,
            usage_limit,
            int(request_needed),
            int(is_permanent),
        ),
    )
    return {
        "token": token,
        "peer_id": peer_id,
        "admin_user_id": actor_user_id,
        "link": link,
        "title": normalized_title,
        "created_at": now,
        "expire_date": expire_date,
        "usage_limit": usage_limit,
        "usage": 0,
        "request_needed": int(request_needed),
        "permanent": int(is_permanent),
        "revoked": 0,
    }


def delete_exported_chat_invite(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    actor_user_id: int,
    link: str,
) -> None:
    membership = _require_active_membership(connection, peer_id, actor_user_id)
    if str(membership["kind"]) not in {"chat", "channel"}:
        raise MessagingError("PEER_ID_INVALID")
    invite = connection.execute(
        "SELECT token, admin_user_id, revoked FROM exported_invites WHERE peer_id = ? AND link = ?",
        (peer_id, link),
    ).fetchone()
    if invite is None:
        raise MessagingError("INVITE_HASH_INVALID")
    if int(invite["admin_user_id"]) != actor_user_id and str(membership["role"]) != "owner":
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    if not bool(int(invite["revoked"])):
        raise MessagingError("INVITE_HASH_INVALID")
    connection.execute("DELETE FROM exported_invites WHERE token = ?", (str(invite["token"]),))


def delete_revoked_exported_chat_invites(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    actor_user_id: int,
    admin_user_id: int,
) -> int:
    membership = _require_active_membership(connection, peer_id, actor_user_id)
    if str(membership["kind"]) not in {"chat", "channel"}:
        raise MessagingError("PEER_ID_INVALID")
    if actor_user_id != admin_user_id and str(membership["role"]) != "owner":
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    cursor = connection.execute(
        "DELETE FROM exported_invites WHERE peer_id = ? AND admin_user_id = ? AND revoked = 1",
        (peer_id, admin_user_id),
    )
    return int(cursor.rowcount)


def edit_exported_chat_invite(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    actor_user_id: int,
    link: str,
    revoked: bool,
    expire_date: int | None,
    expire_date_provided: bool,
    usage_limit: int | None,
    usage_limit_provided: bool,
    request_needed: bool | None,
    title: str | None,
    title_provided: bool,
    public_link_base_url: str = "https://intelligram.local",
) -> dict[str, Any]:
    membership = _require_active_membership(connection, peer_id, actor_user_id)
    if str(membership["kind"]) not in {"chat", "channel"}:
        raise MessagingError("PEER_ID_INVALID")
    invite = connection.execute(
        """
        SELECT token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
               usage, request_needed, permanent, revoked
        FROM exported_invites
        WHERE peer_id = ? AND link = ?
        """,
        (peer_id, link),
    ).fetchone()
    if invite is None:
        raise MessagingError("INVITE_HASH_INVALID")
    if int(invite["admin_user_id"]) != actor_user_id and str(membership["role"]) != "owner":
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    if bool(int(invite["revoked"])):
        raise MessagingError("INVITE_HASH_EXPIRED")

    replacement: dict[str, Any] | None = None
    if revoked:
        connection.execute("UPDATE exported_invites SET revoked = 1 WHERE token = ?", (str(invite["token"]),))
        if bool(int(invite["permanent"])):
            replacement = export_chat_invite(
                connection,
                peer_id=peer_id,
                actor_user_id=actor_user_id,
                expire_date=None,
                usage_limit=None,
                request_needed=False,
                title=None,
                public_link_base_url=public_link_base_url,
            )
    else:
        normalized_expire_date = expire_date or None
        normalized_usage_limit = usage_limit or None
        if expire_date_provided and normalized_expire_date is not None and normalized_expire_date <= now_unix():
            raise MessagingError("INVITE_EXPIRE_INVALID")
        if usage_limit_provided and normalized_usage_limit is not None and not 0 < normalized_usage_limit <= 100000:
            raise MessagingError("INVITE_USAGE_LIMIT_INVALID")
        normalized_title = (title or "").strip() or None
        if title_provided and normalized_title is not None and len(normalized_title) > 64:
            raise MessagingError("INVITE_TITLE_INVALID")
        assignments: list[str] = []
        values: list[object] = []
        if expire_date_provided:
            assignments.append("expire_date = ?")
            values.append(normalized_expire_date)
        if usage_limit_provided:
            assignments.append("usage_limit = ?")
            values.append(normalized_usage_limit)
        if request_needed is not None:
            assignments.append("request_needed = ?")
            values.append(int(request_needed))
        if title_provided:
            assignments.append("title = ?")
            values.append(normalized_title)
        if assignments:
            values.append(str(invite["token"]))
            connection.execute(
                f"UPDATE exported_invites SET {', '.join(assignments)} WHERE token = ?",
                values,
            )

    updated = connection.execute(
        """
        SELECT token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
               usage, request_needed, permanent, revoked
        FROM exported_invites
        WHERE token = ?
        """,
        (str(invite["token"]),),
    ).fetchone()
    if updated is None:
        raise RuntimeError("Invite disappeared after update")
    return {
        "invite": {key: updated[key] for key in updated.keys()},
        "new_invite": replacement,
    }


def list_exported_chat_invites(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    actor_user_id: int,
    admin_user_id: int,
    revoked: bool,
    limit: int,
) -> list[dict[str, Any]]:
    _require_active_membership(connection, peer_id, actor_user_id)
    if limit < 1 or limit > 100:
        raise MessagingError("INVITE_LIMIT_INVALID")
    rows = connection.execute(
        """
        SELECT token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
               usage, request_needed, permanent, revoked
        FROM exported_invites
        WHERE peer_id = ? AND admin_user_id = ? AND revoked = ?
        ORDER BY permanent DESC, created_at DESC
        LIMIT ?
        """,
        (peer_id, admin_user_id, int(revoked), limit),
    ).fetchall()
    return [{key: row[key] for key in row.keys()} for row in rows]


def set_channel_reactions(
    connection: sqlite3.Connection,
    *,
    channel_id: int,
    actor_user_id: int,
    mode: str,
    allow_custom: bool,
    emoticons: list[str],
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    if mode not in {"all", "some", "none"}:
        raise MessagingError("REACTIONS_INVALID")
    normalized_emoticons = list(dict.fromkeys(item.strip() for item in emoticons if item.strip()))
    if mode == "some" and not normalized_emoticons:
        mode = "none"
    if len(normalized_emoticons) > 32 or any(len(item) > 32 for item in normalized_emoticons):
        raise MessagingError("REACTIONS_INVALID")
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    connection.execute(
        """
        INSERT INTO channel_reaction_settings(peer_id, mode, allow_custom, emoticons_json, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(peer_id) DO UPDATE SET
            mode = excluded.mode,
            allow_custom = excluded.allow_custom,
            emoticons_json = excluded.emoticons_json,
            updated_at = excluded.updated_at
        """,
        (channel_id, mode, int(allow_custom if mode == "all" else False), json.dumps(normalized_emoticons if mode == "some" else []), now_unix()),
    )
    details = get_channel_details(connection, channel_id=channel_id, user_id=actor_user_id)
    emitted = [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]
    return details, emitted


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


def ensure_permanent_exported_invite(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    actor_user_id: int,
    public_link_base_url: str = "https://intelligram.local",
) -> dict[str, Any]:
    """Return the durable primary invite Web K shows in the invite-link tab."""

    return export_chat_invite(
        connection,
        peer_id=peer_id,
        actor_user_id=actor_user_id,
        expire_date=None,
        usage_limit=None,
        request_needed=False,
        title=None,
        public_link_base_url=public_link_base_url,
    )


def create_channel(
    connection: sqlite3.Connection,
    *,
    owner_user_id: int,
    title: str,
    about: str = "",
    broadcast: bool = False,
    megagroup: bool = False,
    member_user_ids: list[int] | None = None,
    public_link_base_url: str = "https://intelligram.local",
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    title = title.strip()
    if not title:
        raise MessagingError("CHAT_TITLE_EMPTY")
    if len(about) > 255:
        raise MessagingError("CHAT_ABOUT_TOO_LONG")
    is_broadcast = bool(broadcast) and not megagroup
    unique_members = sorted(set([owner_user_id, *(member_user_ids or [])]))
    existing = connection.execute(
        f"SELECT id FROM users WHERE id IN ({','.join('?' for _ in unique_members)})",
        unique_members,
    ).fetchall()
    if len(existing) != len(unique_members):
        raise MessagingError("USER_ID_INVALID")
    now = now_unix()
    cursor = connection.execute(
        "INSERT INTO peers(kind, title, about, created_by_user_id, created_at) VALUES ('channel', ?, ?, ?, ?)",
        (title, about, owner_user_id, now),
    )
    peer_id = int(cursor.lastrowid)
    connection.execute(
        "INSERT INTO channel_settings(peer_id, slowmode_seconds, is_broadcast) VALUES (?, 0, ?)",
        (peer_id, int(is_broadcast)),
    )
    connection.execute(
        "INSERT OR IGNORE INTO channel_reaction_settings(peer_id, mode, allow_custom, emoticons_json, updated_at) VALUES (?, 'none', 0, '[]', ?)",
        (peer_id, now),
    )
    emitted: list[UpdateEnvelope] = []
    for user_id in unique_members:
        role = "owner" if user_id == owner_user_id else "member"
        connection.execute(
            "INSERT INTO peer_memberships(peer_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (peer_id, user_id, role, now),
        )
        _ensure_dialog(connection, user_id, peer_id, None, 0)
        emitted.append(
            append_update(connection, user_id=user_id, kind="updateChannel", payload={"channel_id": peer_id})
        )
    ensure_permanent_exported_invite(
        connection,
        peer_id=peer_id,
        actor_user_id=owner_user_id,
        public_link_base_url=public_link_base_url,
    )
    details = get_channel_details(connection, channel_id=peer_id, user_id=owner_user_id)
    return details, emitted


def invite_to_channel(
    connection: sqlite3.Connection,
    *,
    channel_id: int,
    actor_user_id: int,
    invited_user_ids: list[int],
) -> list[UpdateEnvelope]:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) not in {"owner", "admin"}:
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    emitted: list[UpdateEnvelope] = []
    for invited_user_id in invited_user_ids:
        user = connection.execute("SELECT id FROM users WHERE id = ?", (invited_user_id,)).fetchone()
        if user is None:
            raise MessagingError("USER_ID_INVALID")
        existing = connection.execute(
            "SELECT left_at FROM peer_memberships WHERE peer_id = ? AND user_id = ?",
            (channel_id, invited_user_id),
        ).fetchone()
        now = now_unix()
        if existing is not None and existing["left_at"] is None:
            continue
        if existing is None:
            connection.execute(
                "INSERT INTO peer_memberships(peer_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                (channel_id, invited_user_id, now),
            )
        else:
            connection.execute(
                "UPDATE peer_memberships SET role = 'member', joined_at = ?, left_at = NULL WHERE peer_id = ? AND user_id = ?",
                (now, channel_id, invited_user_id),
            )
        _ensure_dialog(connection, invited_user_id, channel_id, None, 0)
        emitted.append(
            append_update(connection, user_id=invited_user_id, kind="updateChannel", payload={"channel_id": channel_id})
        )
    for member_id in _active_member_ids(connection, peer_id=channel_id):
        emitted.append(
            append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        )
    return emitted


def join_channel(connection: sqlite3.Connection, *, channel_id: int, user_id: int) -> list[UpdateEnvelope]:
    peer = connection.execute("SELECT kind FROM peers WHERE id = ?", (channel_id,)).fetchone()
    if peer is None or str(peer["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    existing = connection.execute(
        "SELECT left_at FROM peer_memberships WHERE peer_id = ? AND user_id = ?",
        (channel_id, user_id),
    ).fetchone()
    now = now_unix()
    if existing is not None and existing["left_at"] is None:
        return []
    if existing is None:
        connection.execute(
            "INSERT INTO peer_memberships(peer_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
            (channel_id, user_id, now),
        )
    else:
        connection.execute(
            "UPDATE peer_memberships SET left_at = NULL, joined_at = ? WHERE peer_id = ? AND user_id = ?",
            (now, channel_id, user_id),
        )
    _ensure_dialog(connection, user_id, channel_id, None, 0)
    return [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in _active_member_ids(connection, peer_id=channel_id)
    ]


def leave_channel(connection: sqlite3.Connection, *, channel_id: int, user_id: int) -> list[UpdateEnvelope]:
    membership = _require_active_membership(connection, channel_id, user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) == "owner":
        raise MessagingError("USER_CREATOR")
    connection.execute(
        "UPDATE peer_memberships SET left_at = ? WHERE peer_id = ? AND user_id = ?",
        (now_unix(), channel_id, user_id),
    )
    connection.execute("DELETE FROM dialogs WHERE user_id = ? AND peer_id = ?", (user_id, channel_id))
    remaining = _active_member_ids(connection, peer_id=channel_id)
    return [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in [*remaining, user_id]
    ]


def delete_channel(connection: sqlite3.Connection, *, channel_id: int, actor_user_id: int) -> list[UpdateEnvelope]:
    membership = _require_active_membership(connection, channel_id, actor_user_id)
    if str(membership["kind"]) != "channel":
        raise MessagingError("CHANNEL_INVALID")
    if str(membership["role"]) != "owner":
        raise MessagingError("CHAT_ADMIN_REQUIRED")
    member_ids = _active_member_ids(connection, peer_id=channel_id)
    now = now_unix()
    connection.execute("UPDATE peer_memberships SET left_at = ? WHERE peer_id = ? AND left_at IS NULL", (now, channel_id))
    connection.execute("DELETE FROM dialogs WHERE peer_id = ?", (channel_id,))
    return [
        append_update(connection, user_id=member_id, kind="updateChannel", payload={"channel_id": channel_id})
        for member_id in member_ids
    ]


def lookup_exported_invite(connection: sqlite3.Connection, *, link_or_hash: str) -> dict[str, Any] | None:
    token = link_or_hash.rsplit("+", 1)[-1].strip().lstrip("/")
    row = connection.execute(
        """
        SELECT token, peer_id, admin_user_id, link, title, created_at, expire_date, usage_limit,
               usage, request_needed, permanent, revoked
        FROM exported_invites
        WHERE token = ? OR link = ?
        """,
        (token, link_or_hash),
    ).fetchone()
    return {key: row[key] for key in row.keys()} if row is not None else None


def send_message(
    connection: sqlite3.Connection,
    *,
    peer_id: int,
    sender_user_id: int,
    body: str,
    client_random_id: str,
    reply_to_message_id: int | None = None,
    media: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    _require_active_membership(connection, peer_id, sender_user_id)
    body = (body or "").strip()
    if not body and media is None:
        raise MessagingError("MESSAGE_EMPTY")
    if len(body) > 4096:
        raise MessagingError("MESSAGE_TOO_LONG")
    if not client_random_id or len(client_random_id) > 128:
        raise MessagingError("RANDOM_ID_INVALID")
    if reply_to_message_id is not None:
        reply_target = connection.execute(
            "SELECT id FROM messages WHERE id = ? AND peer_id = ? AND deleted_at IS NULL",
            (reply_to_message_id, peer_id),
        ).fetchone()
        if reply_target is None:
            raise MessagingError("REPLY_MESSAGE_ID_INVALID")

    existing = connection.execute(
        """
        SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
        FROM messages WHERE sender_user_id = ? AND client_random_id = ?
        """,
        (sender_user_id, client_random_id),
    ).fetchone()
    if existing is not None:
        return _message_row(existing, connection), []

    # Match only active challenge-bound digests, never persisted plaintext
    # codes. This executes in the caller's message transaction so a code is
    # unusable as soon as its owner posts it in any ordinary IntelliGram peer.
    invalidate_codes_shared_by_owner(
        connection,
        owner_user_id=sender_user_id,
        body=body,
    )

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
    if media is not None:
        _store_message_media(connection, message_id=message_id, media=media)
    row = connection.execute(
        "SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("Message disappeared after insertion")
    message = _message_row(row, connection)

    members = connection.execute(
        "SELECT user_id FROM peer_memberships WHERE peer_id = ? AND left_at IS NULL", (peer_id,)
    ).fetchall()
    emitted: list[UpdateEnvelope] = []
    for member in members:
        recipient_user_id = int(member["user_id"])
        _ensure_dialog(
            connection,
            recipient_user_id,
            peer_id,
            message_id,
            0 if recipient_user_id == sender_user_id else 1,
            read_outbox_max_id=message_id if recipient_user_id == sender_user_id else 0,
        )
        payload = {"message": message, "is_outgoing": recipient_user_id == sender_user_id}
        # A first post-refresh `updates.getDifference` can supersede the
        # immediate RPC result while Web K is synchronizing. Persist the
        # sender-only random-id mapping with the durable envelope so that
        # difference replay can still finalize the optimistic message.
        if recipient_user_id == sender_user_id:
            payload["client_random_id"] = client_random_id
        emitted.append(
            append_update(
                connection,
                user_id=recipient_user_id,
                kind="updateNewMessage",
                payload=payload,
            )
        )
    return message, emitted


def forward_messages(
    connection: sqlite3.Connection,
    *,
    source_peer_id: int,
    destination_peer_id: int,
    actor_user_id: int,
    message_ids: list[int],
    random_ids: list[int],
) -> tuple[list[dict[str, Any]], list[UpdateEnvelope]]:
    _require_active_membership(connection, source_peer_id, actor_user_id)
    _require_active_membership(connection, destination_peer_id, actor_user_id)
    if not message_ids or len(message_ids) != len(random_ids):
        raise MessagingError("INPUT_REQUEST_INVALID")
    source_rows = connection.execute(
        f"""
        SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
        FROM messages WHERE peer_id = ? AND id IN ({','.join('?' for _ in message_ids)}) AND deleted_at IS NULL
        """,
        (source_peer_id, *message_ids),
    ).fetchall()
    messages_by_id = {int(row["id"]): _message_row(row, connection) for row in source_rows}
    if len(messages_by_id) != len(set(message_ids)):
        raise MessagingError("MESSAGE_ID_INVALID")
    forwarded: list[dict[str, Any]] = []
    emitted: list[UpdateEnvelope] = []
    for message_id, random_id in zip(message_ids, random_ids, strict=True):
        source = messages_by_id[message_id]
        stored, updates = send_message(
            connection,
            peer_id=destination_peer_id,
            sender_user_id=actor_user_id,
            body=str(source["body"]),
            client_random_id=f"forward:{random_id}",
        )
        forwarded.append(stored)
        emitted.extend(updates)
    return forwarded, emitted


def edit_message(
    connection: sqlite3.Connection, *, peer_id: int, message_id: int, actor_user_id: int, body: str
) -> tuple[dict[str, Any], list[UpdateEnvelope]]:
    _require_active_membership(connection, peer_id, actor_user_id)
    body = body.strip()
    if not body:
        raise MessagingError("MESSAGE_EMPTY")
    if len(body) > 4096:
        raise MessagingError("MESSAGE_TOO_LONG")
    row = connection.execute(
        """
        SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
        FROM messages WHERE id = ? AND peer_id = ? AND deleted_at IS NULL
        """,
        (message_id, peer_id),
    ).fetchone()
    if row is None:
        raise MessagingError("MESSAGE_ID_INVALID")
    if int(row["sender_user_id"]) != actor_user_id:
        raise MessagingError("MESSAGE_AUTHOR_REQUIRED")
    now = now_unix()
    connection.execute("UPDATE messages SET body = ?, edited_at = ? WHERE id = ?", (body, now, message_id))
    updated = connection.execute(
        """
        SELECT id, peer_id, sender_user_id, body, reply_to_message_id, sent_at, edited_at, deleted_at
        FROM messages WHERE id = ?
        """,
        (message_id,),
    ).fetchone()
    if updated is None:
        raise RuntimeError("Edited message disappeared")
    message = _message_row(updated, connection)
    emitted = [
        append_update(
            connection,
            user_id=member_id,
            kind="updateEditMessage",
            payload={"message": message, "is_outgoing": member_id == actor_user_id},
        )
        for member_id in _active_member_ids(connection, peer_id=peer_id)
    ]
    return message, emitted


def delete_messages(
    connection: sqlite3.Connection, *, message_ids: list[int], actor_user_id: int, revoke: bool
) -> tuple[list[int], list[UpdateEnvelope]]:
    if not message_ids:
        raise MessagingError("MESSAGE_IDS_EMPTY")
    unique_ids = sorted({message_id for message_id in message_ids if message_id > 0})
    if not unique_ids:
        raise MessagingError("MESSAGE_IDS_EMPTY")
    rows = connection.execute(
        f"""
        SELECT id, peer_id, sender_user_id, deleted_at
        FROM messages WHERE id IN ({','.join('?' for _ in unique_ids)})
        """,
        unique_ids,
    ).fetchall()
    deleted: list[int] = []
    emitted: list[UpdateEnvelope] = []
    now = now_unix()
    for row in rows:
        message_id = int(row["id"])
        peer_id = int(row["peer_id"])
        if row["deleted_at"] is not None:
            continue
        membership = _require_active_membership(connection, peer_id, actor_user_id)
        authorized = int(row["sender_user_id"]) == actor_user_id
        if str(membership["kind"]) == "chat":
            role = connection.execute(
                "SELECT role FROM peer_memberships WHERE peer_id = ? AND user_id = ? AND left_at IS NULL",
                (peer_id, actor_user_id),
            ).fetchone()
            authorized = authorized or (role is not None and str(role["role"]) in {"owner", "admin"})
        if not authorized:
            raise MessagingError("MESSAGE_DELETE_FORBIDDEN")
        connection.execute("UPDATE messages SET deleted_at = ? WHERE id = ?", (now, message_id))
        deleted.append(message_id)
        recipients = _active_member_ids(connection, peer_id=peer_id) if revoke else [actor_user_id]
        for member_id in recipients:
            emitted.append(
                append_update(
                    connection,
                    user_id=member_id,
                    kind="updateDeleteMessages",
                    payload={"message_ids": [message_id]},
                )
            )
    return deleted, emitted


def _active_member_ids(connection: sqlite3.Connection, *, peer_id: int) -> list[int]:
    return [
        int(row["user_id"])
        for row in connection.execute(
            "SELECT user_id FROM peer_memberships WHERE peer_id = ? AND left_at IS NULL", (peer_id,)
        ).fetchall()
    ]


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


def ensure_dialog_anchor_message(
    connection: sqlite3.Connection, *, peer_id: int, user_id: int, body: str, client_random_id: str
) -> tuple[dict[str, Any] | None, list[UpdateEnvelope]]:
    row = connection.execute(
        "SELECT top_message_id FROM dialogs WHERE user_id = ? AND peer_id = ?", (user_id, peer_id)
    ).fetchone()
    if row is not None and row["top_message_id"] is not None:
        connection.execute(
            """
            UPDATE dialogs
            SET read_outbox_max_id = MAX(read_outbox_max_id, top_message_id)
            WHERE user_id = ? AND peer_id = ?
            """,
            (user_id, peer_id),
        )
        return None, []
    return send_message(
        connection,
        peer_id=peer_id,
        sender_user_id=user_id,
        body=body,
        client_random_id=client_random_id,
    )


def get_history(
connection: sqlite3.Connection, *, peer_id: int, user_id: int, before_id: int | None, limit: int) -> list[dict[str, Any]]:
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
    return [_message_row(row, connection) for row in reversed(rows)]


def get_history_count(connection: sqlite3.Connection, *, peer_id: int) -> int:
    row = connection.execute(
        "SELECT COUNT(*) AS count FROM messages WHERE peer_id = ? AND deleted_at IS NULL",
        (peer_id,),
    ).fetchone()
    return int(row["count"])


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


def _stored_media_attributes(media: dict[str, Any]) -> str:
    """Serialize safe document attributes while preserving binary waveforms."""

    stored: list[dict[str, Any]] = []
    for attribute in media.get("attributes") or []:
        if not isinstance(attribute, dict):
            continue
        item = dict(attribute)
        waveform = item.pop("waveform", None)
        if isinstance(waveform, bytes):
            item["waveform_b64"] = base64.b64encode(waveform).decode("ascii")
        stored.append(item)
    return json.dumps(stored, separators=(",", ":"), sort_keys=True)


def _loaded_media_attributes(value: object) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, list):
        return []
    attributes: list[dict[str, Any]] = []
    for candidate in parsed:
        if not isinstance(candidate, dict):
            continue
        item = dict(candidate)
        waveform_b64 = item.pop("waveform_b64", None)
        if isinstance(waveform_b64, str):
            try:
                item["waveform"] = base64.b64decode(waveform_b64.encode("ascii"), validate=True)
            except (ValueError, UnicodeError):
                pass
        attributes.append(item)
    return attributes


def _store_message_media(connection: sqlite3.Connection, *, message_id: int, media: dict[str, Any]) -> None:
    connection.execute(
        """
        INSERT INTO message_media(message_id, file_id, kind, filename, mime_type, size, created_at, attributes_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            message_id,
            int(media["file_id"]),
            str(media["kind"]),
            str(media.get("filename") or "attachment"),
            str(media.get("mime_type") or "application/octet-stream"),
            int(media.get("size") or 0),
            int(media.get("date") or now_unix()),
            _stored_media_attributes(media),
        ),
    )


def _load_message_media(connection: sqlite3.Connection, message_id: int) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT mm.file_id, mm.kind, mm.filename, mm.mime_type, mm.size, mm.created_at, mm.attributes_json
        FROM message_media mm
        WHERE mm.message_id = ?
        """,
        (message_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "kind": str(row["kind"]),
        "file_id": int(row["file_id"]),
        "filename": str(row["filename"]),
        "mime_type": str(row["mime_type"]),
        "size": int(row["size"]),
        "date": int(row["created_at"]),
        "attributes": _loaded_media_attributes(row["attributes_json"]),
    }


def _message_row(row: sqlite3.Row, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
    message = {
        "id": int(row["id"]),
        "peer_id": int(row["peer_id"]),
        "sender_user_id": int(row["sender_user_id"]),
        "body": str(row["body"]),
        "reply_to_message_id": int(row["reply_to_message_id"]) if row["reply_to_message_id"] is not None else None,
        "sent_at": int(row["sent_at"]),
        "edited_at": int(row["edited_at"]) if row["edited_at"] is not None else None,
        "deleted_at": int(row["deleted_at"]) if row["deleted_at"] is not None else None,
    }
    if connection is not None:
        media = _load_message_media(connection, int(row["id"]))
        if media is not None:
            message["media"] = media
    return message
