"""Contact list and block list persistence.

A contact is a directed edge: ``contacts(user_id -> contact_user_id)`` means
the owner saved that account. Saved first/last names are per-owner overrides
kept on the edge, so two people who both save the same account may see
different names for it -- the shared ``users`` row is never rewritten.

Every surface that needs "is this a contact" (the ``contact``/``mutual_contact``
User flags, the Premium messaging privacy rule, phone-number visibility) reads
through this module so the answers cannot drift apart.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from intelligram.database import now_unix


@dataclass(frozen=True)
class ContactLink:
    """One owner's view of a saved contact."""

    user_id: int
    mutual: bool
    first_name: str | None
    last_name: str | None
    phone: str | None


def _clean(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def save_contact(
    connection: sqlite3.Connection,
    *,
    owner_user_id: int,
    contact_user_id: int,
    first_name: object = None,
    last_name: object = None,
    phone: object = None,
    client_id: int = 0,
) -> bool:
    """Add or update a saved contact. Returns True when it was newly added.

    Blank names are stored as NULL so the account's own profile name shows
    through instead of an empty label.
    """
    if owner_user_id == contact_user_id:
        return False
    existed = connection.execute(
        "SELECT 1 FROM contacts WHERE user_id = ? AND contact_user_id = ?",
        (owner_user_id, contact_user_id),
    ).fetchone() is not None
    connection.execute(
        """
        INSERT INTO contacts(user_id, contact_user_id, client_id, created_at, first_name, last_name, phone)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, contact_user_id) DO UPDATE SET
            client_id = excluded.client_id,
            first_name = excluded.first_name,
            last_name = excluded.last_name,
            phone = COALESCE(excluded.phone, contacts.phone)
        """,
        (
            owner_user_id,
            contact_user_id,
            client_id,
            now_unix(),
            _clean(first_name),
            _clean(last_name),
            _clean(phone),
        ),
    )
    return not existed


def delete_contacts(
    connection: sqlite3.Connection, *, owner_user_id: int, contact_user_ids: set[int]
) -> set[int]:
    """Drop saved contacts, returning the ids that were actually removed."""
    targets = {int(user_id) for user_id in contact_user_ids if int(user_id) != owner_user_id}
    if not targets:
        return set()
    placeholders = ",".join("?" for _ in targets)
    rows = connection.execute(
        f"SELECT contact_user_id FROM contacts WHERE user_id = ? AND contact_user_id IN ({placeholders})",
        (owner_user_id, *sorted(targets)),
    ).fetchall()
    removed = {int(row["contact_user_id"]) for row in rows}
    if removed:
        connection.execute(
            f"DELETE FROM contacts WHERE user_id = ? AND contact_user_id IN ({placeholders})",
            (owner_user_id, *sorted(targets)),
        )
    return removed


def load_contact_links(
    connection: sqlite3.Connection, *, owner_user_id: int, user_ids: set[int]
) -> dict[int, ContactLink]:
    """Return the owner's contact edges for ``user_ids``, keyed by user id.

    Mutuality is resolved in the same statement so encoding a batch of users
    costs one query instead of one per user.
    """
    targets = {int(user_id) for user_id in user_ids if int(user_id) != owner_user_id}
    if not targets:
        return {}
    placeholders = ",".join("?" for _ in targets)
    rows = connection.execute(
        f"""
        SELECT c.contact_user_id AS user_id,
               c.first_name,
               c.last_name,
               c.phone,
               EXISTS(
                   SELECT 1 FROM contacts back
                   WHERE back.user_id = c.contact_user_id AND back.contact_user_id = c.user_id
               ) AS mutual
        FROM contacts c
        WHERE c.user_id = ? AND c.contact_user_id IN ({placeholders})
        """,
        (owner_user_id, *sorted(targets)),
    ).fetchall()
    return {
        int(row["user_id"]): ContactLink(
            user_id=int(row["user_id"]),
            mutual=bool(int(row["mutual"] or 0)),
            first_name=_clean(row["first_name"]),
            last_name=_clean(row["last_name"]),
            phone=_clean(row["phone"]),
        )
        for row in rows
    }


def list_contacts(connection: sqlite3.Connection, *, owner_user_id: int) -> list[ContactLink]:
    """Return every saved contact, ordered by the name the owner will see."""
    rows = connection.execute(
        """
        SELECT c.contact_user_id AS user_id,
               COALESCE(NULLIF(c.first_name, ''), u.first_name) AS sort_first,
               COALESCE(NULLIF(c.last_name, ''), u.last_name) AS sort_last,
               c.first_name,
               c.last_name,
               c.phone,
               EXISTS(
                   SELECT 1 FROM contacts back
                   WHERE back.user_id = c.contact_user_id AND back.contact_user_id = c.user_id
               ) AS mutual
        FROM contacts c
        JOIN users u ON u.id = c.contact_user_id
        WHERE c.user_id = ?
        ORDER BY sort_first COLLATE NOCASE, sort_last COLLATE NOCASE, c.contact_user_id
        """,
        (owner_user_id,),
    ).fetchall()
    return [
        ContactLink(
            user_id=int(row["user_id"]),
            mutual=bool(int(row["mutual"] or 0)),
            first_name=_clean(row["first_name"]),
            last_name=_clean(row["last_name"]),
            phone=_clean(row["phone"]),
        )
        for row in rows
    ]


def set_blocked(
    connection: sqlite3.Connection, *, owner_user_id: int, target_user_id: int, blocked: bool
) -> bool:
    """Block or unblock an account. Returns whether the state changed."""
    if owner_user_id == target_user_id:
        return False
    if blocked:
        cursor = connection.execute(
            """
            INSERT INTO blocked_peers(user_id, blocked_user_id, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, blocked_user_id) DO NOTHING
            """,
            (owner_user_id, target_user_id, now_unix()),
        )
    else:
        cursor = connection.execute(
            "DELETE FROM blocked_peers WHERE user_id = ? AND blocked_user_id = ?",
            (owner_user_id, target_user_id),
        )
    return bool(cursor.rowcount)


def list_blocked(
    connection: sqlite3.Connection, *, owner_user_id: int, offset: int = 0, limit: int = 100
) -> tuple[list[tuple[int, int]], int]:
    """Return one page of ``(user_id, blocked_at)`` plus the total count."""
    total = int(
        connection.execute(
            "SELECT COUNT(*) AS total FROM blocked_peers WHERE user_id = ?", (owner_user_id,)
        ).fetchone()["total"]
    )
    rows = connection.execute(
        """
        SELECT blocked_user_id, created_at
        FROM blocked_peers
        WHERE user_id = ?
        ORDER BY created_at DESC, blocked_user_id
        LIMIT ? OFFSET ?
        """,
        (owner_user_id, max(1, min(int(limit or 100), 200)), max(0, int(offset or 0))),
    ).fetchall()
    return [(int(row["blocked_user_id"]), int(row["created_at"])) for row in rows], total


def is_blocked(
    connection: sqlite3.Connection, *, owner_user_id: int, target_user_id: int
) -> bool:
    """Return whether ``owner_user_id`` has blocked ``target_user_id``."""
    if owner_user_id == target_user_id:
        return False
    return connection.execute(
        "SELECT 1 FROM blocked_peers WHERE user_id = ? AND blocked_user_id = ?",
        (owner_user_id, target_user_id),
    ).fetchone() is not None
