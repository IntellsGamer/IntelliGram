"""IntelliGram Premium capability resolution.

Premium is a per-account tier stored on the ``users`` row. The tier is
authoritative only while unexpired; every enforcement point funnels through
this module so free/premium limits stay consistent across surfaces.
"""

from __future__ import annotations

import sqlite3
import time

FREE_ATTACHMENT_BYTES = 50 * 1024 * 1024
PREMIUM_ATTACHMENT_BYTES = 200 * 1024 * 1024

USER_PREMIUM_COLUMNS = "premium, premium_until"


def is_premium_active(row: sqlite3.Row | dict | None) -> bool:
    """Return whether a ``users`` row (with premium/premium_until) is an
    unexpired Premium subscription."""
    if row is None:
        return False
    try:
        premium = int(row["premium"] or 0)
    except (KeyError, IndexError, TypeError, ValueError):
        return False
    if not premium:
        return False
    try:
        premium_until = row["premium_until"]
    except (KeyError, IndexError, TypeError):
        premium_until = None
    if premium_until is None:
        return True
    return int(premium_until) >= int(time.time())


def attachment_limit_bytes(*, premium: bool) -> int:
    return PREMIUM_ATTACHMENT_BYTES if premium else FREE_ATTACHMENT_BYTES


def user_is_premium(connection: sqlite3.Connection, user_id: int) -> bool:
    row = connection.execute(
        f"SELECT {USER_PREMIUM_COLUMNS} FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return is_premium_active(row)


def is_contact(connection: sqlite3.Connection, *, owner_user_id: int, contact_user_id: int) -> bool:
    if owner_user_id == contact_user_id:
        return True
    row = connection.execute(
        "SELECT 1 FROM contacts WHERE user_id = ? AND contact_user_id = ?",
        (owner_user_id, contact_user_id),
    ).fetchone()
    return row is not None


def can_message_user(connection: sqlite3.Connection, *, sender_user_id: int, recipient_user_id: int) -> bool:
    """Enforce the recipient's ``new_noncontact_peers_require_premium`` rule.

    Contacts and Premium senders may always start direct conversations; other
    senders are rejected while the rule is enabled.
    """
    if sender_user_id == recipient_user_id:
        return True
    recipient = connection.execute(
        "SELECT premium, premium_until, noncontacts_require_premium FROM users WHERE id = ?",
        (recipient_user_id,),
    ).fetchone()
    if recipient is None or not int(recipient["noncontacts_require_premium"] or 0):
        return True
    if is_contact(connection, owner_user_id=recipient_user_id, contact_user_id=sender_user_id):
        return True
    return user_is_premium(connection, sender_user_id)
