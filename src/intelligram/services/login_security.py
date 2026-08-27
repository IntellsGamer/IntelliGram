"""Durable protections for IntelliGram in-app login codes."""

from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3

from intelligram.database import now_unix


_LOGIN_CODE_RE = re.compile(r"(?<![0-9])[0-9]{6}(?![0-9])")


def challenge_code_hash(challenge_id: str, code: str) -> str:
    """Return the per-challenge digest already stored for an in-app code."""

    return hashlib.sha256(f"{challenge_id}:{code}".encode("utf-8")).hexdigest()


def invalidate_codes_shared_by_owner(
    connection: sqlite3.Connection,
    *,
    owner_user_id: int,
    body: str,
) -> int:
    """Invalidate active login codes that their owner posts in a message.

    Codes are never stored as plaintext. The text is reduced to bounded
    six-digit candidates and each is compared against its active challenge's
    challenge-bound digest. The calling message transaction atomically records
    the denial before its content can become a durable share in a direct chat,
    group, or channel.
    """

    candidates = set(_LOGIN_CODE_RE.findall(body))
    if not candidates:
        return 0
    now = now_unix()
    challenges = connection.execute(
        """
        SELECT id, code_hash FROM login_challenges
        WHERE user_id = ? AND completed_at IS NULL AND denied_at IS NULL
        AND expires_at >= ?
        """,
        (owner_user_id, now),
    ).fetchall()
    invalidated = 0
    for challenge in challenges:
        if not any(
            hmac.compare_digest(str(challenge["code_hash"]), challenge_code_hash(str(challenge["id"]), candidate))
            for candidate in candidates
        ):
            continue
        invalidated += connection.execute(
            """
            UPDATE login_challenges
            SET denied_at = ?, denial_reason = 'shared'
            WHERE id = ? AND completed_at IS NULL AND denied_at IS NULL
            """,
            (now, str(challenge["id"])),
        ).rowcount
    return invalidated
