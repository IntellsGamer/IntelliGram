from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
from typing import Literal

from intelligram.auth.tokens import create_session_id
from intelligram.database import now_unix
from intelligram.services.updates import UpdateEnvelope, append_update


class AccountAuthError(ValueError):
    """A client-safe account authentication failure."""


PHONE_PATTERN = re.compile(r"^\+?[0-9 ()-]{3,64}$")
PASSWORD_MIN_LENGTH = 8
SESSION_LIFETIME_SECONDS = 60 * 60 * 24 * 30
LOGIN_CHALLENGE_LIFETIME_SECONDS = 60 * 5
MAX_LOGIN_CODE_ATTEMPTS = 5


@dataclass(frozen=True, slots=True)
class IssuedSession:
    session_id: str
    user_id: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class LoginStartResult:
    status: Literal["password_required", "in_app_code_sent"]
    user_id: int
    challenge_id: str | None
    expires_at: int | None
    updates: list[UpdateEnvelope]


def normalize_phone(phone: str) -> str:
    """Normalize a syntactically valid phone-like account identifier.

    IntelliGram deliberately does not claim to validate telephone-number ownership
    in this self-hosted mode. The normalized value is only a unique account name.
    """

    candidate = phone.strip()
    if not PHONE_PATTERN.fullmatch(candidate):
        raise AccountAuthError("PHONE_NUMBER_INVALID")
    digits = "".join(character for character in candidate if character.isdigit())
    if not 3 <= len(digits) <= 15:
        raise AccountAuthError("PHONE_NUMBER_INVALID")
    return f"+{digits}"


def register_password_account(
    connection: sqlite3.Connection,
    *,
    phone: str,
    password: str,
    first_name: str,
    last_name: str = "",
    username: str | None = None,
    device_label: str,
) -> IssuedSession:
    normalized_phone = normalize_phone(phone)
    _validate_profile(first_name=first_name, last_name=last_name, username=username)
    password_hash = hash_password(password)
    now = now_unix()
    try:
        cursor = connection.execute(
            """
            INSERT INTO users(phone, username, first_name, last_name, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_phone,
                username.strip().lstrip("@") if username else None,
                first_name.strip(),
                last_name.strip(),
                password_hash,
                now,
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise AccountAuthError("PHONE_OR_USERNAME_OCCUPIED") from exc
    user_id = int(cursor.lastrowid)
    connection.execute(
        "INSERT INTO update_state(user_id, pts, qts, seq, date) VALUES (?, 0, 0, 0, ?)",
        (user_id, now),
    )
    return _issue_session(connection, user_id=user_id, device_label=device_label, now=now)


def password_login(
    connection: sqlite3.Connection,
    *,
    phone: str,
    password: str,
    device_label: str,
) -> IssuedSession:
    normalized_phone = normalize_phone(phone)
    user = connection.execute(
        "SELECT id, password_hash FROM users WHERE phone = ?", (normalized_phone,)
    ).fetchone()
    if user is None:
        raise AccountAuthError("PHONE_NUMBER_UNOCCUPIED")
    stored_hash = user["password_hash"]
    if not isinstance(stored_hash, str) or not verify_password(password, stored_hash):
        raise AccountAuthError("PASSWORD_HASH_INVALID")
    return _issue_session(connection, user_id=int(user["id"]), device_label=device_label)


def start_device_login(
    connection: sqlite3.Connection,
    *,
    phone: str,
    device_label: str,
) -> LoginStartResult:
    normalized_phone = normalize_phone(phone)
    user = connection.execute("SELECT id FROM users WHERE phone = ?", (normalized_phone,)).fetchone()
    if user is None:
        raise AccountAuthError("PHONE_NUMBER_UNOCCUPIED")
    user_id = int(user["id"])
    now = now_unix()
    existing_session = connection.execute(
        """
        SELECT id FROM sessions
        WHERE user_id = ? AND revoked_at IS NULL AND expires_at >= ?
        LIMIT 1
        """,
        (user_id, now),
    ).fetchone()
    if existing_session is None:
        return LoginStartResult(
            status="password_required",
            user_id=user_id,
            challenge_id=None,
            expires_at=None,
            updates=[],
        )

    connection.execute(
        """
        UPDATE login_challenges
        SET denied_at = ?
        WHERE user_id = ? AND completed_at IS NULL AND denied_at IS NULL AND expires_at >= ?
        """,
        (now, user_id, now),
    )
    challenge_id = secrets.token_urlsafe(24)
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = now + LOGIN_CHALLENGE_LIFETIME_SECONDS
    connection.execute(
        """
        INSERT INTO login_challenges(id, user_id, requested_device_label, code_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (challenge_id, user_id, _normalize_device_label(device_label), _challenge_code_hash(challenge_id, code), now, expires_at),
    )
    update = append_update(
        connection,
        user_id=user_id,
        kind="updateIntelliGramLoginCode",
        payload={
            "challenge_id": challenge_id,
            "code": code,
            "device_label": _normalize_device_label(device_label),
            "expires_at": expires_at,
        },
    )
    return LoginStartResult(
        status="in_app_code_sent",
        user_id=user_id,
        challenge_id=challenge_id,
        expires_at=expires_at,
        updates=[update],
    )


def complete_device_login(
    connection: sqlite3.Connection,
    *,
    phone: str,
    challenge_id: str,
    code: str,
    device_label: str,
) -> IssuedSession:
    normalized_phone = normalize_phone(phone)
    now = now_unix()
    challenge = connection.execute(
        """
        SELECT c.id, c.user_id, c.code_hash, c.expires_at, c.completed_at, c.denied_at, c.attempts
        FROM login_challenges c
        JOIN users u ON u.id = c.user_id
        WHERE c.id = ? AND u.phone = ?
        """,
        (challenge_id, normalized_phone),
    ).fetchone()
    if challenge is None:
        raise AccountAuthError("PHONE_CODE_INVALID")
    if challenge["completed_at"] is not None or challenge["denied_at"] is not None or int(challenge["expires_at"]) < now:
        raise AccountAuthError("PHONE_CODE_EXPIRED")
    attempts = int(challenge["attempts"])
    if attempts >= MAX_LOGIN_CODE_ATTEMPTS:
        connection.execute("UPDATE login_challenges SET denied_at = ? WHERE id = ?", (now, challenge_id))
        raise AccountAuthError("PHONE_CODE_INVALID")
    if not hmac.compare_digest(str(challenge["code_hash"]), _challenge_code_hash(challenge_id, code)):
        connection.execute("UPDATE login_challenges SET attempts = attempts + 1 WHERE id = ?", (challenge_id,))
        raise AccountAuthError("PHONE_CODE_INVALID")
    connection.execute("UPDATE login_challenges SET completed_at = ? WHERE id = ?", (now, challenge_id))
    return _issue_session(connection, user_id=int(challenge["user_id"]), device_label=device_label, now=now)


def active_login_challenges(connection: sqlite3.Connection, *, user_id: int) -> list[dict[str, int | str]]:
    now = now_unix()
    rows = connection.execute(
        """
        SELECT id, requested_device_label, created_at, expires_at
        FROM login_challenges
        WHERE user_id = ? AND completed_at IS NULL AND denied_at IS NULL AND expires_at >= ?
        ORDER BY created_at DESC
        """,
        (user_id, now),
    ).fetchall()
    return [
        {
            "challenge_id": str(row["id"]),
            "device_label": str(row["requested_device_label"]),
            "created_at": int(row["created_at"]),
            "expires_at": int(row["expires_at"]),
        }
        for row in rows
    ]


def hash_password(password: str) -> str:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise AccountAuthError("PASSWORD_TOO_SHORT")
    if len(password) > 1024:
        raise AccountAuthError("PASSWORD_TOO_LONG")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, expected_b64 = stored_hash.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(expected_b64.encode("ascii"))
        derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError, UnicodeError):
        return False
    return hmac.compare_digest(derived, expected)


def _issue_session(connection: sqlite3.Connection, *, user_id: int, device_label: str, now: int | None = None) -> IssuedSession:
    now = now if now is not None else now_unix()
    session_id = create_session_id()
    expires_at = now + SESSION_LIFETIME_SECONDS
    connection.execute(
        """
        INSERT INTO sessions(id, user_id, device_label, created_at, last_seen_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (session_id, user_id, _normalize_device_label(device_label), now, now, expires_at),
    )
    return IssuedSession(session_id=session_id, user_id=user_id, expires_at=expires_at)


def _challenge_code_hash(challenge_id: str, code: str) -> str:
    return hashlib.sha256(f"{challenge_id}:{code}".encode("utf-8")).hexdigest()


def _normalize_device_label(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 255:
        raise AccountAuthError("DEVICE_MODEL_INVALID")
    return value


def _validate_profile(*, first_name: str, last_name: str, username: str | None) -> None:
    if not first_name.strip() or len(first_name.strip()) > 128 or len(last_name.strip()) > 128:
        raise AccountAuthError("FIRSTNAME_INVALID")
    if username is not None and (not username.strip() or len(username.strip().lstrip("@")) > 32):
        raise AccountAuthError("USERNAME_INVALID")
