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
from intelligram.services.messaging import create_user, get_or_create_direct_peer, send_message
from intelligram.services.srp import (
    CHALLENGE_LIFETIME_SECONDS as SRP_CHALLENGE_LIFETIME_SECONDS,
    MAX_PASSWORD_ATTEMPTS,
    make_challenge,
    make_password_verifier,
    verify_proof,
)
from intelligram.services.updates import UpdateEnvelope, append_update


class AccountAuthError(ValueError):
    """A client-safe account authentication failure."""


PHONE_PATTERN = re.compile(r"^\+?[0-9 ()-]{3,64}$")
PASSWORD_MIN_LENGTH = 8
SESSION_LIFETIME_SECONDS = 60 * 60 * 24 * 30
LOGIN_CHALLENGE_LIFETIME_SECONDS = 60 * 5
MAX_LOGIN_CODE_ATTEMPTS = 5
LOGIN_SERVICE_PHONE = "+00000000001"
LOGIN_SERVICE_USERNAME = "intelligram_login"


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


@dataclass(frozen=True, slots=True)
class PasswordSRPState:
    """A single Web K `account.password` SRP state for a pending login."""

    user_id: int
    srp_id: int
    salt1: bytes
    salt2: bytes
    srp_B: bytes


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
    srp_verifier = make_password_verifier(password)
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
        """
        INSERT INTO password_srp_verifiers(user_id, salt1, salt2, verifier, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, srp_verifier.salt1, srp_verifier.salt2, srp_verifier.verifier, now, now),
    )
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
    user_id = int(user["id"])
    _ensure_srp_verifier_from_password(connection, user_id=user_id, password=password)
    return _issue_session(connection, user_id=user_id, device_label=device_label)


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
    # Preserve the machine-readable update for the self-hosted REST surface,
    # and also deliver the secret through an ordinary incoming dialog/message.
    # The latter is essential: unmodified Web K cannot render a private custom
    # update constructor, but it does render a normal `updateNewMessage`.
    message_updates = _deliver_login_code_message(
        connection,
        user_id=user_id,
        challenge_id=challenge_id,
        code=code,
        expires_at=expires_at,
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
        updates=[*message_updates, update],
    )


def _deliver_login_code_message(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    challenge_id: str,
    code: str,
    expires_at: int,
) -> list[UpdateEnvelope]:
    """Deliver a short-lived code as a visible incoming IntelliGram message.

    The system identity is local to this self-hosted database.  A direct peer
    is used deliberately because Web K already hydrates and renders its
    standard message/dialog updates; no Telegram production identity or SMS
    transport is involved.
    """

    service = connection.execute(
        "SELECT id FROM users WHERE phone = ?",
        (LOGIN_SERVICE_PHONE,),
    ).fetchone()
    if service is None:
        service_user_id = create_user(
            connection,
            phone=LOGIN_SERVICE_PHONE,
            first_name="IntelliGram",
            last_name="",
            username=LOGIN_SERVICE_USERNAME,
        )
    else:
        service_user_id = int(service["id"])
    peer_id = get_or_create_direct_peer(
        connection,
        user_id=user_id,
        other_user_id=service_user_id,
    )
    remaining_seconds = max(0, expires_at - now_unix())
    _, updates = send_message(
        connection,
        peer_id=peer_id,
        sender_user_id=service_user_id,
        body=(
            f"Your IntelliGram login code is: {code}\n\n"
            f"It expires in {max(1, remaining_seconds // 60)} minutes. "
            "Do not share this code with anyone."
        ),
        client_random_id=f"login-code:{challenge_id}",
    )
    return updates


def begin_password_login(
    connection: sqlite3.Connection,
    *,
    auth_key_id: str,
    user_id: int,
) -> None:
    """Bind an unauthenticated MTProto key to the account chosen by sendCode.

    Web K's `account.getPassword` carries no phone number.  The short-lived
    binding lets the real PasswordCard request a password state after a code
    delivery problem without leaking account information to another auth key.
    """

    now = now_unix()
    connection.execute(
        """
        INSERT INTO password_login_contexts(auth_key_id, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(auth_key_id) DO UPDATE SET
            user_id = excluded.user_id,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at
        """,
        (auth_key_id, user_id, now, now + SRP_CHALLENGE_LIFETIME_SECONDS),
    )


def get_password_srp_state(
    connection: sqlite3.Connection,
    *,
    auth_key_id: str,
) -> PasswordSRPState:
    """Issue the one-time SRP material consumed by Web K's PasswordCard."""

    now = now_unix()
    context = connection.execute(
        """
        SELECT user_id FROM password_login_contexts
        WHERE auth_key_id = ? AND expires_at >= ?
        """,
        (auth_key_id, now),
    ).fetchone()
    if context is None:
        raise AccountAuthError("SESSION_PASSWORD_NEEDED")
    user_id = int(context["user_id"])
    verifier = connection.execute(
        "SELECT salt1, salt2, verifier FROM password_srp_verifiers WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if verifier is None:
        # Legacy scrypt-only accounts cannot issue a real SRP challenge. Return
        # srp_id=0 so PasswordCard can submit the UTF-8 password inside the
        # existing encrypted MTProto envelope.
        return PasswordSRPState(
            user_id=user_id,
            srp_id=0,
            salt1=b"\x00" * 8,
            salt2=b"\x00" * 8,
            srp_B=b"\x00" * 256,
        )
    challenge = make_challenge(
        salt1=bytes(verifier["salt1"]),
        salt2=bytes(verifier["salt2"]),
        verifier=bytes(verifier["verifier"]),
    )
    connection.execute(
        """
        UPDATE password_srp_challenges SET completed_at = ?
        WHERE user_id = ? AND auth_key_id = ? AND completed_at IS NULL
        """,
        (now, user_id, auth_key_id),
    )
    connection.execute(
        """
        INSERT INTO password_srp_challenges(
            srp_id, user_id, auth_key_id, private_b, srp_B, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            challenge.srp_id,
            user_id,
            auth_key_id,
            challenge.private_b,
            challenge.srp_B,
            now,
            now + SRP_CHALLENGE_LIFETIME_SECONDS,
        ),
    )
    return PasswordSRPState(
        user_id=user_id,
        srp_id=challenge.srp_id,
        salt1=challenge.salt1,
        salt2=challenge.salt2,
        srp_B=challenge.srp_B,
    )


def complete_password_plaintext_login(
    connection: sqlite3.Connection,
    *,
    auth_key_id: str,
    password: str,
    device_label: str,
) -> IssuedSession:
    """Verify a scrypt-only account over encrypted MTProto and bootstrap SRP.

    Web K's PasswordCard can reach this path when ``account.getPassword``
    returns ``PASSWORD_FALLBACK_UNAVAILABLE`` because the account was created
    before an SRP verifier existed. The password still travels inside the
    existing MTProto envelope; it is never written to the database.
    """

    now = now_unix()
    context = connection.execute(
        """
        SELECT user_id FROM password_login_contexts
        WHERE auth_key_id = ? AND expires_at >= ?
        """,
        (auth_key_id, now),
    ).fetchone()
    if context is None:
        raise AccountAuthError("SESSION_PASSWORD_NEEDED")
    user_id = int(context["user_id"])
    user = connection.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    stored_hash = user["password_hash"] if user is not None else None
    if not isinstance(stored_hash, str) or not verify_password(password, stored_hash):
        raise AccountAuthError("PASSWORD_HASH_INVALID")
    _ensure_srp_verifier_from_password(connection, user_id=user_id, password=password)
    connection.execute("DELETE FROM password_login_contexts WHERE auth_key_id = ?", (auth_key_id,))
    return _issue_session(connection, user_id=user_id, device_label=device_label, now=now)


def complete_password_srp_login(
    connection: sqlite3.Connection,
    *,
    auth_key_id: str,
    srp_id: int,
    client_A: bytes,
    client_M1: bytes,
    device_label: str,
) -> IssuedSession:
    """Verify an `inputCheckPasswordSRP` proof and issue a normal session."""

    now = now_unix()
    row = connection.execute(
        """
        SELECT c.user_id, c.private_b, c.srp_B, c.expires_at, c.completed_at, c.attempts,
               v.salt1, v.salt2, v.verifier
        FROM password_srp_challenges c
        JOIN password_srp_verifiers v ON v.user_id = c.user_id
        WHERE c.srp_id = ? AND c.auth_key_id = ?
        """,
        (srp_id, auth_key_id),
    ).fetchone()
    if row is None or row["completed_at"] is not None or int(row["expires_at"]) < now:
        raise AccountAuthError("PASSWORD_HASH_INVALID")
    attempts = int(row["attempts"])
    if attempts >= MAX_PASSWORD_ATTEMPTS:
        connection.execute("UPDATE password_srp_challenges SET completed_at = ? WHERE srp_id = ?", (now, srp_id))
        raise AccountAuthError("PASSWORD_HASH_INVALID")
    accepted = verify_proof(
        salt1=bytes(row["salt1"]),
        salt2=bytes(row["salt2"]),
        verifier=bytes(row["verifier"]),
        private_b=bytes(row["private_b"]),
        srp_B=bytes(row["srp_B"]),
        client_A=client_A,
        client_M1=client_M1,
    )
    if not accepted:
        next_attempts = attempts + 1
        connection.execute(
            "UPDATE password_srp_challenges SET attempts = ?, completed_at = ? WHERE srp_id = ?",
            (next_attempts, now if next_attempts >= MAX_PASSWORD_ATTEMPTS else None, srp_id),
        )
        raise AccountAuthError("PASSWORD_HASH_INVALID")
    connection.execute("UPDATE password_srp_challenges SET completed_at = ? WHERE srp_id = ?", (now, srp_id))
    connection.execute("DELETE FROM password_login_contexts WHERE auth_key_id = ?", (auth_key_id,))
    return _issue_session(connection, user_id=int(row["user_id"]), device_label=device_label, now=now)


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
        next_attempts = attempts + 1
        connection.execute(
            "UPDATE login_challenges SET attempts = ?, denied_at = ? WHERE id = ?",
            (next_attempts, now if next_attempts >= MAX_LOGIN_CODE_ATTEMPTS else None, challenge_id),
        )
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


def _ensure_srp_verifier_from_password(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    password: str,
) -> None:
    """Backfill SRP only after an existing account proves its password locally."""

    existing = connection.execute(
        "SELECT 1 FROM password_srp_verifiers WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if existing is not None:
        return
    verifier = make_password_verifier(password)
    now = now_unix()
    connection.execute(
        """
        INSERT INTO password_srp_verifiers(user_id, salt1, salt2, verifier, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, verifier.salt1, verifier.salt2, verifier.verifier, now, now),
    )


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
