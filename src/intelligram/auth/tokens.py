from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


class TokenError(ValueError):
    """Raised when a session token is malformed, expired, or tampered with."""


def _encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_session_id() -> str:
    return secrets.token_urlsafe(32)


def issue_token(*, session_id: str, user_id: int, secret: bytes, expires_at: int) -> str:
    payload = {
        "sid": session_id,
        "sub": user_id,
        "exp": expires_at,
        "iat": int(time.time()),
        "v": 1,
    }
    encoded_payload = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"ig1.{encoded_payload}.{_encode(signature)}"


def verify_token(token: str, secret: bytes) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "ig1":
        raise TokenError("TOKEN_INVALID")
    _, encoded_payload, encoded_signature = parts
    expected = hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    try:
        signature = _decode(encoded_signature)
        payload = json.loads(_decode(encoded_payload))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenError("TOKEN_INVALID") from exc
    if not hmac.compare_digest(signature, expected):
        raise TokenError("TOKEN_INVALID")
    if not isinstance(payload, dict) or not isinstance(payload.get("sid"), str) or not isinstance(payload.get("sub"), int):
        raise TokenError("TOKEN_INVALID")
    if not isinstance(payload.get("exp"), int) or payload["exp"] < int(time.time()):
        raise TokenError("TOKEN_EXPIRED")
    return payload
