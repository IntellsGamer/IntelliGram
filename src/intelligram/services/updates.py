from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import sqlite3
from typing import Any

from intelligram.database import now_unix


@dataclass(frozen=True, slots=True)
class UpdateEnvelope:
    user_id: int
    pts: int
    pts_count: int
    seq: int
    date: int
    kind: str
    payload: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "@type": self.kind,
            "pts": self.pts,
            "pts_count": self.pts_count,
            "seq": self.seq,
            "date": self.date,
            "payload": self.payload,
        }


_BYTES_MARKER = "__intelligram_bytes_b64__"


def _json_default(value: object) -> object:
    if isinstance(value, bytes):
        return {_BYTES_MARKER: base64.b64encode(value).decode("ascii")}
    raise TypeError(f"Unsupported update payload value: {type(value).__name__}")


def _json_object_hook(value: dict[str, Any]) -> object:
    encoded = value.get(_BYTES_MARKER)
    if len(value) == 1 and isinstance(encoded, str):
        try:
            return base64.b64decode(encoded.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            return value
    return value


def _state_for_update(connection: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    now = now_unix()
    connection.execute(
        "INSERT OR IGNORE INTO update_state(user_id, pts, qts, seq, date) VALUES (?, 0, 0, 0, ?)",
        (user_id, now),
    )
    state = connection.execute(
        "SELECT user_id, pts, qts, seq, date FROM update_state WHERE user_id = ?", (user_id,)
    ).fetchone()
    if state is None:
        raise RuntimeError("Failed to create update state")
    return state


def append_update(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    kind: str,
    payload: dict[str, Any],
    pts_count: int = 1,
) -> UpdateEnvelope:
    if pts_count < 0:
        raise ValueError("pts_count must be non-negative")
    state = _state_for_update(connection, user_id)
    now = now_unix()
    pts = int(state["pts"]) + pts_count
    seq = int(state["seq"]) + 1
    connection.execute(
        "UPDATE update_state SET pts = ?, seq = ?, date = ? WHERE user_id = ?",
        (pts, seq, now, user_id),
    )
    connection.execute(
        """
        INSERT INTO updates(user_id, pts, pts_count, seq, date, kind, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            pts,
            pts_count,
            seq,
            now,
            kind,
            json.dumps(payload, default=_json_default, separators=(",", ":"), sort_keys=True),
            now,
        ),
    )
    connection.execute(
        """
        INSERT INTO outbox(aggregate_type, aggregate_id, event_type, payload_json, created_at)
        VALUES ('user_update', ?, ?, ?, ?)
        """,
        (
            str(user_id),
            kind,
            json.dumps({"user_id": user_id, "pts": pts, "payload": payload}, default=_json_default),
            now,
        ),
    )
    return UpdateEnvelope(user_id, pts, pts_count, seq, now, kind, payload)


def get_state(connection: sqlite3.Connection, user_id: int) -> dict[str, int]:
    state = _state_for_update(connection, user_id)
    return {"pts": int(state["pts"]), "qts": int(state["qts"]), "seq": int(state["seq"]), "date": int(state["date"])}


def get_difference(connection: sqlite3.Connection, *, user_id: int, after_pts: int, limit: int = 100) -> list[UpdateEnvelope]:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    rows = connection.execute(
        """
        SELECT user_id, pts, pts_count, seq, date, kind, payload_json
        FROM updates
        WHERE user_id = ? AND pts > ?
        ORDER BY pts ASC
        LIMIT ?
        """,
        (user_id, after_pts, limit),
    ).fetchall()
    return [
        UpdateEnvelope(
            user_id=int(row["user_id"]),
            pts=int(row["pts"]),
            pts_count=int(row["pts_count"]),
            seq=int(row["seq"]),
            date=int(row["date"]),
            kind=str(row["kind"]),
            payload=json.loads(row["payload_json"], object_hook=_json_object_hook),
        )
        for row in rows
    ]
