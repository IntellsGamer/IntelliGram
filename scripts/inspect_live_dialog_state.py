from __future__ import annotations

import sqlite3
from pathlib import Path

path = Path("data/intelligram.sqlite3")
connection = sqlite3.connect(path)
connection.row_factory = sqlite3.Row
for name, sql in [
    ("users", "SELECT id, phone, first_name, username FROM users ORDER BY id"),
    ("peers", "SELECT id, kind, title, created_by_user_id, created_at FROM peers ORDER BY id"),
    ("dialogs", "SELECT user_id, peer_id, top_message_id, unread_count FROM dialogs ORDER BY user_id, peer_id"),
    ("messages", "SELECT id, peer_id, sender_user_id, body, deleted_at FROM messages ORDER BY id"),
]:
    print(f"--- {name} ---")
    for row in connection.execute(sql):
        print(dict(row))
