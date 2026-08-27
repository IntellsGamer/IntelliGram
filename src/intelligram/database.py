from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import threading
import time
from typing import Iterator


SCHEMA_VERSION = 12


@dataclass(frozen=True, slots=True)
class Database:
    path: Path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self) -> None:
        with self.transaction(immediate=True) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone TEXT NOT NULL UNIQUE,
                    username TEXT UNIQUE,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL DEFAULT '',
                    about TEXT NOT NULL DEFAULT '',
                    password_hash TEXT,
                    premium INTEGER NOT NULL DEFAULT 0 CHECK(premium IN (0, 1)),
                    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0, 1)),
                    is_service INTEGER NOT NULL DEFAULT 0 CHECK(is_service IN (0, 1)),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_keys (
                    auth_key_id TEXT PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    key_fingerprint TEXT NOT NULL UNIQUE,
                    key_material BLOB,
                    server_salt TEXT,
                    created_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    expires_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    auth_key_id TEXT REFERENCES auth_keys(auth_key_id) ON DELETE SET NULL,
                    device_label TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    expires_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS login_challenges (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    requested_device_label TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    approved_at INTEGER,
                    completed_at INTEGER,
                    denied_at INTEGER,
                    denial_reason TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0)
                );

                CREATE INDEX IF NOT EXISTS login_challenges_user_active_idx
                    ON login_challenges(user_id, expires_at DESC)
                    WHERE completed_at IS NULL AND denied_at IS NULL;

                -- Existing REST/session password verification remains scrypt-backed.
                -- These records add the independent verifier Web K requires for
                -- `account.getPassword` / `auth.checkPassword` SRP exchange.
                CREATE TABLE IF NOT EXISTS password_srp_verifiers (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    salt1 BLOB NOT NULL,
                    salt2 BLOB NOT NULL,
                    verifier BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS password_srp_challenges (
                    srp_id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    auth_key_id TEXT NOT NULL,
                    private_b BLOB NOT NULL,
                    srp_B BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    completed_at INTEGER,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0)
                );
                CREATE INDEX IF NOT EXISTS password_srp_challenges_active_idx
                    ON password_srp_challenges(user_id, auth_key_id, expires_at DESC)
                    WHERE completed_at IS NULL;

                -- `account.getPassword` has no phone argument.  auth.sendCode
                -- binds the selected account to this unauthenticated auth key;
                -- that survives a Web K page reload which reuses the auth key.
                CREATE TABLE IF NOT EXISTS password_login_contexts (
                    auth_key_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS peers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL CHECK(kind IN ('user', 'chat', 'channel')),
                    title TEXT NOT NULL,
                    about TEXT NOT NULL DEFAULT '',
                    username TEXT,
                    created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_settings (
                    peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
                    slowmode_seconds INTEGER NOT NULL DEFAULT 0 CHECK(slowmode_seconds IN (0, 5, 10, 30, 60, 300, 900, 3600)),
                    noforwards INTEGER NOT NULL DEFAULT 0 CHECK(noforwards IN (0, 1)),
                    join_request_enabled INTEGER NOT NULL DEFAULT 0 CHECK(join_request_enabled IN (0, 1)),
                    is_broadcast INTEGER NOT NULL DEFAULT 0 CHECK(is_broadcast IN (0, 1)),
                    signatures_enabled INTEGER NOT NULL DEFAULT 0 CHECK(signatures_enabled IN (0, 1))
                );

                CREATE TABLE IF NOT EXISTS peer_permissions (
                    peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
                    default_banned_rights_flags INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_reaction_settings (
                    peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
                    mode TEXT NOT NULL CHECK(mode IN ('all', 'some', 'none')) DEFAULT 'none',
                    allow_custom INTEGER NOT NULL DEFAULT 0 CHECK(allow_custom IN (0, 1)),
                    emoticons_json TEXT NOT NULL DEFAULT '[]',
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS exported_invites (
                    token TEXT PRIMARY KEY,
                    peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                    admin_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    link TEXT NOT NULL UNIQUE,
                    title TEXT,
                    created_at INTEGER NOT NULL,
                    expire_date INTEGER,
                    usage_limit INTEGER,
                    usage INTEGER NOT NULL DEFAULT 0,
                    request_needed INTEGER NOT NULL DEFAULT 0 CHECK(request_needed IN (0, 1)),
                    permanent INTEGER NOT NULL DEFAULT 0 CHECK(permanent IN (0, 1)),
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
                );
                CREATE INDEX IF NOT EXISTS exported_invites_peer_idx
                    ON exported_invites(peer_id, revoked, permanent, created_at);

                CREATE TABLE IF NOT EXISTS contacts (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    contact_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    client_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(user_id, contact_user_id)
                );

                CREATE TABLE IF NOT EXISTS direct_peer_users (
                    peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
                    user_low_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    user_high_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    CHECK(user_low_id <= user_high_id),
                    UNIQUE(user_low_id, user_high_id)
                );

                CREATE TABLE IF NOT EXISTS peer_memberships (
                    peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
                    joined_at INTEGER NOT NULL,
                    left_at INTEGER,
                    PRIMARY KEY(peer_id, user_id)
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                    sender_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
                    client_random_id TEXT,
                    body TEXT NOT NULL,
                    reply_to_message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
                    sent_at INTEGER NOT NULL,
                    edited_at INTEGER,
                    deleted_at INTEGER,
                    UNIQUE(sender_user_id, client_random_id)
                );

                CREATE INDEX IF NOT EXISTS messages_peer_sent_idx ON messages(peer_id, sent_at DESC, id DESC);

                CREATE TABLE IF NOT EXISTS upload_parts (
                    file_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    part_index INTEGER NOT NULL CHECK(part_index >= 0),
                    content BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(file_id, part_index)
                );

                CREATE TABLE IF NOT EXISTS profile_photos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    source_file_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    content BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS stored_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    source_file_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    content BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS message_media (
                    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                    file_id INTEGER NOT NULL REFERENCES stored_files(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL CHECK(kind IN ('photo', 'document')),
                    filename TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    attributes_json TEXT NOT NULL DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS profile_photos_user_created_idx
                    ON profile_photos(user_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS dialogs (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                    top_message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
                    unread_count INTEGER NOT NULL DEFAULT 0 CHECK(unread_count >= 0),
                    read_inbox_max_id INTEGER NOT NULL DEFAULT 0,
                    read_outbox_max_id INTEGER NOT NULL DEFAULT 0,
                    pinned_order INTEGER,
                    draft_text TEXT,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(user_id, peer_id)
                );

                CREATE TABLE IF NOT EXISTS update_state (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    pts INTEGER NOT NULL DEFAULT 0,
                    qts INTEGER NOT NULL DEFAULT 0,
                    seq INTEGER NOT NULL DEFAULT 0,
                    date INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    pts INTEGER NOT NULL,
                    pts_count INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    date INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(user_id, pts)
                );

                CREATE INDEX IF NOT EXISTS updates_user_pts_idx ON updates(user_id, pts);

                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    aggregate_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    delivered_at INTEGER
                );

                INSERT INTO schema_meta(key, value) VALUES ('schema_version', '15')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                """
            )
            auth_key_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(auth_keys)").fetchall()
            }
            if "key_material" not in auth_key_columns:
                connection.execute("ALTER TABLE auth_keys ADD COLUMN key_material BLOB")
            if "server_salt" not in auth_key_columns:
                connection.execute("ALTER TABLE auth_keys ADD COLUMN server_salt TEXT")
            user_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "about" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN about TEXT NOT NULL DEFAULT ''")
            if "profile_photo_id" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN profile_photo_id INTEGER")
            if "premium" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN premium INTEGER NOT NULL DEFAULT 0")
            if "verified" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
            if "is_service" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN is_service INTEGER NOT NULL DEFAULT 0")
            login_challenge_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(login_challenges)").fetchall()
            }
            if "denial_reason" not in login_challenge_columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN denial_reason TEXT")
            channel_settings_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(channel_settings)").fetchall()
            }
            if "noforwards" not in channel_settings_columns:
                connection.execute("ALTER TABLE channel_settings ADD COLUMN noforwards INTEGER NOT NULL DEFAULT 0")
            if "join_request_enabled" not in channel_settings_columns:
                connection.execute("ALTER TABLE channel_settings ADD COLUMN join_request_enabled INTEGER NOT NULL DEFAULT 0")
            if "is_broadcast" not in channel_settings_columns:
                connection.execute("ALTER TABLE channel_settings ADD COLUMN is_broadcast INTEGER NOT NULL DEFAULT 0")
            if "signatures_enabled" not in channel_settings_columns:
                connection.execute("ALTER TABLE channel_settings ADD COLUMN signatures_enabled INTEGER NOT NULL DEFAULT 0")
            peer_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(peers)").fetchall()
            }
            if "about" not in peer_columns:
                connection.execute("ALTER TABLE peers ADD COLUMN about TEXT NOT NULL DEFAULT ''")
            if "username" not in peer_columns:
                connection.execute("ALTER TABLE peers ADD COLUMN username TEXT")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS peers_username_unique_idx ON peers(username COLLATE NOCASE) WHERE username IS NOT NULL"
            )
            upload_part_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(upload_parts)").fetchall()
            }
            if "user_id" not in upload_part_columns:
                connection.execute("ALTER TABLE upload_parts ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0")
            message_media_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(message_media)").fetchall()
            }
            if "attributes_json" not in message_media_columns:
                connection.execute("ALTER TABLE message_media ADD COLUMN attributes_json TEXT NOT NULL DEFAULT '[]'")

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def now_unix() -> int:
    return int(time.time())
