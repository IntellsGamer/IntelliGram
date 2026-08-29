"""Per-account privacy rule storage and evaluation.

Telegram models each privacy setting as an ordered list of rules. Evaluation is
first-match-wins against the viewer, and a viewer matched by no rule is denied
-- which is what makes ``[allow_contacts]`` mean "contacts only" without an
explicit trailing deny.

Rules are persisted as JSON on ``privacy_rules`` because a rule list is ordered
and heterogeneous (``allow_users`` carries an id list), which a relational shape
would only obscure.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from intelligram.database import now_unix

# Canonical key names. These double as the stored ``privacy_rules.key`` value,
# so they must stay stable even if the TL constructor ids change.
KEY_STATUS_TIMESTAMP = "status_timestamp"
KEY_CHAT_INVITE = "chat_invite"
KEY_PHONE_CALL = "phone_call"
KEY_PHONE_P2P = "phone_p2p"
KEY_FORWARDS = "forwards"
KEY_PROFILE_PHOTO = "profile_photo"
KEY_PHONE_NUMBER = "phone_number"
KEY_ADDED_BY_PHONE = "added_by_phone"
KEY_VOICE_MESSAGES = "voice_messages"
KEY_ABOUT = "about"
KEY_BIRTHDAY = "birthday"
KEY_STAR_GIFTS_AUTO_SAVE = "star_gifts_auto_save"
KEY_NO_PAID_MESSAGES = "no_paid_messages"
KEY_SAVED_MUSIC = "saved_music"

ALLOW_ALL = "allow_all"
ALLOW_CONTACTS = "allow_contacts"
ALLOW_PREMIUM = "allow_premium"
ALLOW_USERS = "allow_users"
ALLOW_CLOSE_FRIENDS = "allow_close_friends"
ALLOW_BOTS = "allow_bots"
DISALLOW_ALL = "disallow_all"
DISALLOW_CONTACTS = "disallow_contacts"
DISALLOW_USERS = "disallow_users"
DISALLOW_BOTS = "disallow_bots"

_ALLOW_KINDS = frozenset(
    {ALLOW_ALL, ALLOW_CONTACTS, ALLOW_PREMIUM, ALLOW_USERS, ALLOW_CLOSE_FRIENDS, ALLOW_BOTS}
)

# Telegram ships "everybody" as the default for every key IntelliGram exposes.
# ``added_by_phone`` is the one exception -- contacts only -- matching the
# official clients.
_DEFAULTS: dict[str, str] = {KEY_ADDED_BY_PHONE: ALLOW_CONTACTS}

# Restricting who may send voice and round messages is a Premium feature in
# Telegram; Web K locks the row for free accounts and the server must agree.
PREMIUM_ONLY_KEYS = frozenset({KEY_VOICE_MESSAGES})

# InputPrivacyKey constructor -> canonical key. Keys absent from this map are
# rejected so a client cannot silently store a setting under the wrong name.
# InputPrivacyKey constructor -> canonical key. Keys absent from this map are
# rejected so a client cannot silently store a setting under the wrong name.
# The output PrivacyKey* constructors are accepted too: Web K's settings UI
# round-trips the resolved PrivacyKey from account.getPrivacy through the
# localization of *some* rows, so both spellings reach the server.
_KEY_INPUT_CONSTRUCTORS: dict[int, str] = {
    0x4F96CB18: KEY_STATUS_TIMESTAMP,
    0xBDFB0426: KEY_CHAT_INVITE,
    0xFABADC5F: KEY_PHONE_CALL,
    0xDB9E70D2: KEY_PHONE_P2P,
    0xA4DD4C08: KEY_FORWARDS,
    0x5719BACC: KEY_PROFILE_PHOTO,
    0x0352DAFA: KEY_PHONE_NUMBER,
    0xD1219BDD: KEY_ADDED_BY_PHONE,
    0xAEE69D68: KEY_VOICE_MESSAGES,
    0x3823CC40: KEY_ABOUT,
    0xD65A11CC: KEY_BIRTHDAY,
    0xE1732341: KEY_STAR_GIFTS_AUTO_SAVE,
    0xBDC597B4: KEY_NO_PAID_MESSAGES,
    0x4DBE9226: KEY_SAVED_MUSIC,
}
_OUTPUT_KEY_CONSTRUCTORS: dict[int, str] = {
    0xBC2EAB30: KEY_STATUS_TIMESTAMP,
    0x500E6DFA: KEY_CHAT_INVITE,
    0x3D662B7B: KEY_PHONE_CALL,
    0x39491CC8: KEY_PHONE_P2P,
    0x69EC56A3: KEY_FORWARDS,
    0x96151FED: KEY_PROFILE_PHOTO,
    0xD19AE46D: KEY_PHONE_NUMBER,
    0x42FFD42B: KEY_ADDED_BY_PHONE,
    0x0697F414: KEY_VOICE_MESSAGES,
    0xA486B761: KEY_ABOUT,
    0x2000A518: KEY_BIRTHDAY,
    0x2CA4FDF8: KEY_STAR_GIFTS_AUTO_SAVE,
    0x17D348D2: KEY_NO_PAID_MESSAGES,
    0xFF7A571B: KEY_SAVED_MUSIC,
}
KEY_BY_CONSTRUCTOR: dict[int, str] = {**_KEY_INPUT_CONSTRUCTORS, **_OUTPUT_KEY_CONSTRUCTORS}

# InputPrivacyRule constructor -> rule kind.
_KIND_BY_INPUT_CONSTRUCTOR: dict[int, str] = {
    0x184B35CE: ALLOW_ALL,
    0x0D09E07B: ALLOW_CONTACTS,
    0x131CC67F: ALLOW_USERS,
    0x77CDC9F1: ALLOW_PREMIUM,
    0x2F453E49: ALLOW_CLOSE_FRIENDS,
    0x5A4FCCE5: ALLOW_BOTS,
    0xD66B66C9: DISALLOW_ALL,
    0x0BA52007: DISALLOW_CONTACTS,
    0x90110467: DISALLOW_USERS,
    0xC4E57915: DISALLOW_BOTS,
}

# Rule kind -> PrivacyRule constructor for the response.
_OUTPUT_CONSTRUCTOR_BY_KIND: dict[str, int] = {
    ALLOW_ALL: 0x65427B82,
    ALLOW_CONTACTS: 0xFFFE1BAC,
    ALLOW_USERS: 0xB8905FB2,
    ALLOW_PREMIUM: 0xECE9814B,
    ALLOW_CLOSE_FRIENDS: 0xF7E8D89B,
    ALLOW_BOTS: 0x21461B5D,
    DISALLOW_ALL: 0x8B73E763,
    DISALLOW_CONTACTS: 0xF888FA1A,
    DISALLOW_USERS: 0xE4621141,
    DISALLOW_BOTS: 0xF6A5F82F,
}


def key_for_constructor(constructor_id: int) -> str | None:
    return KEY_BY_CONSTRUCTOR.get(constructor_id)


def rules_from_input(parsed: list[dict]) -> list[PrivacyRule]:
    """Convert parsed InputPrivacyRule payloads into storable rules.

    Chat-scoped rules are dropped: IntelliGram evaluates privacy per viewer, and
    silently treating "these groups" as "everybody" would be worse than the
    client seeing its unsupported rule disappear on reload.
    """
    rules: list[PrivacyRule] = []
    for entry in parsed:
        kind = _KIND_BY_INPUT_CONSTRUCTOR.get(int(entry.get("constructor_id") or 0))
        if kind is None:
            continue
        rules.append(PrivacyRule(kind, tuple(int(user) for user in entry.get("users") or ())))
    return rules


def output_constructor(kind: str) -> int | None:
    return _OUTPUT_CONSTRUCTOR_BY_KIND.get(kind)


@dataclass(frozen=True)
class PrivacyRule:
    kind: str
    users: tuple[int, ...] = ()

    def allows(self, *, viewer_id: int, is_contact: bool, viewer_premium: bool) -> bool | None:
        """Return True/False when this rule decides, or None when it does not apply."""
        if self.kind == ALLOW_ALL:
            return True
        if self.kind == DISALLOW_ALL:
            return False
        if self.kind in (ALLOW_USERS, DISALLOW_USERS):
            if viewer_id not in self.users:
                return None
            return self.kind == ALLOW_USERS
        if self.kind in (ALLOW_CONTACTS, DISALLOW_CONTACTS, ALLOW_CLOSE_FRIENDS):
            # IntelliGram has no close-friends list, so it degrades to contacts
            # rather than silently matching nobody.
            if not is_contact:
                return None
            return self.kind != DISALLOW_CONTACTS
        if self.kind == ALLOW_PREMIUM:
            return True if viewer_premium else None
        if self.kind in (ALLOW_BOTS, DISALLOW_BOTS):
            # No bot accounts exist yet, so a bot-scoped rule never matches.
            return None
        return None


def default_rules(key: str) -> list[PrivacyRule]:
    return [PrivacyRule(_DEFAULTS.get(key, ALLOW_ALL))]


def get_rules(connection: sqlite3.Connection, *, user_id: int, key: str) -> list[PrivacyRule]:
    row = connection.execute(
        "SELECT rules FROM privacy_rules WHERE user_id = ? AND key = ?", (user_id, key)
    ).fetchone()
    if row is None:
        return default_rules(key)
    try:
        payload = json.loads(str(row["rules"]))
    except (TypeError, ValueError):
        return default_rules(key)
    rules = [
        PrivacyRule(str(entry.get("kind")), tuple(int(user) for user in entry.get("users") or ()))
        for entry in payload
        if isinstance(entry, dict) and entry.get("kind")
    ]
    return rules or default_rules(key)


def set_rules(
    connection: sqlite3.Connection, *, user_id: int, key: str, rules: list[PrivacyRule]
) -> list[PrivacyRule]:
    stored = rules or default_rules(key)
    connection.execute(
        """
        INSERT INTO privacy_rules(user_id, key, rules, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id, key) DO UPDATE SET
            rules = excluded.rules,
            updated_at = excluded.updated_at
        """,
        (
            user_id,
            key,
            json.dumps([{"kind": rule.kind, "users": list(rule.users)} for rule in stored]),
            now_unix(),
        ),
    )
    return stored


def is_allowed(
    rules: list[PrivacyRule], *, viewer_id: int, is_contact: bool, viewer_premium: bool = False
) -> bool:
    """Evaluate a rule list first-match-wins, denying an unmatched viewer."""
    for rule in rules:
        decision = rule.allows(
            viewer_id=viewer_id, is_contact=is_contact, viewer_premium=viewer_premium
        )
        if decision is not None:
            return decision
    # A list made only of deny rules leaves everyone else allowed; a list with
    # any allow rule is an allow-list and denies by default.
    return not any(rule.kind in _ALLOW_KINDS for rule in rules)


def viewer_allowed(
    connection: sqlite3.Connection,
    *,
    owner_user_id: int,
    key: str,
    viewer_id: int,
    is_contact: bool,
    viewer_premium: bool = False,
) -> bool:
    """Convenience wrapper: load ``key`` for the owner and evaluate the viewer."""
    if owner_user_id == viewer_id:
        return True
    return is_allowed(
        get_rules(connection, user_id=owner_user_id, key=key),
        viewer_id=viewer_id,
        is_contact=is_contact,
        viewer_premium=viewer_premium,
    )
