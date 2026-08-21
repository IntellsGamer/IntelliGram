from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from intelligram.api.app import create_app
from intelligram.config import Settings


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        database_path=tmp_path / "test.sqlite3",
        host="127.0.0.1",
        port=8080,
        public_base_url="http://testserver",
        token_secret=b"test-secret" * 8,
        development_mode=True,
        development_login_code=None,
        mtproto_dc_id=1,
        mtproto_port=10443,
        mtproto_rsa_private_key_path=tmp_path / "mtproto_private.pem",
        mtproto_rsa_public_key_path=tmp_path / "mtproto_public.pem",
    )
    return TestClient(create_app(settings))


def _register_and_login(client: TestClient, phone: str, first_name: str) -> tuple[int, dict[str, str]]:
    response = client.post(
        "/v1/auth/register",
        json={
            "phone": phone,
            "password": "correct-horse-battery-staple",
            "first_name": first_name,
            "device_label": f"{first_name} primary device",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return body["user_id"], {"Authorization": f"Bearer {body['access_token']}"}


def test_dialog_history_and_difference_recover_after_offline_period(tmp_path: Path) -> None:
    client = _client(tmp_path)
    alice_id, alice_headers = _register_and_login(client, "+15550000001", "Alice")
    bob_id, bob_headers = _register_and_login(client, "+15550000002", "Bob")

    response = client.post("/v1/peers/groups", json={"title": "Research", "member_user_ids": [bob_id]}, headers=alice_headers)
    assert response.status_code == 201, response.text
    peer_id = response.json()["peer_id"]

    response = client.post(
        "/v1/messages",
        json={"peer_id": peer_id, "body": "First durable message", "client_random_id": "client-message-1"},
        headers=alice_headers,
    )
    assert response.status_code == 201, response.text
    assert response.json()["updates_emitted"] == 2
    message_id = response.json()["message"]["id"]

    # A resend with the same random ID is idempotent.
    repeat = client.post(
        "/v1/messages",
        json={"peer_id": peer_id, "body": "First durable message", "client_random_id": "client-message-1"},
        headers=alice_headers,
    )
    assert repeat.status_code == 201
    assert repeat.json()["message"]["id"] == message_id
    assert repeat.json()["updates_emitted"] == 0

    dialogs = client.get("/v1/dialogs", headers=bob_headers)
    assert dialogs.status_code == 200
    assert dialogs.json()["dialogs"][0]["peer_id"] == peer_id
    assert dialogs.json()["dialogs"][0]["unread_count"] == 1

    history = client.get(f"/v1/peers/{peer_id}/history?limit=60", headers=bob_headers)
    assert history.status_code == 200
    assert [message["body"] for message in history.json()["messages"]] == ["First durable message"]

    state_before = client.get("/v1/updates/state", headers=bob_headers).json()
    difference = client.get("/v1/updates/difference?after_pts=0", headers=bob_headers)
    assert difference.status_code == 200
    assert difference.json()["state"]["pts"] == state_before["pts"]
    assert any(update["@type"] == "updateNewMessage" for update in difference.json()["updates"])


def test_protected_resources_require_valid_session(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/v1/dialogs")
    assert response.status_code == 401
    assert response.json()["detail"] == "AUTH_KEY_UNREGISTERED"


def test_sms_free_registration_password_login_and_in_app_device_code(tmp_path: Path) -> None:
    client = _client(tmp_path)
    phone = "+15550000003"
    password = "correct-horse-battery-staple"

    registration = client.post(
        "/v1/auth/register",
        json={
            "phone": phone,
            "password": password,
            "first_name": "Ilya",
            "device_label": "Primary IntelliGram Web K",
        },
    )
    assert registration.status_code == 201, registration.text
    primary_headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}

    password_session = client.post(
        "/v1/auth/login/password",
        json={"phone": "1 (555) 000-0003", "password": password, "device_label": "Recovery device"},
    )
    assert password_session.status_code == 200, password_session.text
    assert password_session.json()["user_id"] == registration.json()["user_id"]

    start = client.post(
        "/v1/auth/login/start",
        json={"phone": phone, "device_label": "New IntelliGram Web K browser"},
    )
    assert start.status_code == 200, start.text
    assert start.json()["status"] == "in_app_code_sent"
    challenge_id = start.json()["challenge_id"]
    assert isinstance(challenge_id, str)

    in_app_updates = client.get("/v1/updates/difference?after_pts=0", headers=primary_headers)
    assert in_app_updates.status_code == 200, in_app_updates.text
    login_update = next(update for update in in_app_updates.json()["updates"] if update["@type"] == "updateIntelliGramLoginCode")
    assert login_update["payload"]["challenge_id"] == challenge_id
    code = login_update["payload"]["code"]
    assert code.isdigit() and len(code) == 6

    completed = client.post(
        "/v1/auth/login/complete",
        json={
            "phone": phone,
            "challenge_id": challenge_id,
            "code": code,
            "device_label": "New IntelliGram Web K browser",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["user_id"] == registration.json()["user_id"]


def test_active_primary_session_receives_in_app_code_for_second_browser(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/v1/auth/register",
        json={
            "phone": "+15550000004",
            "password": "correct-horse-battery-staple",
            "first_name": "Nika",
        },
    )
    assert response.status_code == 201

    # Registration created the primary password-authenticated session, so a
    # subsequent browser receives an in-app code rather than an SMS message.
    start = client.post(
        "/v1/auth/login/start",
        json={"phone": "+15550000004", "device_label": "Second browser"},
    )
    assert start.status_code == 200
    assert start.json()["status"] == "in_app_code_sent"


def test_application_restores_persisted_mtproto_authorization_key(tmp_path: Path) -> None:
    from intelligram.database import Database, now_unix

    database_path = tmp_path / "restored.sqlite3"
    settings = Settings(
        database_path=database_path,
        host="127.0.0.1",
        port=8080,
        public_base_url="http://testserver",
        token_secret=b"test-secret" * 8,
        development_mode=True,
        development_login_code=None,
        mtproto_dc_id=1,
        mtproto_port=10443,
        mtproto_rsa_private_key_path=tmp_path / "restored_private.pem",
        mtproto_rsa_public_key_path=tmp_path / "restored_public.pem",
    )
    database = Database(database_path)
    database.initialize()
    auth_key_id = "123456789"
    auth_key = bytes(range(256))
    with database.transaction(immediate=True) as connection:
        user = connection.execute(
            """
            INSERT INTO users(phone, first_name, last_name, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("+15550000005", "Restored", "", "scrypt$placeholder", now_unix(), now_unix()),
        )
        connection.execute(
            """
            INSERT INTO auth_keys(
                auth_key_id, user_id, key_fingerprint, key_material, server_salt, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (auth_key_id, int(user.lastrowid), f"mtproto:{auth_key_id}", auth_key, "987654321", now_unix()),
        )

    app = create_app(settings)
    restored = app.state.mtproto_auth_keys[int(auth_key_id)]
    assert restored.auth_key == auth_key
    assert restored.server_salt == 987654321
