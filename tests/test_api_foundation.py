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
    response = client.post("/v1/development/users", json={"phone": phone, "first_name": first_name})
    assert response.status_code == 201, response.text
    user_id = response.json()["id"]
    response = client.post("/v1/development/login", json={"phone": phone})
    assert response.status_code == 200, response.text
    return user_id, {"Authorization": f"Bearer {response.json()['access_token']}"}


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
