from __future__ import annotations

import hashlib
import struct
import time

import pytest

from intelligram.mtproto.adapter import MTProtoSessionAdapter
from intelligram.mtproto.crypto import MTProtoSecurityError, aes_ige_decrypt, aes_ige_encrypt, auth_key_id, derive_aes_key_iv
from intelligram.mtproto.tl import MSGS_ACK_CONSTRUCTOR, PING_CONSTRUCTOR, PONG_CONSTRUCTOR, RPC_RESULT_CONSTRUCTOR


def _encrypt_client(auth_key: bytes, *, salt: int, session_id: int, msg_id: int, seq_no: int, body: bytes) -> bytes:
    inner = struct.pack("<QQQII", salt, session_id, msg_id, seq_no, len(body)) + body
    padding_length = 12
    while (len(inner) + padding_length) % 16:
        padding_length += 1
    plaintext = inner + b"\x01" * padding_length
    msg_key = hashlib.sha256(auth_key[88:120] + plaintext).digest()[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=True)
    return struct.pack("<Q", auth_key_id(auth_key)) + msg_key + aes_ige_encrypt(key, iv, plaintext)


def _decrypt_server(auth_key: bytes, envelope: bytes) -> tuple[int, int, int, int, bytes]:
    assert struct.unpack_from("<Q", envelope, 0)[0] == auth_key_id(auth_key)
    msg_key = envelope[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=False)
    plaintext = aes_ige_decrypt(key, iv, envelope[24:])
    assert msg_key == hashlib.sha256(auth_key[96:128] + plaintext).digest()[8:24]
    salt, session_id, msg_id, seq_no, body_length = struct.unpack_from("<QQQII", plaintext, 0)
    return salt, session_id, msg_id, seq_no, plaintext[32:32 + body_length]


def test_encrypted_ping_yields_standards_shaped_rpc_result() -> None:
    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    request_message_id = (int(time.time()) << 32) + 4
    ping_id = 987654321
    request_body = struct.pack("<Iq", PING_CONSTRUCTOR, ping_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)

    response = adapter.handle_encrypted(
        _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=1, body=request_body)
    )

    assert response is not None
    response_salt, response_session, response_message_id, response_seq_no, body = _decrypt_server(auth_key, response)
    assert (response_salt, response_session) == (salt, session_id)
    assert response_message_id % 4 == 1
    assert response_seq_no == 1
    constructor, result_request_id, result_constructor, pong_message_id, pong_ping_id = struct.unpack("<IqIqq", body)
    assert constructor == RPC_RESULT_CONSTRUCTOR
    assert result_request_id == request_message_id
    assert result_constructor == PONG_CONSTRUCTOR
    assert pong_message_id == request_message_id
    assert pong_ping_id == ping_id


def test_msgs_ack_has_no_response_and_replayed_message_is_rejected() -> None:
    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    request_message_id = (int(time.time()) << 32) + 4
    ack_body = struct.pack("<IIi", MSGS_ACK_CONSTRUCTOR, 0x1CB5C415, 0)
    encrypted = _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=0, body=ack_body)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)

    assert adapter.handle_encrypted(encrypted) is None
    with pytest.raises(MTProtoSecurityError, match="MESSAGE_REPLAY"):
        adapter.handle_encrypted(encrypted)


def _tl_bytes(value: bytes) -> bytes:
    encoded = bytes([len(value)]) + value
    return encoded + b"\x00" * (-len(encoded) % 4)


def _wrapped_query(query: bytes) -> bytes:
    from intelligram.mtproto.tl import INIT_CONNECTION_CONSTRUCTOR, INVOKE_WITH_LAYER_CONSTRUCTOR

    metadata = b"".join(_tl_bytes(value) for value in [
        b"IntelliGram Web", b"Linux", b"0.1.0", b"en", b"", b"en",
    ])
    init_connection = (
        struct.pack("<IIi", INIT_CONNECTION_CONSTRUCTOR, 0, 1)
        + metadata
        + query
    )
    return struct.pack("<Ii", INVOKE_WITH_LAYER_CONSTRUCTOR, 220) + init_connection


def test_wrapped_get_config_and_qr_token_are_served_after_authorization() -> None:
    from intelligram.mtproto.tl import (
        AUTH_EXPORT_LOGIN_TOKEN_CONSTRUCTOR,
        AUTH_LOGIN_TOKEN_CONSTRUCTOR,
        CONFIG_CONSTRUCTOR,
        HELP_GET_CONFIG_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        VECTOR_CONSTRUCTOR,
    )

    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    first_message_id = (int(time.time()) << 32) + 4
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, dc_host="127.0.0.1", dc_port=8080)

    config_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=first_message_id,
        seq_no=1,
        body=_wrapped_query(struct.pack("<I", HELP_GET_CONFIG_CONSTRUCTOR)),
    ))
    assert config_response is not None
    _, _, _, _, config_body = _decrypt_server(auth_key, config_response)
    config_reader = TLReader(config_body)
    assert config_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert config_reader.int64() == first_message_id
    assert config_reader.uint32() == CONFIG_CONSTRUCTOR

    token_message_id = first_message_id + 4
    export_query = (
        struct.pack("<Ii", AUTH_EXPORT_LOGIN_TOKEN_CONSTRUCTOR, 1)
        + _tl_bytes(b"intelligram-self-hosted")
        + struct.pack("<Ii", VECTOR_CONSTRUCTOR, 0)
    )
    token_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=token_message_id,
        seq_no=3,
        body=_wrapped_query(export_query),
    ))
    assert token_response is not None
    _, _, _, _, token_body = _decrypt_server(auth_key, token_response)
    token_reader = TLReader(token_body)
    assert token_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert token_reader.int64() == token_message_id
    assert token_reader.uint32() == AUTH_LOGIN_TOKEN_CONSTRUCTOR
    assert token_reader.int32() > int(time.time())
    assert len(token_reader.bytes()) == 32


def test_web_k_sms_free_sign_up_creates_password_backed_account(tmp_path) -> None:
    import base64

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        AUTH_AUTHORIZATION_CONSTRUCTOR,
        AUTH_SEND_CODE_CONSTRUCTOR,
        AUTH_SENT_CODE_SUCCESS_CONSTRUCTOR,
        AUTH_SIGN_UP_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
    )

    # Keep the generated-client constructor explicit: codeSettings#AD253D78?
    # The adapter only requires a constructor word plus zero optional flags.
    code_settings_constructor = 0xAD253D78
    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    database = Database(tmp_path / "account.sqlite3")
    database.initialize()
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database)
    message_id = (int(time.time()) << 32) + 4
    phone = "+15551230000"

    send_code = (
        struct.pack("<I", AUTH_SEND_CODE_CONSTRUCTOR)
        + _tl_bytes(phone.encode())
        + struct.pack("<i", 1)
        + _tl_bytes(b"intelligram-self-hosted")
        + struct.pack("<II", code_settings_constructor, 0)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=send_code
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == AUTH_SENT_CODE_SUCCESS_CONSTRUCTOR

    password = "correct-horse-battery-staple"
    signup = (
        struct.pack("<II", AUTH_SIGN_UP_CONSTRUCTOR, 0)
        + _tl_bytes(phone.encode())
        + _tl_bytes(f"intelligram-register:{base64.b64encode(password.encode()).decode()}".encode())
        + _tl_bytes(b"Ilya")
        + _tl_bytes(b"Researcher")
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=signup
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == AUTH_AUTHORIZATION_CONSTRUCTOR

    from intelligram.mtproto.crypto import auth_key_id

    with database.transaction() as connection:
        user = connection.execute("SELECT id, phone, password_hash FROM users WHERE phone = ?", (phone,)).fetchone()
        binding = connection.execute(
            "SELECT user_id FROM auth_keys WHERE auth_key_id = ?", (str(auth_key_id(auth_key)),)
        ).fetchone()
    assert user is not None
    assert user["password_hash"] is not None
    assert binding is not None
    assert int(binding["user_id"]) == int(user["id"])


def test_web_k_existing_session_login_uses_durable_in_app_code(tmp_path) -> None:
    import json

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        AUTH_AUTHORIZATION_CONSTRUCTOR,
        AUTH_SEND_CODE_CONSTRUCTOR,
        AUTH_SENT_CODE_CONSTRUCTOR,
        AUTH_SENT_CODE_TYPE_APP_CONSTRUCTOR,
        AUTH_SIGN_IN_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
    )
    from intelligram.services.accounts import register_password_account

    code_settings_constructor = 0xAD253D78
    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    database = Database(tmp_path / "existing-session.sqlite3")
    database.initialize()
    phone = "+15551230002"
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone=phone,
            password="correct-horse-battery-staple",
            first_name="Existing",
            device_label="Primary IntelliGram device",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database)
    message_id = (int(time.time()) << 32) + 4

    send_code = (
        struct.pack("<I", AUTH_SEND_CODE_CONSTRUCTOR)
        + _tl_bytes(phone.encode())
        + struct.pack("<i", 1)
        + _tl_bytes(b"intelligram-self-hosted")
        + struct.pack("<II", code_settings_constructor, 0)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=send_code
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == AUTH_SENT_CODE_CONSTRUCTOR
    assert reader.uint32() == 0
    assert reader.uint32() == AUTH_SENT_CODE_TYPE_APP_CONSTRUCTOR
    assert reader.int32() == 6
    challenge_id = reader.bytes().decode()

    with database.transaction() as connection:
        update = connection.execute(
            "SELECT payload_json FROM updates WHERE user_id = ? ORDER BY id DESC LIMIT 1", (issued.user_id,)
        ).fetchone()
    assert update is not None
    payload = json.loads(str(update["payload_json"]))
    assert payload["challenge_id"] == challenge_id
    code = payload["code"]

    sign_in = (
        struct.pack("<II", AUTH_SIGN_IN_CONSTRUCTOR, 1)
        + _tl_bytes(phone.encode())
        + _tl_bytes(challenge_id.encode())
        + _tl_bytes(code.encode())
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=sign_in
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == AUTH_AUTHORIZATION_CONSTRUCTOR


def test_signed_in_web_k_core_rpcs_return_real_tl_entities(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_GET_PRIVACY_CONSTRUCTOR,
        ACCOUNT_PRIVACY_RULES_CONSTRUCTOR,
        ACCOUNT_UPDATE_STATUS_CONSTRUCTOR,
        BOOL_FALSE_CONSTRUCTOR,
        BOOL_TRUE_CONSTRUCTOR,
        CONTACTS_CONTACTS_CONSTRUCTOR,
        CONTACTS_GET_CONTACTS_CONSTRUCTOR,
        DIALOG_CONSTRUCTOR,
        INPUT_PEER_EMPTY_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        INPUT_USER_SELF_CONSTRUCTOR,
        MESSAGES_DIALOGS_CONSTRUCTOR,
        MESSAGES_GET_DIALOGS_CONSTRUCTOR,
        MESSAGES_GET_HISTORY_CONSTRUCTOR,
        MESSAGES_MESSAGES_CONSTRUCTOR,
        MESSAGES_SEND_MESSAGE_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_MESSAGE_ID_CONSTRUCTOR,
        UPDATE_NEW_MESSAGE_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        USER_CONSTRUCTOR,
        USERS_GET_FULL_USER_CONSTRUCTOR,
        USERS_GET_USERS_CONSTRUCTOR,
        USERS_USER_FULL_CONSTRUCTOR,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        encode_vector,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 123, 456
    database = Database(tmp_path / "signed-in-rpcs.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection,
            phone="+15550000101",
            password="correct-horse-battery-staple",
            first_name="Alice",
            device_label="Alice primary",
        )
        bob = register_password_account(
            connection,
            phone="+15550000102",
            password="correct-horse-battery-staple",
            first_name="Bob",
            device_label="Bob primary",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4

    def invoke(query: bytes) -> TLReader:
        nonlocal message_id
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=message_id,
            seq_no=((message_id - ((int(time.time()) << 32) + 4)) // 2) | 1,
            body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == message_id
        message_id += 4
        return reader

    users_reader = invoke(
        encode_uint32(USERS_GET_USERS_CONSTRUCTOR)
        + encode_vector([encode_uint32(INPUT_USER_SELF_CONSTRUCTOR)])
    )
    assert users_reader.uint32() == 0x1CB5C415
    assert users_reader.int32() == 1
    assert users_reader.uint32() == USER_CONSTRUCTOR
    flags = users_reader.uint32()
    assert flags & (1 << 10)
    assert users_reader.uint32() == 0
    assert users_reader.int64() == alice.user_id

    full_reader = invoke(encode_uint32(USERS_GET_FULL_USER_CONSTRUCTOR) + encode_uint32(INPUT_USER_SELF_CONSTRUCTOR))
    assert full_reader.uint32() == USERS_USER_FULL_CONSTRUCTOR

    send_reader = invoke(
        encode_uint32(MESSAGES_SEND_MESSAGE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_tl_string("IntelliGram native MTProto test")
        + encode_int64(901)
    )
    assert send_reader.uint32() == UPDATES_CONSTRUCTOR
    assert send_reader.uint32() == 0x1CB5C415
    assert send_reader.int32() == 2
    assert send_reader.uint32() == UPDATE_MESSAGE_ID_CONSTRUCTOR
    assert send_reader.int32() == 1
    assert send_reader.int64() == 901
    assert send_reader.uint32() == UPDATE_NEW_MESSAGE_CONSTRUCTOR

    dialogs_reader = invoke(
        encode_uint32(MESSAGES_GET_DIALOGS_CONSTRUCTOR)
        + encode_uint32(0)
        + struct.pack("<ii", 0, 0)
        + encode_uint32(INPUT_PEER_EMPTY_CONSTRUCTOR)
        + struct.pack("<i", 30)
        + encode_int64(0)
    )
    assert dialogs_reader.uint32() == MESSAGES_DIALOGS_CONSTRUCTOR
    assert dialogs_reader.uint32() == 0x1CB5C415
    assert dialogs_reader.int32() == 1
    assert dialogs_reader.uint32() == DIALOG_CONSTRUCTOR

    history_reader = invoke(
        encode_uint32(MESSAGES_GET_HISTORY_CONSTRUCTOR)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + struct.pack("<iiiiii", 0, 0, 0, 30, 0, 0)
        + encode_int64(0)
    )
    assert history_reader.uint32() == MESSAGES_MESSAGES_CONSTRUCTOR
    assert history_reader.uint32() == 0x1CB5C415
    assert history_reader.int32() == 1

    contacts_reader = invoke(encode_uint32(CONTACTS_GET_CONTACTS_CONSTRUCTOR) + encode_int64(0))
    assert contacts_reader.uint32() == CONTACTS_CONTACTS_CONSTRUCTOR
    assert contacts_reader.uint32() == 0x1CB5C415
    assert contacts_reader.int32() == 1

    status_reader = invoke(encode_uint32(ACCOUNT_UPDATE_STATUS_CONSTRUCTOR) + encode_uint32(BOOL_FALSE_CONSTRUCTOR))
    assert status_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    privacy_reader = invoke(encode_uint32(ACCOUNT_GET_PRIVACY_CONSTRUCTOR) + encode_uint32(0xBC2EAB30))
    assert privacy_reader.uint32() == ACCOUNT_PRIVACY_RULES_CONSTRUCTOR


def test_web_k_create_chat_returns_messages_invited_users(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_USER_CONSTRUCTOR,
        MESSAGES_CREATE_CHAT_CONSTRUCTOR,
        MESSAGES_INVITED_USERS_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        encode_vector,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 321, 654
    database = Database(tmp_path / "create-chat.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection,
            phone="+15550000111",
            password="correct-horse-battery-staple",
            first_name="Alice",
            device_label="Alice primary",
        )
        bob = register_password_account(
            connection,
            phone="+15550000112",
            password="correct-horse-battery-staple",
            first_name="Bob",
            device_label="Bob primary",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    create_chat = (
        encode_uint32(MESSAGES_CREATE_CHAT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_vector([
            encode_uint32(INPUT_USER_CONSTRUCTOR)
            + encode_int64(bob.user_id)
            + encode_int64(user_access_hash(bob.user_id))
        ])
        + encode_tl_string("IntelliGram Research")
    )

    response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=create_chat,
    ))

    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == MESSAGES_INVITED_USERS_CONSTRUCTOR
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        group = connection.execute(
            "SELECT id, title FROM peers WHERE kind = 'chat' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        members = connection.execute(
            "SELECT user_id FROM peer_memberships WHERE peer_id = ? ORDER BY user_id", (group["id"],)
        ).fetchall()
    assert group is not None
    assert group["title"] == "IntelliGram Research"
    assert [int(member["user_id"]) for member in members] == sorted([alice.user_id, bob.user_id])


def test_web_k_account_update_profile_persists_identity_and_full_user_about(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_UPDATE_PROFILE_CONSTRUCTOR,
        INPUT_USER_SELF_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        USERS_GET_FULL_USER_CONSTRUCTOR,
        USERS_USER_FULL_CONSTRUCTOR,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 654, 987
    database = Database(tmp_path / "update-profile.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone="+15550000121",
            password="correct-horse-battery-staple",
            first_name="Initial",
            device_label="Initial device",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=issued.user_id)
    message_id = (int(time.time()) << 32) + 4
    update_profile = (
        encode_uint32(ACCOUNT_UPDATE_PROFILE_CONSTRUCTOR)
        + encode_uint32(0b111)
        + encode_tl_string("Ilya")
        + encode_tl_string("Researcher")
        + encode_tl_string("Building IntelliGram")
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=update_profile,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id

    full_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(USERS_GET_FULL_USER_CONSTRUCTOR) + encode_uint32(INPUT_USER_SELF_CONSTRUCTOR),
    ))
    assert full_response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, full_response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_reader.int64() == message_id + 4
    assert full_reader.uint32() == USERS_USER_FULL_CONSTRUCTOR

    with database.transaction() as connection:
        row = connection.execute("SELECT first_name, last_name, about FROM users WHERE id = ?", (issued.user_id,)).fetchone()
    assert row is not None
    assert dict(row) == {"first_name": "Ilya", "last_name": "Researcher", "about": "Building IntelliGram"}


def test_web_k_profile_photo_upload_assembles_staged_file_parts(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        INPUT_FILE_CONSTRUCTOR,
        PHOTOS_PHOTO_CONSTRUCTOR,
        PHOTOS_UPLOAD_PROFILE_PHOTO_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPLOAD_SAVE_FILE_PART_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 741, 852
    database = Database(tmp_path / "profile-photo.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone="+15550000141",
            password="correct-horse-battery-staple",
            first_name="Photo",
            device_label="Photo test",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=issued.user_id)
    message_id = (int(time.time()) << 32) + 4
    file_id = 777_001
    content = b"self-hosted-intelligram-profile-photo"

    save_part = (
        encode_uint32(UPLOAD_SAVE_FILE_PART_CONSTRUCTOR)
        + encode_int64(file_id)
        + encode_int32(0)
        + encode_tl_bytes(content)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=save_part,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    input_file = (
        encode_uint32(INPUT_FILE_CONSTRUCTOR)
        + encode_int64(file_id)
        + encode_int32(1)
        + encode_tl_string("avatar.png")
        + encode_tl_string("")
    )
    upload_photo = encode_uint32(PHOTOS_UPLOAD_PROFILE_PHOTO_CONSTRUCTOR) + encode_uint32(1) + input_file
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=upload_photo,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    photo_reader = TLReader(body)
    assert photo_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert photo_reader.int64() == message_id + 4
    assert photo_reader.uint32() == PHOTOS_PHOTO_CONSTRUCTOR

    with database.transaction() as connection:
        photo = connection.execute(
            "SELECT user_id, filename, content FROM profile_photos WHERE user_id = ?", (issued.user_id,)
        ).fetchone()
        user = connection.execute("SELECT profile_photo_id FROM users WHERE id = ?", (issued.user_id,)).fetchone()
    assert photo is not None
    assert int(photo["user_id"]) == issued.user_id
    assert photo["filename"] == "avatar.png"
    assert bytes(photo["content"]) == content
    assert user is not None and user["profile_photo_id"] is not None
