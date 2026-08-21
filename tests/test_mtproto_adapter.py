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


def test_web_k_upload_get_file_returns_persisted_profile_photo_bytes(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PHOTO_FILE_LOCATION_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        STORAGE_FILE_UNKNOWN_CONSTRUCTOR,
        TLReader,
        UPLOAD_FILE_CONSTRUCTOR,
        UPLOAD_GET_FILE_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 963, 852
    database = Database(tmp_path / "profile-photo-download.sqlite3")
    database.initialize()
    content = b"intelligram-avatar-download-content"
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone="+15550000142",
            password="correct-horse-battery-staple",
            first_name="Download",
            device_label="Photo download test",
        )
        photo = connection.execute(
            """
            INSERT INTO profile_photos(user_id, source_file_id, filename, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (issued.user_id, 99, "avatar.png", content, int(time.time())),
        )
        photo_id = int(photo.lastrowid)
        connection.execute("UPDATE users SET profile_photo_id = ? WHERE id = ?", (photo_id, issued.user_id))
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=issued.user_id)
    message_id = (int(time.time()) << 32) + 4
    get_file = (
        encode_uint32(UPLOAD_GET_FILE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PHOTO_FILE_LOCATION_CONSTRUCTOR)
        + encode_int64(photo_id)
        + encode_int64((photo_id << 32) | 1)
        + encode_tl_bytes(f"intelligram-photo:{photo_id}".encode("ascii"))
        + encode_tl_string("m")
        + encode_int64(0)
        + encode_int32(len(content))
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=get_file,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPLOAD_FILE_CONSTRUCTOR
    assert reader.uint32() == STORAGE_FILE_UNKNOWN_CONSTRUCTOR
    assert reader.int32() > 0
    assert reader.bytes() == content


def test_web_k_updates_get_difference_replays_durable_message(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_DIFFERENCE_CONSTRUCTOR,
        UPDATES_GET_DIFFERENCE_CONSTRUCTOR,
        encode_int32,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    auth_key = bytes(range(256))
    salt, session_id = 159, 753
    database = Database(tmp_path / "updates-difference.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection,
            phone="+15550000151",
            password="correct-horse-battery-staple",
            first_name="Alice",
            device_label="Alice device",
        )
        bob = register_password_account(
            connection,
            phone="+15550000152",
            password="correct-horse-battery-staple",
            first_name="Bob",
            device_label="Bob device",
        )
        peer_id = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        send_message(
            connection,
            peer_id=peer_id,
            sender_user_id=alice.user_id,
            body="durable difference message",
            client_random_id="difference-1",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=bob.user_id)
    message_id = (int(time.time()) << 32) + 4
    get_difference = (
        encode_uint32(UPDATES_GET_DIFFERENCE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(0)
        + encode_int32(0)
        + encode_int32(0)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=get_difference,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPDATES_DIFFERENCE_CONSTRUCTOR
    assert reader.uint32() == 0x1CB5C415
    assert reader.int32() == 1


def test_web_k_messages_get_full_chat_returns_durable_members(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        MESSAGES_CREATE_CHAT_CONSTRUCTOR,
        MESSAGES_GET_FULL_CHAT_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        encode_vector,
        user_access_hash,
        INPUT_USER_CONSTRUCTOR,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 456, 789
    database = Database(tmp_path / "full-chat.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000161", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000162", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    create_chat = (
        encode_uint32(MESSAGES_CREATE_CHAT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_vector([encode_uint32(INPUT_USER_CONSTRUCTOR) + encode_int64(bob.user_id) + encode_int64(user_access_hash(bob.user_id))])
        + encode_tl_string("Full chat")
    )
    created = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=create_chat,
    ))
    assert created is not None
    with database.transaction() as connection:
        chat_id = int(connection.execute("SELECT id FROM peers WHERE kind = 'chat' ORDER BY id DESC LIMIT 1").fetchone()["id"])
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(MESSAGES_GET_FULL_CHAT_CONSTRUCTOR) + encode_int64(chat_id),
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR


def test_web_k_everyday_read_typing_peer_settings_and_logout_rpcs(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        AUTH_LOGGED_OUT_CONSTRUCTOR,
        AUTH_LOG_OUT_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR,
        MESSAGES_GET_PEER_SETTINGS_CONSTRUCTOR,
        MESSAGES_PEER_SETTINGS_CONSTRUCTOR,
        MESSAGES_READ_HISTORY_CONSTRUCTOR,
        MESSAGES_SET_TYPING_CONSTRUCTOR,
        PEER_SETTINGS_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_int64,
        encode_uint32,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    auth_key = bytes(range(256))
    salt, session_id = 918, 193
    database = Database(tmp_path / "everyday-rpcs.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000171", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000172", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        peer_id = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        stored, _ = send_message(
            connection, peer_id=peer_id, sender_user_id=bob.user_id, body="Unread", client_random_id="bob-unread",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    adapter._associate_auth_key(alice.user_id)
    input_bob = encode_uint32(INPUT_PEER_USER_CONSTRUCTOR) + encode_int64(bob.user_id) + encode_int64(user_access_hash(bob.user_id))
    message_id = (int(time.time()) << 32) + 4

    read_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(MESSAGES_READ_HISTORY_CONSTRUCTOR) + input_bob + encode_int32(int(stored["id"])),
    ))
    assert read_response is not None
    _, _, _, _, read_body = _decrypt_server(auth_key, read_response)
    reader = TLReader(read_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR
    assert reader.int32() > 0
    assert reader.int32() == 1
    with database.transaction() as connection:
        dialog = connection.execute(
            "SELECT unread_count, read_inbox_max_id FROM dialogs WHERE user_id = ? AND peer_id = ?",
            (alice.user_id, peer_id),
        ).fetchone()
        assert dialog is not None
        assert (int(dialog["unread_count"]), int(dialog["read_inbox_max_id"])) == (0, int(stored["id"]))

    settings_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(MESSAGES_GET_PEER_SETTINGS_CONSTRUCTOR) + input_bob,
    ))
    assert settings_response is not None
    _, _, _, _, settings_body = _decrypt_server(auth_key, settings_response)
    reader = TLReader(settings_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == MESSAGES_PEER_SETTINGS_CONSTRUCTOR
    assert reader.uint32() == PEER_SETTINGS_CONSTRUCTOR
    assert reader.uint32() == 0

    typing_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 8,
        seq_no=5,
        body=encode_uint32(MESSAGES_SET_TYPING_CONSTRUCTOR) + encode_uint32(0) + input_bob + encode_uint32(0x16BF744E),
    ))
    assert typing_response is not None
    _, _, _, _, typing_body = _decrypt_server(auth_key, typing_response)
    reader = TLReader(typing_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 8
    assert reader.uint32() == 0x997275B5

    logout_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 12,
        seq_no=7,
        body=encode_uint32(AUTH_LOG_OUT_CONSTRUCTOR),
    ))
    assert logout_response is not None
    _, _, _, _, logout_body = _decrypt_server(auth_key, logout_response)
    reader = TLReader(logout_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 12
    assert reader.uint32() == AUTH_LOGGED_OUT_CONSTRUCTOR
    assert reader.uint32() == 0
    with database.transaction() as connection:
        auth_row = connection.execute(
            "SELECT revoked_at FROM auth_keys WHERE auth_key_id = ?", (str(auth_key_id(auth_key)),)
        ).fetchone()
        assert auth_row is not None and auth_row["revoked_at"] is not None


def test_web_k_messages_create_chat_permits_owner_only_group(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        MESSAGES_CREATE_CHAT_CONSTRUCTOR,
        MESSAGES_INVITED_USERS_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_tl_string,
        encode_uint32,
        encode_vector,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 919, 194
    database = Database(tmp_path / "owner-only-group.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000181", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    message_id = (int(time.time()) << 32) + 4
    request = (
        encode_uint32(MESSAGES_CREATE_CHAT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_vector([])
        + encode_tl_string("Solo group")
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=request,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == MESSAGES_INVITED_USERS_CONSTRUCTOR
    with database.transaction() as connection:
        chat = connection.execute("SELECT id FROM peers WHERE kind = 'chat'").fetchone()
        assert chat is not None
        members = connection.execute(
            "SELECT user_id, role FROM peer_memberships WHERE peer_id = ? AND left_at IS NULL", (int(chat["id"]),)
        ).fetchall()
        assert [(int(row["user_id"]), str(row["role"])) for row in members] == [(owner.user_id, "owner")]


def test_web_k_startup_langpack_and_countries_calls_receive_valid_responses() -> None:
    from intelligram.mtproto.tl import (
        HELP_COUNTRIES_LIST_CONSTRUCTOR,
        HELP_GET_COUNTRIES_LIST_CONSTRUCTOR,
        LANG_PACK_DIFFERENCE_CONSTRUCTOR,
        LANGPACK_GET_LANG_PACK_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_tl_string,
        encode_uint32,
    )

    auth_key = bytes(range(256))
    salt, session_id = 920, 195
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)
    message_id = (int(time.time()) << 32) + 4
    langpack_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(LANGPACK_GET_LANG_PACK_CONSTRUCTOR) + encode_tl_string("web") + encode_tl_string("en"),
    ))
    assert langpack_response is not None
    _, _, _, _, langpack_body = _decrypt_server(auth_key, langpack_response)
    reader = TLReader(langpack_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == LANG_PACK_DIFFERENCE_CONSTRUCTOR
    assert reader.bytes() == b"en"
    assert (reader.int32(), reader.int32()) == (0, 0)
    assert reader.vector_count() == 0

    countries_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(HELP_GET_COUNTRIES_LIST_CONSTRUCTOR) + encode_tl_string("en") + encode_int32(0),
    ))
    assert countries_response is not None
    _, _, _, _, countries_body = _decrypt_server(auth_key, countries_response)
    reader = TLReader(countries_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == HELP_COUNTRIES_LIST_CONSTRUCTOR
    assert reader.vector_count() == 0
    assert reader.int32() == 0


def test_web_k_contacts_resolve_username_returns_self_hosted_user_entities(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CONTACTS_RESOLVE_USERNAME_CONSTRUCTOR,
        CONTACTS_RESOLVED_PEER_CONSTRUCTOR,
        PEER_USER_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        USER_CONSTRUCTOR,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 921, 196
    database = Database(tmp_path / "resolve-username.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000191", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000192", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        connection.execute("UPDATE users SET username = ? WHERE id = ?", ("IntelliGramBob", bob.user_id))
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(CONTACTS_RESOLVE_USERNAME_CONSTRUCTOR) + encode_uint32(0) + encode_tl_string("@intelligrambob"),
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == CONTACTS_RESOLVED_PEER_CONSTRUCTOR
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    assert reader.vector_count() == 0
    assert reader.vector_count() == 2
    # User objects are variable length; the first entity constructor confirms
    # that the resolved-peer wrapper starts the expected entity vector.
    assert reader.uint32() == USER_CONSTRUCTOR


def test_web_k_updates_get_difference_replays_durable_read_history(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        PEER_USER_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_READ_HISTORY_INBOX_CONSTRUCTOR,
        UPDATES_DIFFERENCE_CONSTRUCTOR,
        UPDATES_GET_DIFFERENCE_CONSTRUCTOR,
        encode_int32,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, read_history, send_message

    auth_key = bytes(range(256))
    salt, session_id = 922, 197
    database = Database(tmp_path / "read-history-difference.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000201", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000202", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        peer_id = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        stored, _ = send_message(
            connection, peer_id=peer_id, sender_user_id=alice.user_id, body="Read me", client_random_id="read-difference",
        )
        read_update = read_history(connection, peer_id=peer_id, user_id=bob.user_id, max_id=int(stored["id"]))
        assert read_update is not None
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=bob.user_id)
    message_id = (int(time.time()) << 32) + 4
    request = (
        encode_uint32(UPDATES_GET_DIFFERENCE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(read_update.pts - 1)
        + encode_int32(0)
        + encode_int32(0)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=request,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPDATES_DIFFERENCE_CONSTRUCTOR
    assert reader.vector_count() == 0  # new_messages
    assert reader.vector_count() == 0  # new_encrypted_messages
    assert reader.vector_count() == 1  # other_updates
    assert reader.uint32() == UPDATE_READ_HISTORY_INBOX_CONSTRUCTOR
    assert reader.uint32() == 0  # flags
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == alice.user_id
    assert reader.int32() == int(stored["id"])
    assert reader.int32() == 0
    assert reader.int32() == read_update.pts
    assert reader.int32() == read_update.pts_count


def test_web_k_group_membership_and_metadata_operations_are_durable(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_CHAT_CONSTRUCTOR,
        INPUT_USER_CONSTRUCTOR,
        MESSAGES_ADD_CHAT_USER_CONSTRUCTOR,
        MESSAGES_CREATE_CHAT_CONSTRUCTOR,
        MESSAGES_DELETE_CHAT_USER_CONSTRUCTOR,
        MESSAGES_EDIT_CHAT_ABOUT_CONSTRUCTOR,
        MESSAGES_EDIT_CHAT_TITLE_CONSTRUCTOR,
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
    salt, session_id = 923, 198
    database = Database(tmp_path / "group-management.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000211", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
        member = register_password_account(
            connection, phone="+15550000212", password="correct-horse-battery-staple", first_name="Member", device_label="Member",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    message_id = (int(time.time()) << 32) + 4

    create_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=(
            encode_uint32(MESSAGES_CREATE_CHAT_CONSTRUCTOR) + encode_uint32(0) + encode_vector([]) + encode_tl_string("Management group")
        ),
    ))
    assert create_response is not None
    with database.transaction() as connection:
        row = connection.execute("SELECT id FROM peers WHERE kind = 'chat'").fetchone()
        assert row is not None
        chat_id = int(row["id"])

    add_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=(
            encode_uint32(MESSAGES_ADD_CHAT_USER_CONSTRUCTOR)
            + encode_int64(chat_id)
            + encode_uint32(INPUT_USER_CONSTRUCTOR)
            + encode_int64(member.user_id)
            + encode_int64(user_access_hash(member.user_id))
            + encode_uint32(0)
        ),
    ))
    assert add_response is not None
    _, _, _, _, add_body = _decrypt_server(auth_key, add_response)
    reader = TLReader(add_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == MESSAGES_INVITED_USERS_CONSTRUCTOR
    with database.transaction() as connection:
        membership = connection.execute(
            "SELECT role, left_at FROM peer_memberships WHERE peer_id = ? AND user_id = ?", (chat_id, member.user_id)
        ).fetchone()
        assert membership is not None and membership["role"] == "member" and membership["left_at"] is None

    title_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 8,
        seq_no=5,
        body=encode_uint32(MESSAGES_EDIT_CHAT_TITLE_CONSTRUCTOR) + encode_int64(chat_id) + encode_tl_string("Renamed group"),
    ))
    assert title_response is not None
    _, _, _, _, title_body = _decrypt_server(auth_key, title_response)
    reader = TLReader(title_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 8
    assert reader.uint32() == UPDATES_CONSTRUCTOR

    about_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 12,
        seq_no=7,
        body=(
            encode_uint32(MESSAGES_EDIT_CHAT_ABOUT_CONSTRUCTOR)
            + encode_uint32(INPUT_PEER_CHAT_CONSTRUCTOR)
            + encode_int64(chat_id)
            + encode_tl_string("A durable group description")
        ),
    ))
    assert about_response is not None
    with database.transaction() as connection:
        peer = connection.execute("SELECT title, about FROM peers WHERE id = ?", (chat_id,)).fetchone()
        assert peer is not None
        assert (peer["title"], peer["about"]) == ("Renamed group", "A durable group description")

    delete_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 16,
        seq_no=9,
        body=(
            encode_uint32(MESSAGES_DELETE_CHAT_USER_CONSTRUCTOR)
            + encode_uint32(0)
            + encode_int64(chat_id)
            + encode_uint32(INPUT_USER_CONSTRUCTOR)
            + encode_int64(member.user_id)
            + encode_int64(user_access_hash(member.user_id))
        ),
    ))
    assert delete_response is not None
    with database.transaction() as connection:
        membership = connection.execute(
            "SELECT left_at FROM peer_memberships WHERE peer_id = ? AND user_id = ?", (chat_id, member.user_id)
        ).fetchone()
        assert membership is not None and membership["left_at"] is not None


def test_web_k_updates_get_difference_replays_group_participant_change(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CHAT_PARTICIPANTS_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_CHAT_PARTICIPANTS_CONSTRUCTOR,
        UPDATES_DIFFERENCE_CONSTRUCTOR,
        UPDATES_GET_DIFFERENCE_CONSTRUCTOR,
        encode_int32,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import add_chat_user, create_group

    auth_key = bytes(range(256))
    salt, session_id = 924, 199
    database = Database(tmp_path / "group-update-difference.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000221", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
        member = register_password_account(
            connection, phone="+15550000222", password="correct-horse-battery-staple", first_name="Member", device_label="Member",
        )
        chat_id, create_updates = create_group(
            connection, owner_user_id=owner.user_id, title="Update group", member_user_ids=[]
        )
        assert len(create_updates) == 1
        membership_updates = add_chat_user(
            connection, chat_id=chat_id, actor_user_id=owner.user_id, added_user_id=member.user_id
        )
        owner_update = next(item for item in membership_updates if item.user_id == owner.user_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    message_id = (int(time.time()) << 32) + 4
    request = (
        encode_uint32(UPDATES_GET_DIFFERENCE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(owner_update.pts - 1)
        + encode_int32(0)
        + encode_int32(0)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=request,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPDATES_DIFFERENCE_CONSTRUCTOR
    assert reader.vector_count() == 0
    assert reader.vector_count() == 0
    assert reader.vector_count() == 1
    assert reader.uint32() == UPDATE_CHAT_PARTICIPANTS_CONSTRUCTOR
    assert reader.uint32() == CHAT_PARTICIPANTS_CONSTRUCTOR
    assert reader.int64() == chat_id
    assert reader.vector_count() == 2


def test_web_k_message_edit_and_revoke_delete_are_durable_and_replayable(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR,
        MESSAGES_DELETE_MESSAGES_CONSTRUCTOR,
        MESSAGES_EDIT_MESSAGE_CONSTRUCTOR,
        PEER_USER_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_DELETE_MESSAGES_CONSTRUCTOR,
        UPDATE_EDIT_MESSAGE_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        UPDATES_DIFFERENCE_CONSTRUCTOR,
        UPDATES_GET_DIFFERENCE_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        encode_vector_ints,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    auth_key = bytes(range(256))
    salt, session_id = 925, 200
    database = Database(tmp_path / "message-lifecycle.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000231", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000232", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        peer_id = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        stored, _ = send_message(
            connection, peer_id=peer_id, sender_user_id=alice.user_id, body="Before edit", client_random_id="lifecycle-1",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    input_bob = encode_uint32(INPUT_PEER_USER_CONSTRUCTOR) + encode_int64(bob.user_id) + encode_int64(user_access_hash(bob.user_id))
    message_id = (int(time.time()) << 32) + 4
    edit_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=(
            encode_uint32(MESSAGES_EDIT_MESSAGE_CONSTRUCTOR)
            + encode_uint32(1 << 11)
            + input_bob
            + encode_int32(int(stored["id"]))
            + encode_tl_string("After edit")
        ),
    ))
    assert edit_response is not None
    _, _, _, _, edit_body = _decrypt_server(auth_key, edit_response)
    reader = TLReader(edit_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        row = connection.execute("SELECT body, edited_at FROM messages WHERE id = ?", (int(stored["id"]),)).fetchone()
        assert row is not None and row["body"] == "After edit" and row["edited_at"] is not None

    edit_difference = (
        encode_uint32(UPDATES_GET_DIFFERENCE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(1)
        + encode_int32(0)
        + encode_int32(0)
    )
    difference_response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=edit_difference,
    ))
    assert difference_response is not None
    _, _, _, _, difference_body = _decrypt_server(auth_key, difference_response)
    reader = TLReader(difference_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == UPDATES_DIFFERENCE_CONSTRUCTOR
    assert reader.vector_count() == 0
    assert reader.vector_count() == 0
    assert reader.vector_count() == 1
    assert reader.uint32() == UPDATE_EDIT_MESSAGE_CONSTRUCTOR

    delete_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 8,
        seq_no=5,
        body=encode_uint32(MESSAGES_DELETE_MESSAGES_CONSTRUCTOR) + encode_uint32(1) + encode_vector_ints([int(stored["id"])]) ,
    ))
    assert delete_response is not None
    _, _, _, _, delete_body = _decrypt_server(auth_key, delete_response)
    reader = TLReader(delete_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 8
    assert reader.uint32() == MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR
    assert reader.int32() > 0
    assert reader.int32() == 1
    with database.transaction() as connection:
        row = connection.execute("SELECT deleted_at FROM messages WHERE id = ?", (int(stored["id"]),)).fetchone()
        assert row is not None and row["deleted_at"] is not None

    delete_difference = (
        encode_uint32(UPDATES_GET_DIFFERENCE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(2)
        + encode_int32(0)
        + encode_int32(0)
    )
    deleted_difference_response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 12, seq_no=7, body=delete_difference,
    ))
    assert deleted_difference_response is not None
    _, _, _, _, deleted_difference_body = _decrypt_server(auth_key, deleted_difference_response)
    reader = TLReader(deleted_difference_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 12
    assert reader.uint32() == UPDATES_DIFFERENCE_CONSTRUCTOR
    assert reader.vector_count() == 0
    assert reader.vector_count() == 0
    assert reader.vector_count() == 1
    assert reader.uint32() == UPDATE_DELETE_MESSAGES_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.int32() == int(stored["id"])


def test_web_k_forwards_text_message_into_saved_messages(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_SELF_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_int64,
        encode_uint32,
        encode_vector_ints,
        encode_vector_longs,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    auth_key = bytes(range(256))
    salt, session_id = 926, 201
    database = Database(tmp_path / "forward-message.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000241", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000242", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        source_peer = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        stored, _ = send_message(
            connection, peer_id=source_peer, sender_user_id=bob.user_id, body="Forwardable", client_random_id="forward-source",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    request = (
        encode_uint32(MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_vector_ints([int(stored["id"])])
        + encode_vector_longs([987_654_321])
        + encode_uint32(INPUT_PEER_SELF_CONSTRUCTOR)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=request,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        saved_peer = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=alice.user_id)
        forwarded = connection.execute(
            "SELECT body, sender_user_id FROM messages WHERE peer_id = ? ORDER BY id DESC LIMIT 1", (saved_peer,)
        ).fetchone()
        assert forwarded is not None
        assert (forwarded["body"], int(forwarded["sender_user_id"])) == ("Forwardable", alice.user_id)


def test_web_k_contacts_import_and_search_are_durable(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CONTACTS_FOUND_CONSTRUCTOR,
        CONTACTS_IMPORT_CONTACTS_CONSTRUCTOR,
        CONTACTS_IMPORTED_CONTACTS_CONSTRUCTOR,
        CONTACTS_SEARCH_CONSTRUCTOR,
        IMPORTED_CONTACT_CONSTRUCTOR,
        INPUT_PHONE_CONTACT_CONSTRUCTOR,
        PEER_USER_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        encode_vector,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 929, 202
    database = Database(tmp_path / "contact-discovery.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000251", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000252", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        connection.execute("UPDATE users SET username = ? WHERE id = ?", ("bob_search", bob.user_id))
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    input_contact = (
        encode_uint32(INPUT_PHONE_CONTACT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(7001)
        + encode_tl_string("+1 (555) 000-0252")
        + encode_tl_string("Bob")
        + encode_tl_string("Imported")
    )
    import_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(CONTACTS_IMPORT_CONTACTS_CONSTRUCTOR) + encode_vector([input_contact]),
    ))
    assert import_response is not None
    _, _, _, _, import_body = _decrypt_server(auth_key, import_response)
    reader = TLReader(import_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == CONTACTS_IMPORTED_CONTACTS_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == IMPORTED_CONTACT_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    assert reader.int64() == 7001
    with database.transaction() as connection:
        contact = connection.execute(
            "SELECT client_id FROM contacts WHERE user_id = ? AND contact_user_id = ?", (alice.user_id, bob.user_id)
        ).fetchone()
        assert contact is not None and int(contact["client_id"]) == 7001

    search_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(CONTACTS_SEARCH_CONSTRUCTOR) + encode_uint32(0) + encode_tl_string("bob") + encode_int32(20),
    ))
    assert search_response is not None
    _, _, _, _, search_body = _decrypt_server(auth_key, search_response)
    reader = TLReader(search_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == CONTACTS_FOUND_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    assert reader.vector_count() == 0
