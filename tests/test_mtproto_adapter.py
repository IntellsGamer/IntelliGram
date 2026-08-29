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


def test_web_k_chat_startup_compatibility_calls_return_valid_results() -> None:
    from intelligram.mtproto.tl import (
        ACCOUNT_CONTENT_SETTINGS_CONSTRUCTOR,
        ACCOUNT_GET_CONTENT_SETTINGS_CONSTRUCTOR,
        HELP_APP_CONFIG_CONSTRUCTOR,
        HELP_GET_APP_CONFIG_CONSTRUCTOR,
        JSON_OBJECT_CONSTRUCTOR,
        COMMUNITIES_GET_JOINED_COMMUNITIES_CONSTRUCTOR,
        MESSAGES_AVAILABLE_REACTIONS_CONSTRUCTOR,
        MESSAGES_CHATS_CONSTRUCTOR,
        MESSAGES_GET_AVAILABLE_REACTIONS_CONSTRUCTOR,
        MESSAGES_GET_PAID_REACTION_PRIVACY_CONSTRUCTOR,
        PING_DELAY_DISCONNECT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        VECTOR_CONSTRUCTOR,
    )

    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)
    base_message_id = (int(time.time()) << 32) + 4
    requests = [
        (struct.pack("<Iqi", PING_DELAY_DISCONNECT_CONSTRUCTOR, 345, 30), PONG_CONSTRUCTOR),
        (struct.pack("<I", ACCOUNT_GET_CONTENT_SETTINGS_CONSTRUCTOR), ACCOUNT_CONTENT_SETTINGS_CONSTRUCTOR),
        (struct.pack("<Ii", HELP_GET_APP_CONFIG_CONSTRUCTOR, 17), HELP_APP_CONFIG_CONSTRUCTOR),
        (struct.pack("<I", MESSAGES_GET_PAID_REACTION_PRIVACY_CONSTRUCTOR), UPDATES_CONSTRUCTOR),
        (struct.pack("<Ii", MESSAGES_GET_AVAILABLE_REACTIONS_CONSTRUCTOR, 0), MESSAGES_AVAILABLE_REACTIONS_CONSTRUCTOR),
        (struct.pack("<I", COMMUNITIES_GET_JOINED_COMMUNITIES_CONSTRUCTOR), MESSAGES_CHATS_CONSTRUCTOR),
    ]

    for index, (request_body, expected_constructor) in enumerate(requests):
        request_message_id = base_message_id + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id,
            seq_no=index * 2 + 1,
            body=request_body,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        assert reader.uint32() == expected_constructor
        if expected_constructor == PONG_CONSTRUCTOR:
            assert reader.int64() == request_message_id
            assert reader.int64() == 345
        elif expected_constructor == ACCOUNT_CONTENT_SETTINGS_CONSTRUCTOR:
            assert reader.uint32() == 0
        elif expected_constructor == HELP_APP_CONFIG_CONSTRUCTOR:
            assert reader.int32() == 17
            assert reader.uint32() == JSON_OBJECT_CONSTRUCTOR
            assert reader.uint32() == VECTOR_CONSTRUCTOR
            # Tiered upload caps plus the Premium feature order.
            assert reader.int32() == 3
        elif expected_constructor == MESSAGES_AVAILABLE_REACTIONS_CONSTRUCTOR:
            assert reader.int32() == 0
            assert reader.uint32() == VECTOR_CONSTRUCTOR
            assert reader.int32() == 0
        elif expected_constructor == MESSAGES_CHATS_CONSTRUCTOR:
            assert reader.uint32() == VECTOR_CONSTRUCTOR
            assert reader.int32() == 0


def test_web_k_initial_emoji_catalogue_requests_receive_full_empty_results() -> None:
    from intelligram.mtproto.tl import (
        MESSAGES_ALL_STICKERS_CONSTRUCTOR,
        MESSAGES_EMOJI_GROUPS_CONSTRUCTOR,
        MESSAGES_GET_EMOJI_GROUPS_CONSTRUCTOR,
        MESSAGES_GET_EMOJI_STICKERS_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        VECTOR_CONSTRUCTOR,
    )

    auth_key = bytes(range(256))
    salt, session_id = 91, 17
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt)
    base_message_id = (int(time.time()) << 32) + 4
    requests = [
        (struct.pack("<Ii", MESSAGES_GET_EMOJI_GROUPS_CONSTRUCTOR, 0), MESSAGES_EMOJI_GROUPS_CONSTRUCTOR, "int"),
        (struct.pack("<Iq", MESSAGES_GET_EMOJI_STICKERS_CONSTRUCTOR, 0), MESSAGES_ALL_STICKERS_CONSTRUCTOR, "long"),
    ]

    for index, (request_body, expected_constructor, hash_width) in enumerate(requests):
        request_message_id = base_message_id + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id,
            seq_no=index * 2 + 1,
            body=request_body,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        assert reader.uint32() == expected_constructor
        assert (reader.int32() if hash_width == "int" else reader.int64()) == 0
        assert reader.uint32() == VECTOR_CONSTRUCTOR
        assert reader.int32() == 0


def _tl_bytes(value: bytes) -> bytes:
    if len(value) < 254:
        encoded = bytes([len(value)]) + value
    elif len(value) < 1 << 24:
        encoded = b"\xfe" + len(value).to_bytes(3, "little") + value
    else:
        raise ValueError("test TL byte value exceeds the protocol limit")
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

    # The app-code is also a normal incoming message from the local
    # IntelliGram service identity, so an unmodified Web K session has a real
    # dialog/message surface to render instead of an unhandled custom update.
    with database.transaction() as connection:
        delivered = connection.execute(
            """
            SELECT m.body, sender.first_name AS sender_name, p.title AS peer_title
            FROM messages m
            JOIN users sender ON sender.id = m.sender_user_id
            JOIN peers p ON p.id = m.peer_id
            WHERE p.id IN (
                SELECT d.peer_id FROM dialogs d WHERE d.user_id = ?
            ) AND sender.username = 'intelligram_login'
            ORDER BY m.id DESC LIMIT 1
            """,
            (issued.user_id,),
        ).fetchone()
        incoming_update = connection.execute(
            """
            SELECT 1 FROM updates
            WHERE user_id = ? AND kind = 'updateNewMessage'
            ORDER BY id DESC LIMIT 1
            """,
            (issued.user_id,),
        ).fetchone()
    assert delivered is not None
    assert str(delivered["sender_name"]) == "IntelliGram Official"
    assert str(delivered["peer_title"]) == "IntelliGram Official"
    assert f"login code is: {code}" in str(delivered["body"])
    assert incoming_update is not None

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
        MESSAGES_DIALOGS_SLICE_CONSTRUCTOR,
        MESSAGES_GET_DIALOGS_CONSTRUCTOR,
        MESSAGES_GET_HISTORY_CONSTRUCTOR,
        MESSAGES_MESSAGES_SLICE_CONSTRUCTOR,
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
    sequence_no = 1

    def invoke(query: bytes) -> TLReader:
        nonlocal message_id, sequence_no
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=message_id,
            seq_no=sequence_no,
            body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == message_id
        message_id += 4
        sequence_no += 2
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
    assert dialogs_reader.uint32() == MESSAGES_DIALOGS_SLICE_CONSTRUCTOR
    assert dialogs_reader.int32() == 2
    assert dialogs_reader.uint32() == 0x1CB5C415
    assert dialogs_reader.int32() == 2
    assert dialogs_reader.uint32() == DIALOG_CONSTRUCTOR

    history_reader = invoke(
        encode_uint32(MESSAGES_GET_HISTORY_CONSTRUCTOR)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + struct.pack("<iiiiii", 0, 0, 0, 30, 0, 0)
        + encode_int64(0)
    )
    assert history_reader.uint32() == MESSAGES_MESSAGES_SLICE_CONSTRUCTOR
    assert history_reader.uint32() == 0
    assert history_reader.int32() == 1
    assert history_reader.uint32() == 0x1CB5C415
    assert history_reader.int32() == 1

    contacts_reader = invoke(encode_uint32(CONTACTS_GET_CONTACTS_CONSTRUCTOR) + encode_int64(0))
    assert contacts_reader.uint32() == CONTACTS_CONTACTS_CONSTRUCTOR
    assert contacts_reader.uint32() == 0x1CB5C415
    # Exchanging messages does not create a contact; only contacts.addContact
    # and contacts.importContacts do. See
    # test_web_k_contact_management_round_trip.
    assert contacts_reader.int32() == 0

    status_reader = invoke(encode_uint32(ACCOUNT_UPDATE_STATUS_CONSTRUCTOR) + encode_uint32(BOOL_FALSE_CONSTRUCTOR))
    assert status_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    privacy_reader = invoke(encode_uint32(ACCOUNT_GET_PRIVACY_CONSTRUCTOR) + encode_uint32(0xBC2EAB30))
    assert privacy_reader.uint32() == ACCOUNT_PRIVACY_RULES_CONSTRUCTOR


def test_web_k_persists_and_hydrates_ordinary_message_replies(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_USER_CONSTRUCTOR,
        INPUT_REPLY_TO_MESSAGE_CONSTRUCTOR,
        MESSAGE_CONSTRUCTOR,
        MESSAGE_REPLY_HEADER_CONSTRUCTOR,
        MESSAGES_GET_HISTORY_CONSTRUCTOR,
        MESSAGES_MESSAGES_SLICE_CONSTRUCTOR,
        MESSAGES_SEND_MESSAGE_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_MESSAGE_ID_CONSTRUCTOR,
        UPDATE_NEW_MESSAGE_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 137, 271
    database = Database(tmp_path / "message-replies.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000186", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000187", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    input_peer = (
        encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
    )
    message_id = (int(time.time()) << 32) + 4

    def invoke(query: bytes, *, sequence: int) -> bytes:
        nonlocal message_id
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=sequence, body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == message_id
        message_id += 4
        return body

    first_body = invoke(
        encode_uint32(MESSAGES_SEND_MESSAGE_CONSTRUCTOR)
        + encode_uint32(0)
        + input_peer
        + encode_tl_string("Reply target")
        + encode_int64(1001),
        sequence=1,
    )
    first_reader = TLReader(first_body)
    assert first_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    first_reader.int64()
    assert first_reader.uint32() == UPDATES_CONSTRUCTOR
    assert first_reader.vector_count() == 2
    assert first_reader.uint32() == UPDATE_MESSAGE_ID_CONSTRUCTOR
    first_reader.int32()  # final server message id
    assert first_reader.int64() == 1001
    assert first_reader.uint32() == UPDATE_NEW_MESSAGE_CONSTRUCTOR
    assert first_reader.uint32() == MESSAGE_CONSTRUCTOR
    assert first_reader.uint32() & (1 << 1)  # outgoing
    first_reader.uint32()  # flags2
    first_reader.int32()  # message id
    assert first_reader.uint32() == 0x59511722  # peerUser sender
    first_reader.int64()
    assert first_reader.uint32() == 0x59511722  # peerUser recipient
    first_reader.int64()
    first_reader.int32()  # date
    assert first_reader.bytes() == b"Reply target"
    first_pts = first_reader.int32()
    first_pts_count = first_reader.int32()
    assert first_pts == 0  # pre-send PTS finalizes Web K's optimistic message
    assert first_pts_count == 0
    with database.transaction() as connection:
        target = connection.execute("SELECT id FROM messages WHERE client_random_id = ?", ("1001",)).fetchone()
        assert target is not None
        target_id = int(target["id"])

    reply_body = invoke(
        encode_uint32(MESSAGES_SEND_MESSAGE_CONSTRUCTOR)
        + encode_uint32(1)
        + input_peer
        + encode_uint32(INPUT_REPLY_TO_MESSAGE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(target_id)
        + encode_tl_string("Native reply")
        + encode_int64(1002),
        sequence=3,
    )
    reply_offset = reply_body.index(encode_uint32(MESSAGE_CONSTRUCTOR))
    encoded_reply = TLReader(reply_body[reply_offset:])
    assert encoded_reply.uint32() == MESSAGE_CONSTRUCTOR
    assert encoded_reply.uint32() & (1 << 3)
    encoded_reply.uint32()  # flags2
    encoded_reply.int32()  # message id
    assert encoded_reply.uint32() == 0x59511722  # peerUser sender
    encoded_reply.int64()
    assert encoded_reply.uint32() == 0x59511722  # peerUser recipient
    encoded_reply.int64()
    assert MESSAGE_REPLY_HEADER_CONSTRUCTOR == 0x1B97DD66
    assert encoded_reply.uint32() == 0x1B97DD66
    assert encoded_reply.uint32() & (1 << 4)
    assert encoded_reply.int32() == target_id
    with database.transaction() as connection:
        stored = connection.execute(
            "SELECT reply_to_message_id FROM messages WHERE client_random_id = ?", ("1002",)
        ).fetchone()
        assert stored is not None and int(stored["reply_to_message_id"]) == target_id

    history_body = invoke(
        encode_uint32(MESSAGES_GET_HISTORY_CONSTRUCTOR)
        + input_peer
        + encode_int32(0)
        + encode_int32(0)
        + encode_int32(0)
        + encode_int32(30)
        + encode_int32(0)
        + encode_int32(0)
        + encode_int64(0),
        sequence=5,
    )
    history_reader = TLReader(history_body)
    assert history_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    history_reader.int64()
    assert history_reader.uint32() == MESSAGES_MESSAGES_SLICE_CONSTRUCTOR
    assert history_reader.uint32() == 0
    assert history_reader.int32() == 2
    reply_header_offset = history_body.index(encode_uint32(MESSAGE_REPLY_HEADER_CONSTRUCTOR))
    hydrated_header = TLReader(history_body[reply_header_offset:])
    assert hydrated_header.uint32() == 0x1B97DD66
    assert hydrated_header.uint32() & (1 << 4)
    assert hydrated_header.int32() == target_id


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
        INPUT_USER_SELF_CONSTRUCTOR,
        PHOTOS_PHOTO_CONSTRUCTOR,
        PHOTOS_UPLOAD_PROFILE_PHOTO_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPLOAD_SAVE_FILE_PART_CONSTRUCTOR,
        USER_CONSTRUCTOR,
        USER_PROFILE_PHOTO_CONSTRUCTOR,
        USERS_GET_USERS_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
        encode_vector,
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
    profile_photo_id = int(user["profile_photo_id"])

    users_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 8,
        seq_no=5,
        body=encode_uint32(USERS_GET_USERS_CONSTRUCTOR) + encode_vector([encode_uint32(INPUT_USER_SELF_CONSTRUCTOR)]),
    ))
    assert users_response is not None
    _, _, _, _, users_body = _decrypt_server(auth_key, users_response)
    user_reader = TLReader(users_body)
    assert user_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert user_reader.int64() == message_id + 8
    assert user_reader.vector_count() == 1
    assert user_reader.uint32() == USER_CONSTRUCTOR
    flags = user_reader.uint32()
    assert flags & (1 << 5)
    assert flags & (1 << 10)
    assert user_reader.uint32() == 0  # flags2
    assert user_reader.int64() == issued.user_id
    user_reader.int64()  # access_hash
    assert user_reader.bytes() == b"Photo"
    assert user_reader.bytes() == b"+15550000141"
    assert user_reader.uint32() == USER_PROFILE_PHOTO_CONSTRUCTOR
    assert user_reader.uint32() == 0  # profile-photo flags
    assert user_reader.int64() == profile_photo_id
    assert user_reader.int32() == 1  # dc_id


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
        UPDATE_MESSAGE_ID_CONSTRUCTOR,
        UPDATES_DIFFERENCE_CONSTRUCTOR,
        UPDATES_GET_DIFFERENCE_CONSTRUCTOR,
        encode_int32,
        encode_int64,
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
        stored, _ = send_message(
            connection,
            peer_id=peer_id,
            sender_user_id=alice.user_id,
            body="durable difference message",
            client_random_id="424242",
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

    # During a first post-refresh sender sync, Web K can discard the immediate
    # RPC result while applying its durable difference. The difference must
    # replay the random-id mapping before it replays the outgoing message so
    # the optimistic bubble is finalized instead of duplicated.
    sender_auth_key = bytes(reversed(range(256)))
    sender_adapter = MTProtoSessionAdapter(
        auth_key=sender_auth_key, server_salt=salt, database=database, user_id=alice.user_id
    )
    sender_response = sender_adapter.handle_encrypted(_encrypt_client(
        sender_auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=get_difference,
    ))
    assert sender_response is not None
    _, _, _, _, sender_body = _decrypt_server(sender_auth_key, sender_response)
    assert encode_uint32(UPDATE_MESSAGE_ID_CONSTRUCTOR) in sender_body
    assert (
        encode_uint32(UPDATE_MESSAGE_ID_CONSTRUCTOR)
        + encode_int32(int(stored["id"]))
        + encode_int64(424242)
    ) in sender_body


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


def test_web_k_migrates_legacy_group_and_persists_channel_slow_mode(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR,
        CHANNELS_TOGGLE_SLOW_MODE_CONSTRUCTOR,
        CHANNEL_FULL_CONSTRUCTOR,
        CHAT_BANNED_RIGHTS_CONSTRUCTOR,
        CHAT_REACTIONS_ALL_CONSTRUCTOR,
        CHAT_INVITE_EXPORTED_CONSTRUCTOR,
        INPUT_CHANNEL_CONSTRUCTOR,
        INPUT_USER_SELF_CONSTRUCTOR,
        INPUT_PEER_CHAT_CONSTRUCTOR,
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        MESSAGES_EDIT_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR,
        MESSAGES_EDIT_EXPORTED_CHAT_INVITE_CONSTRUCTOR,
        MESSAGES_DELETE_EXPORTED_CHAT_INVITE_CONSTRUCTOR,
        MESSAGES_DELETE_REVOKED_EXPORTED_CHAT_INVITES_CONSTRUCTOR,
        MESSAGES_EXPORTED_CHAT_INVITE_CONSTRUCTOR,
        MESSAGES_EXPORTED_CHAT_INVITE_REPLACED_CONSTRUCTOR,
        MESSAGES_MIGRATE_CHAT_CONSTRUCTOR,
        MESSAGES_SET_CHAT_AVAILABLE_REACTIONS_CONSTRUCTOR,
        PEER_NOTIFY_SETTINGS_CONSTRUCTOR,
        PHOTO_EMPTY_CONSTRUCTOR,
        MESSAGES_EXPORT_CHAT_INVITE_CONSTRUCTOR,
        MESSAGES_GET_EXPORTED_CHAT_INVITES_CONSTRUCTOR,
        MESSAGES_EXPORTED_CHAT_INVITES_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_bool,
        encode_int32,
        encode_int64,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import create_group

    auth_key = bytes(range(256))
    salt, session_id = 929, 195
    database = Database(tmp_path / "legacy-group-migration.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000182", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
        chat_id, _ = create_group(connection, owner_user_id=owner.user_id, title="Migratable group", member_user_ids=[])
    public_link_base_url = "https://links.example.intelligram.test/tenant/"
    adapter = MTProtoSessionAdapter(
        auth_key=auth_key,
        server_salt=salt,
        database=database,
        public_link_base_url=public_link_base_url,
        user_id=owner.user_id,
    )
    message_id = (int(time.time()) << 32) + 4

    default_rights = (
        encode_uint32(MESSAGES_EDIT_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR)
        + encode_uint32(INPUT_PEER_CHAT_CONSTRUCTOR)
        + encode_int64(chat_id)
        + encode_uint32(CHAT_BANNED_RIGHTS_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(0)
    )
    default_response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=default_rights,
    ))
    assert default_response is not None
    _, _, _, _, default_body = _decrypt_server(auth_key, default_response)
    default_reader = TLReader(default_body)
    assert default_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert default_reader.int64() == message_id
    assert default_reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        default_flags = connection.execute(
            "SELECT default_banned_rights_flags FROM peer_permissions WHERE peer_id = ?", (chat_id,)
        ).fetchone()
        assert default_flags is not None and int(default_flags["default_banned_rights_flags"]) == 0

    migrate_message_id = message_id + 4
    migrate = encode_uint32(MESSAGES_MIGRATE_CHAT_CONSTRUCTOR) + encode_int64(chat_id)
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=migrate_message_id, seq_no=3, body=migrate,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == migrate_message_id
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        migrated = connection.execute("SELECT kind FROM peers WHERE id = ?", (chat_id,)).fetchone()
        assert migrated is not None and migrated["kind"] == "channel"
        settings = connection.execute("SELECT slowmode_seconds FROM channel_settings WHERE peer_id = ?", (chat_id,)).fetchone()
        assert settings is not None and int(settings["slowmode_seconds"]) == 0

    input_channel = encode_uint32(INPUT_CHANNEL_CONSTRUCTOR) + encode_int64(chat_id) + encode_int64((chat_id << 32) | 1)
    full_message_id = migrate_message_id + 4
    full_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=full_message_id,
        seq_no=3,
        body=encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR) + input_channel,
    ))
    assert full_response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, full_response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_reader.int64() == full_message_id
    assert full_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR

    slow_message_id = full_message_id + 4
    slow_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=slow_message_id,
        seq_no=5,
        body=encode_uint32(CHANNELS_TOGGLE_SLOW_MODE_CONSTRUCTOR) + input_channel + encode_int32(5),
    ))
    assert slow_response is not None
    _, _, _, _, slow_body = _decrypt_server(auth_key, slow_response)
    slow_reader = TLReader(slow_body)
    assert slow_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert slow_reader.int64() == slow_message_id
    assert slow_reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        settings = connection.execute("SELECT slowmode_seconds FROM channel_settings WHERE peer_id = ?", (chat_id,)).fetchone()
        assert settings is not None and int(settings["slowmode_seconds"]) == 5

    restricted_message_id = slow_message_id + 4
    restricted_rights = (
        encode_uint32(MESSAGES_EDIT_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_uint32(CHAT_BANNED_RIGHTS_CONSTRUCTOR)
        + encode_uint32((1 << 1) | (1 << 2))  # send_messages and send_media
        + encode_int32(0)
    )
    restricted_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=restricted_message_id,
        seq_no=7,
        body=restricted_rights,
    ))
    assert restricted_response is not None
    _, _, _, _, restricted_body = _decrypt_server(auth_key, restricted_response)
    restricted_reader = TLReader(restricted_body)
    assert restricted_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert restricted_reader.int64() == restricted_message_id
    assert restricted_reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        restricted_flags = connection.execute(
            "SELECT default_banned_rights_flags FROM peer_permissions WHERE peer_id = ?", (chat_id,)
        ).fetchone()
        assert restricted_flags is not None and int(restricted_flags["default_banned_rights_flags"]) == ((1 << 1) | (1 << 2))

    reactions_message_id = restricted_message_id + 4
    all_reactions = (
        encode_uint32(MESSAGES_SET_CHAT_AVAILABLE_REACTIONS_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_uint32(CHAT_REACTIONS_ALL_CONSTRUCTOR)
        + encode_uint32(1)  # allow_custom
    )
    reactions_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=reactions_message_id,
        seq_no=9,
        body=all_reactions,
    ))
    assert reactions_response is not None
    _, _, _, _, reactions_body = _decrypt_server(auth_key, reactions_response)
    reactions_reader = TLReader(reactions_body)
    assert reactions_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reactions_reader.int64() == reactions_message_id
    assert reactions_reader.uint32() == UPDATES_CONSTRUCTOR
    with database.transaction() as connection:
        reaction_settings = connection.execute(
            "SELECT mode, allow_custom, emoticons_json FROM channel_reaction_settings WHERE peer_id = ?", (chat_id,)
        ).fetchone()
        assert reaction_settings is not None
        assert (reaction_settings["mode"], int(reaction_settings["allow_custom"]), reaction_settings["emoticons_json"]) == ("all", 1, "[]")

    invite_message_id = reactions_message_id + 4
    invite_request = (
        encode_uint32(MESSAGES_EXPORT_CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32((1 << 0) | (1 << 1) | (1 << 4))  # zero expiry, zero usage limit, and title
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_int32(0)
        + encode_int32(0)
        + encode_tl_string("Regression invite")
    )
    invite_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=invite_message_id,
        seq_no=11,
        body=invite_request,
    ))
    assert invite_response is not None
    _, _, _, _, invite_body = _decrypt_server(auth_key, invite_response)
    invite_reader = TLReader(invite_body)
    assert invite_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert invite_reader.int64() == invite_message_id
    assert invite_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    invite_flags = invite_reader.uint32()
    assert invite_flags & (1 << 8)
    named_invite_link = invite_reader.bytes().decode("utf-8")
    assert named_invite_link.startswith("https://links.example.intelligram.test/tenant/+")
    with database.transaction() as connection:
        invite = connection.execute(
            "SELECT link, title, permanent, revoked FROM exported_invites WHERE peer_id = ? AND title = ?",
            (chat_id, "Regression invite"),
        ).fetchone()
        assert invite is not None
        assert str(invite["link"]).startswith("https://links.example.intelligram.test/tenant/+")
        assert (invite["title"], int(invite["permanent"]), int(invite["revoked"])) == ("Regression invite", 0, 0)

    list_message_id = invite_message_id + 4
    list_request = (
        encode_uint32(MESSAGES_GET_EXPORTED_CHAT_INVITES_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_uint32(INPUT_USER_SELF_CONSTRUCTOR)
        + encode_int32(50)
    )
    list_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=list_message_id,
        seq_no=13,
        body=list_request,
    ))
    assert list_response is not None
    _, _, _, _, list_body = _decrypt_server(auth_key, list_response)
    list_reader = TLReader(list_body)
    assert list_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert list_reader.int64() == list_message_id
    assert list_reader.uint32() == MESSAGES_EXPORTED_CHAT_INVITES_CONSTRUCTOR
    assert list_reader.int32() >= 1

    permanent_message_id = list_message_id + 4
    permanent_request = (
        encode_uint32(MESSAGES_EXPORT_CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
    )
    permanent_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=permanent_message_id,
        seq_no=15,
        body=permanent_request,
    ))
    assert permanent_response is not None
    _, _, _, _, permanent_body = _decrypt_server(auth_key, permanent_response)
    permanent_reader = TLReader(permanent_body)
    assert permanent_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert permanent_reader.int64() == permanent_message_id
    assert permanent_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    assert permanent_reader.uint32() & (1 << 5)  # permanent
    permanent_invite_link = permanent_reader.bytes().decode("utf-8")
    assert permanent_invite_link.startswith("https://links.example.intelligram.test/tenant/+")

    full_with_invite_message_id = permanent_message_id + 4
    full_with_invite_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=full_with_invite_message_id,
        seq_no=17,
        body=encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR) + input_channel,
    ))
    assert full_with_invite_response is not None
    _, _, _, _, full_with_invite_body = _decrypt_server(auth_key, full_with_invite_response)
    full_with_invite_reader = TLReader(full_with_invite_body)
    assert full_with_invite_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_with_invite_reader.int64() == full_with_invite_message_id
    assert full_with_invite_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR
    assert full_with_invite_reader.uint32() == CHANNEL_FULL_CONSTRUCTOR
    channel_full_flags = full_with_invite_reader.uint32()
    assert channel_full_flags & (1 << 23)  # exported_invite
    full_with_invite_reader.uint32()  # flags2
    assert full_with_invite_reader.int64() == chat_id
    full_with_invite_reader.bytes()  # about
    full_with_invite_reader.int32()  # participants_count
    full_with_invite_reader.int32()  # admins_count
    full_with_invite_reader.int32()  # read_inbox_max_id
    full_with_invite_reader.int32()  # read_outbox_max_id
    full_with_invite_reader.int32()  # unread_count
    assert full_with_invite_reader.uint32() == PHOTO_EMPTY_CONSTRUCTOR
    full_with_invite_reader.int64()  # photoEmpty id
    assert full_with_invite_reader.uint32() == PEER_NOTIFY_SETTINGS_CONSTRUCTOR
    assert full_with_invite_reader.uint32() == 0  # peerNotifySettings flags
    assert full_with_invite_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    exported_flags = full_with_invite_reader.uint32()
    assert exported_flags & (1 << 5)  # permanent
    assert full_with_invite_reader.bytes().decode("utf-8").startswith("https://links.example.intelligram.test/tenant/+")

    edit_invite_message_id = full_with_invite_message_id + 4
    edit_invite_request = (
        encode_uint32(MESSAGES_EDIT_EXPORTED_CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32((1 << 0) | (1 << 1) | (1 << 3) | (1 << 4))
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_tl_string(named_invite_link)
        + encode_int32(0)  # explicit unlimited expiry
        + encode_int32(10)
        + encode_bool(False)
        + encode_tl_string("Edited regression invite")
    )
    edit_invite_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=edit_invite_message_id,
        seq_no=19,
        body=edit_invite_request,
    ))
    assert edit_invite_response is not None
    _, _, _, _, edit_invite_body = _decrypt_server(auth_key, edit_invite_response)
    edit_invite_reader = TLReader(edit_invite_body)
    assert edit_invite_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert edit_invite_reader.int64() == edit_invite_message_id
    assert edit_invite_reader.uint32() == MESSAGES_EXPORTED_CHAT_INVITE_CONSTRUCTOR
    assert edit_invite_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    edited_flags = edit_invite_reader.uint32()
    assert edited_flags & (1 << 2)  # usage_limit
    assert edited_flags & (1 << 3)  # usage
    assert edited_flags & (1 << 8)  # title
    assert edit_invite_reader.bytes().decode("utf-8") == named_invite_link
    with database.transaction() as connection:
        edited_invite = connection.execute(
            "SELECT title, expire_date, usage_limit, request_needed, revoked FROM exported_invites WHERE link = ?",
            (named_invite_link,),
        ).fetchone()
        assert edited_invite is not None
        assert (
            edited_invite["title"],
            edited_invite["expire_date"],
            int(edited_invite["usage_limit"]),
            int(edited_invite["request_needed"]),
            int(edited_invite["revoked"]),
        ) == ("Edited regression invite", None, 10, 0, 0)

    revoke_named_message_id = edit_invite_message_id + 4
    revoke_named_request = (
        encode_uint32(MESSAGES_EDIT_EXPORTED_CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32(1 << 2)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_tl_string(named_invite_link)
    )
    revoke_named_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=revoke_named_message_id,
        seq_no=21,
        body=revoke_named_request,
    ))
    assert revoke_named_response is not None
    _, _, _, _, revoke_named_body = _decrypt_server(auth_key, revoke_named_response)
    revoke_named_reader = TLReader(revoke_named_body)
    assert revoke_named_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert revoke_named_reader.int64() == revoke_named_message_id
    assert revoke_named_reader.uint32() == MESSAGES_EXPORTED_CHAT_INVITE_CONSTRUCTOR
    assert revoke_named_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    assert revoke_named_reader.uint32() & 1  # revoked
    with database.transaction() as connection:
        revoked_named = connection.execute("SELECT revoked FROM exported_invites WHERE link = ?", (named_invite_link,)).fetchone()
        assert revoked_named is not None and int(revoked_named["revoked"]) == 1

    delete_revoked_message_id = revoke_named_message_id + 4
    delete_revoked_request = (
        encode_uint32(MESSAGES_DELETE_REVOKED_EXPORTED_CHAT_INVITES_CONSTRUCTOR)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_uint32(INPUT_USER_SELF_CONSTRUCTOR)
    )
    delete_revoked_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=delete_revoked_message_id,
        seq_no=23,
        body=delete_revoked_request,
    ))
    assert delete_revoked_response is not None
    _, _, _, _, delete_revoked_body = _decrypt_server(auth_key, delete_revoked_response)
    delete_revoked_reader = TLReader(delete_revoked_body)
    assert delete_revoked_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert delete_revoked_reader.int64() == delete_revoked_message_id
    assert delete_revoked_reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    with database.transaction() as connection:
        deleted_revoked = connection.execute("SELECT COUNT(*) AS count FROM exported_invites WHERE link = ?", (named_invite_link,)).fetchone()
        assert deleted_revoked is not None and int(deleted_revoked["count"]) == 0

    revoke_permanent_message_id = delete_revoked_message_id + 4
    revoke_permanent_request = (
        encode_uint32(MESSAGES_EDIT_EXPORTED_CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32(1 << 2)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_tl_string(permanent_invite_link)
    )
    revoke_permanent_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=revoke_permanent_message_id,
        seq_no=25,
        body=revoke_permanent_request,
    ))
    assert revoke_permanent_response is not None
    _, _, _, _, revoke_permanent_body = _decrypt_server(auth_key, revoke_permanent_response)
    revoke_permanent_reader = TLReader(revoke_permanent_body)
    assert revoke_permanent_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert revoke_permanent_reader.int64() == revoke_permanent_message_id
    assert revoke_permanent_reader.uint32() == MESSAGES_EXPORTED_CHAT_INVITE_REPLACED_CONSTRUCTOR
    assert revoke_permanent_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    assert revoke_permanent_reader.uint32() & 1  # revoked old permanent invite
    assert revoke_permanent_reader.bytes().decode("utf-8") == permanent_invite_link
    revoke_permanent_reader.int64()  # old invite admin_id
    revoke_permanent_reader.int32()  # old invite date
    assert revoke_permanent_reader.uint32() == CHAT_INVITE_EXPORTED_CONSTRUCTOR
    assert revoke_permanent_reader.uint32() & (1 << 5)  # replacement permanent invite
    replacement_invite_link = revoke_permanent_reader.bytes().decode("utf-8")
    assert replacement_invite_link.startswith("https://links.example.intelligram.test/tenant/+")
    with database.transaction() as connection:
        active_permanent = connection.execute(
            "SELECT COUNT(*) AS count FROM exported_invites WHERE peer_id = ? AND permanent = 1 AND revoked = 0",
            (chat_id,),
        ).fetchone()
        assert active_permanent is not None and int(active_permanent["count"]) == 1

    delete_single_message_id = revoke_permanent_message_id + 4
    delete_single_request = (
        encode_uint32(MESSAGES_DELETE_EXPORTED_CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
        + encode_tl_string(permanent_invite_link)
    )
    delete_single_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=delete_single_message_id,
        seq_no=27,
        body=delete_single_request,
    ))
    assert delete_single_response is not None
    _, _, _, _, delete_single_body = _decrypt_server(auth_key, delete_single_response)
    delete_single_reader = TLReader(delete_single_body)
    assert delete_single_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert delete_single_reader.int64() == delete_single_message_id
    assert delete_single_reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    with database.transaction() as connection:
        deleted_single = connection.execute("SELECT COUNT(*) AS count FROM exported_invites WHERE link = ?", (permanent_invite_link,)).fetchone()
        assert deleted_single is not None and int(deleted_single["count"]) == 0
        active_replacement = connection.execute(
            "SELECT COUNT(*) AS count FROM exported_invites WHERE peer_id = ? AND permanent = 1 AND revoked = 0",
            (chat_id,),
        ).fetchone()
        assert active_replacement is not None and int(active_replacement["count"]) == 1


def test_web_k_persists_channel_content_protection_after_encrypted_toggle(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CHANNEL_CONSTRUCTOR,
        CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR,
        INPUT_CHANNEL_CONSTRUCTOR,
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        MESSAGES_TOGGLE_NO_FORWARDS_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_bool,
        encode_int64,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import create_group, migrate_chat_to_channel

    auth_key = bytes(range(255, -1, -1))
    salt, session_id = 947, 209
    database = Database(tmp_path / "content-protection.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000183", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
        chat_id, _ = create_group(connection, owner_user_id=owner.user_id, title="Protected group", member_user_ids=[])
        migrate_chat_to_channel(connection, chat_id=chat_id, actor_user_id=owner.user_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    message_id = (int(time.time()) << 32) + 8
    input_peer_channel = (
        encode_uint32(0x27BCBBFC)  # inputPeerChannel
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
    )
    toggle_request = (
        encode_uint32(MESSAGES_TOGGLE_NO_FORWARDS_CONSTRUCTOR)
        + encode_uint32(0)
        + input_peer_channel
        + encode_bool(True)
    )
    toggle_response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=toggle_request,
    ))
    assert toggle_response is not None
    _, _, _, _, toggle_body = _decrypt_server(auth_key, toggle_response)
    toggle_reader = TLReader(toggle_body)
    assert toggle_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert toggle_reader.int64() == message_id
    assert toggle_reader.uint32() == UPDATES_CONSTRUCTOR
    channel_offset = toggle_body.index(encode_uint32(CHANNEL_CONSTRUCTOR))
    encoded_channel = TLReader(toggle_body[channel_offset:])
    assert encoded_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert encoded_channel.uint32() & (1 << 27)
    with database.transaction() as connection:
        settings = connection.execute("SELECT noforwards FROM channel_settings WHERE peer_id = ?", (chat_id,)).fetchone()
        assert settings is not None and int(settings["noforwards"]) == 1

    full_message_id = message_id + 4
    input_channel = encode_uint32(INPUT_CHANNEL_CONSTRUCTOR) + encode_int64(chat_id) + encode_int64((chat_id << 32) | 1)
    full_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=full_message_id,
        seq_no=3,
        body=encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR) + input_channel,
    ))
    assert full_response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, full_response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_reader.int64() == full_message_id
    assert full_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR
    full_channel_offset = full_body.index(encode_uint32(CHANNEL_CONSTRUCTOR))
    full_channel = TLReader(full_body[full_channel_offset:])
    assert full_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert full_channel.uint32() & (1 << 27)


def test_web_k_persists_channel_join_request_after_encrypted_toggle(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CHANNEL_CONSTRUCTOR,
        CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR,
        CHANNELS_TOGGLE_JOIN_REQUEST_CONSTRUCTOR,
        INPUT_CHANNEL_CONSTRUCTOR,
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_bool,
        encode_int64,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import create_group, migrate_chat_to_channel

    auth_key = bytes(range(256))
    salt, session_id = 949, 211
    database = Database(tmp_path / "join-request.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000185", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
        chat_id, _ = create_group(connection, owner_user_id=owner.user_id, title="Approval group", member_user_ids=[])
        migrate_chat_to_channel(connection, chat_id=chat_id, actor_user_id=owner.user_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    input_channel = (
        encode_uint32(INPUT_CHANNEL_CONSTRUCTOR)
        + encode_int64(chat_id)
        + encode_int64((chat_id << 32) | 1)
    )
    message_id = (int(time.time()) << 32) + 8

    def toggle(enabled: bool, *, request_message_id: int, sequence: int) -> bytes:
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id,
            seq_no=sequence,
            body=(
                encode_uint32(CHANNELS_TOGGLE_JOIN_REQUEST_CONSTRUCTOR)
                + encode_uint32(0)
                + input_channel
                + encode_bool(enabled)
            ),
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        assert reader.uint32() == UPDATES_CONSTRUCTOR
        return body

    enabled_body = toggle(True, request_message_id=message_id, sequence=1)
    enabled_channel = TLReader(enabled_body[enabled_body.index(encode_uint32(CHANNEL_CONSTRUCTOR)):])
    assert enabled_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert enabled_channel.uint32() & (1 << 29)
    with database.transaction() as connection:
        settings = connection.execute(
            "SELECT join_request_enabled FROM channel_settings WHERE peer_id = ?", (chat_id,)
        ).fetchone()
        assert settings is not None and int(settings["join_request_enabled"]) == 1

    full_message_id = message_id + 4
    full_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=full_message_id,
        seq_no=3,
        body=encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR) + input_channel,
    ))
    assert full_response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, full_response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_reader.int64() == full_message_id
    assert full_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR
    hydrated_channel = TLReader(full_body[full_body.index(encode_uint32(CHANNEL_CONSTRUCTOR)):])
    assert hydrated_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert hydrated_channel.uint32() & (1 << 29)

    disabled_body = toggle(False, request_message_id=full_message_id + 4, sequence=5)
    disabled_channel = TLReader(disabled_body[disabled_body.index(encode_uint32(CHANNEL_CONSTRUCTOR)):])
    assert disabled_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert not disabled_channel.uint32() & (1 << 29)
    with database.transaction() as connection:
        settings = connection.execute(
            "SELECT join_request_enabled FROM channel_settings WHERE peer_id = ?", (chat_id,)
        ).fetchone()
        assert settings is not None and int(settings["join_request_enabled"]) == 0


def test_web_k_persists_public_channel_username_and_returns_to_private(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        CHANNEL_CONSTRUCTOR,
        CHANNELS_CHECK_USERNAME_CONSTRUCTOR,
        CHANNELS_DEACTIVATE_ALL_USERNAMES_CONSTRUCTOR,
        CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR,
        CHANNELS_UPDATE_USERNAME_CONSTRUCTOR,
        INPUT_CHANNEL_CONSTRUCTOR,
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int64,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import create_group, migrate_chat_to_channel

    auth_key = bytes(range(256))
    salt, session_id = 953, 211
    database = Database(tmp_path / "public-username.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000184", password="correct-horse-battery-staple", first_name="Owner", device_label="Owner",
        )
        chat_id, _ = create_group(connection, owner_user_id=owner.user_id, title="Public group", member_user_ids=[])
        migrate_chat_to_channel(connection, chat_id=chat_id, actor_user_id=owner.user_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    input_channel = encode_uint32(INPUT_CHANNEL_CONSTRUCTOR) + encode_int64(chat_id) + encode_int64((chat_id << 32) | 1)
    username = "IntelliGramPublicTest"
    message_id = (int(time.time()) << 32) + 12

    check_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(CHANNELS_CHECK_USERNAME_CONSTRUCTOR) + input_channel + encode_tl_string(username),
    ))
    assert check_response is not None
    _, _, _, _, check_body = _decrypt_server(auth_key, check_response)
    check_reader = TLReader(check_body)
    assert check_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert check_reader.int64() == message_id
    assert check_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    update_message_id = message_id + 4
    update_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=update_message_id,
        seq_no=3,
        body=encode_uint32(CHANNELS_UPDATE_USERNAME_CONSTRUCTOR) + input_channel + encode_tl_string(username),
    ))
    assert update_response is not None
    _, _, _, _, update_body = _decrypt_server(auth_key, update_response)
    update_reader = TLReader(update_body)
    assert update_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert update_reader.int64() == update_message_id
    assert update_reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    with database.transaction() as connection:
        stored = connection.execute("SELECT username FROM peers WHERE id = ?", (chat_id,)).fetchone()
        assert stored is not None and stored["username"] == username

    full_message_id = update_message_id + 4
    full_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=full_message_id,
        seq_no=5,
        body=encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR) + input_channel,
    ))
    assert full_response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, full_response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_reader.int64() == full_message_id
    assert full_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR
    channel_offset = full_body.index(encode_uint32(CHANNEL_CONSTRUCTOR))
    encoded_channel = TLReader(full_body[channel_offset:])
    assert encoded_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert encoded_channel.uint32() & (1 << 6)
    encoded_channel.uint32()  # flags2
    encoded_channel.int64()  # channel id
    encoded_channel.int64()  # access hash
    encoded_channel.bytes()  # title
    assert encoded_channel.bytes().decode("utf-8") == username

    clear_message_id = full_message_id + 4
    clear_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=clear_message_id,
        seq_no=7,
        body=encode_uint32(CHANNELS_UPDATE_USERNAME_CONSTRUCTOR) + input_channel + encode_tl_string(""),
    ))
    assert clear_response is not None
    _, _, _, _, clear_body = _decrypt_server(auth_key, clear_response)
    clear_reader = TLReader(clear_body)
    assert clear_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert clear_reader.int64() == clear_message_id
    assert clear_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    deactivate_message_id = clear_message_id + 4
    deactivate_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=deactivate_message_id,
        seq_no=9,
        body=encode_uint32(CHANNELS_DEACTIVATE_ALL_USERNAMES_CONSTRUCTOR) + input_channel,
    ))
    assert deactivate_response is not None
    _, _, _, _, deactivate_body = _decrypt_server(auth_key, deactivate_response)
    deactivate_reader = TLReader(deactivate_body)
    assert deactivate_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert deactivate_reader.int64() == deactivate_message_id
    assert deactivate_reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    with database.transaction() as connection:
        stored = connection.execute("SELECT username FROM peers WHERE id = ?", (chat_id,)).fetchone()
        assert stored is not None and stored["username"] is None


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
        MESSAGE_CONSTRUCTOR,
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
    assert MESSAGES_EDIT_MESSAGE_CONSTRUCTOR == 0xB106E66C
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
        edited_at = int(row["edited_at"])

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
    assert reader.uint32() == MESSAGE_CONSTRUCTOR
    message_flags = reader.uint32()
    assert message_flags & (1 << 15)
    reader.uint32()  # flags2
    assert reader.int32() == int(stored["id"])
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == alice.user_id
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    reader.int32()  # date
    assert reader.bytes().decode("utf-8") == "After edit"
    assert reader.int32() == edited_at

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
        CONTACTS_CONTACTS_CONSTRUCTOR,
        CONTACTS_FOUND_CONSTRUCTOR,
        CONTACTS_GET_CONTACTS_CONSTRUCTOR,
        CONTACTS_IMPORT_CONTACTS_CONSTRUCTOR,
        CONTACTS_IMPORTED_CONTACTS_CONSTRUCTOR,
        CONTACTS_SEARCH_CONSTRUCTOR,
        CONTACT_CONSTRUCTOR,
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

    contacts_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(CONTACTS_GET_CONTACTS_CONSTRUCTOR) + encode_int64(0),
    ))
    assert contacts_response is not None
    _, _, _, _, contacts_body = _decrypt_server(auth_key, contacts_response)
    reader = TLReader(contacts_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == CONTACTS_CONTACTS_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == CONTACT_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    reader.uint32()  # mutual flag
    assert reader.int32() == 1  # saved_count
    assert reader.vector_count() == 1

    search_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 8,
        seq_no=5,
        body=encode_uint32(CONTACTS_SEARCH_CONSTRUCTOR) + encode_uint32(0) + encode_tl_string("bob") + encode_int32(20),
    ))
    assert search_response is not None
    _, _, _, _, search_body = _decrypt_server(auth_key, search_response)
    reader = TLReader(search_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 8
    assert reader.uint32() == CONTACTS_FOUND_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    assert reader.vector_count() == 0


def test_web_k_account_authorizations_lists_and_revokes_remote_session(tmp_path) -> None:
    from intelligram.database import Database, now_unix
    from intelligram.mtproto.crypto import auth_key_id
    from intelligram.mtproto.tl import (
        ACCOUNT_AUTHORIZATIONS_CONSTRUCTOR,
        ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR,
        ACCOUNT_RESET_AUTHORIZATION_CONSTRUCTOR,
        BOOL_TRUE_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int64,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    current_auth_key = bytes(range(256))
    remote_auth_key = bytes(reversed(range(256)))
    salt, session_id = 930, 203
    database = Database(tmp_path / "account-authorizations.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        user = register_password_account(
            connection, phone="+15550000261", password="correct-horse-battery-staple", first_name="Devices", device_label="Primary",
        )
        now = now_unix()
        connection.execute(
            """
            INSERT INTO auth_keys(auth_key_id, user_id, key_fingerprint, key_material, server_salt, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(auth_key_id(current_auth_key)), user.user_id, "mtproto:current", current_auth_key, str(salt), now),
        )
        connection.execute(
            """
            INSERT INTO auth_keys(auth_key_id, user_id, key_fingerprint, key_material, server_salt, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(auth_key_id(remote_auth_key)), user.user_id, "mtproto:remote", remote_auth_key, str(salt), now),
        )
    adapter = MTProtoSessionAdapter(auth_key=current_auth_key, server_salt=salt, database=database, user_id=user.user_id)
    message_id = (int(time.time()) << 32) + 4
    list_response = adapter.handle_encrypted(_encrypt_client(
        current_auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1,
        body=encode_uint32(ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR),
    ))
    assert list_response is not None
    _, _, _, _, list_body = _decrypt_server(current_auth_key, list_response)
    reader = TLReader(list_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == ACCOUNT_AUTHORIZATIONS_CONSTRUCTOR
    assert reader.int32() == 365
    assert reader.vector_count() == 2

    reset_response = adapter.handle_encrypted(_encrypt_client(
        current_auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(ACCOUNT_RESET_AUTHORIZATION_CONSTRUCTOR) + encode_int64(auth_key_id(remote_auth_key)),
    ))
    assert reset_response is not None
    _, _, _, _, reset_body = _decrypt_server(current_auth_key, reset_response)
    reader = TLReader(reset_body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    with database.transaction() as connection:
        remote = connection.execute(
            "SELECT revoked_at FROM auth_keys WHERE auth_key_id = ?", (str(auth_key_id(remote_auth_key)),)
        ).fetchone()
        current = connection.execute(
            "SELECT revoked_at FROM auth_keys WHERE auth_key_id = ?", (str(auth_key_id(current_auth_key)),)
        ).fetchone()
        assert remote is not None and remote["revoked_at"] is not None
        assert current is not None and current["revoked_at"] is None


def test_web_k_password_fallback_uses_srp_and_authorizes_over_encrypted_mtproto(tmp_path) -> None:
    """The preserved Web K PasswordCard can fall back without a plaintext RPC."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_GET_PASSWORD_CONSTRUCTOR,
        ACCOUNT_PASSWORD_CONSTRUCTOR,
        AUTH_AUTHORIZATION_CONSTRUCTOR,
        AUTH_CHECK_PASSWORD_CONSTRUCTOR,
        AUTH_SEND_CODE_CONSTRUCTOR,
        AUTH_SENT_CODE_CONSTRUCTOR,
        INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR,
        PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR,
        RPC_ERROR_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        SECURE_PASSWORD_KDF_ALGO_UNKNOWN_CONSTRUCTOR,
        TLReader,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.srp import G, P, P_BYTES

    code_settings_constructor = 0xAD253D78
    auth_key = bytes(range(255, -1, -1))
    salt, session_id = 101, 404
    database = Database(tmp_path / "password-fallback.sqlite3")
    database.initialize()
    phone = "+15551239991"
    password = "correct-horse-battery-staple"
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone=phone,
            password=password,
            first_name="Fallback",
            device_label="Primary IntelliGram device",
        )

    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database)
    first_message_id = (int(time.time()) << 32) + 4

    def invoke(query: bytes, index: int) -> TLReader:
        request_message_id = first_message_id + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id,
            seq_no=index * 2 + 1,
            body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        return reader

    send_code = (
        struct.pack("<I", AUTH_SEND_CODE_CONSTRUCTOR)
        + _tl_bytes(phone.encode())
        + struct.pack("<i", 1)
        + _tl_bytes(b"intelligram-self-hosted")
        + struct.pack("<II", code_settings_constructor, 0)
    )
    reader = invoke(send_code, 0)
    assert reader.uint32() == AUTH_SENT_CODE_CONSTRUCTOR

    # account.getPassword has no phone field; the prior sendCode stores the
    # one-time account binding against this encrypted auth key.
    reader = invoke(struct.pack("<I", ACCOUNT_GET_PASSWORD_CONSTRUCTOR), 1)
    assert reader.uint32() == ACCOUNT_PASSWORD_CONSTRUCTOR
    assert reader.uint32() == 1 << 2
    assert reader.uint32() == PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR
    salt1 = reader.bytes()
    salt2 = reader.bytes()
    assert reader.int32() == G
    assert reader.bytes() == P_BYTES
    srp_B = reader.bytes()
    srp_id = reader.int64()
    assert len(srp_B) == 256
    # Required new_algo and secure algorithm still decode after current state.
    assert reader.uint32() == PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR
    assert reader.bytes() == salt1
    assert reader.bytes() == salt2
    assert reader.int32() == G
    assert reader.bytes() == P_BYTES
    assert reader.uint32() == SECURE_PASSWORD_KDF_ALGO_UNKNOWN_CONSTRUCTOR
    assert reader.bytes() == b"\x00" * 32

    def proof() -> tuple[bytes, bytes]:
        def sha(value: bytes) -> bytes:
            return hashlib.sha256(value).digest()

        def pad(value: int) -> bytes:
            return value.to_bytes(256, "big")

        first_hash = sha(salt1 + password.encode() + salt1)
        second_hash = sha(salt2 + first_hash + salt2)
        stretched = hashlib.pbkdf2_hmac("sha512", second_hash, salt1, 100_000, dklen=64)
        x = int.from_bytes(sha(salt2 + stretched + salt2), "big")
        private_a = 0x123456789ABCDEF
        public_A = pow(G, private_a, P)
        public_B = int.from_bytes(srp_B, "big")
        multiplier = int.from_bytes(sha(pad(P) + pad(G)), "big")
        scrambling = int.from_bytes(sha(pad(public_A) + pad(public_B)), "big")
        shared_secret = pow((public_B - multiplier * pow(G, x, P)) % P, private_a + scrambling * x, P)
        session_key = sha(pad(shared_secret))
        hash_prime_xor_generator = bytes(left ^ right for left, right in zip(sha(pad(P)), sha(pad(G)), strict=True))
        m1 = sha(
            hash_prime_xor_generator
            + sha(salt1)
            + sha(salt2)
            + pad(public_A)
            + pad(public_B)
            + session_key
        )
        return pad(public_A), m1

    client_A, client_M1 = proof()
    check_password_prefix = (
        struct.pack("<I", AUTH_CHECK_PASSWORD_CONSTRUCTOR)
        + struct.pack("<I", INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR)
        + struct.pack("<q", srp_id)
        + _tl_bytes(client_A)
    )
    reader = invoke(check_password_prefix + _tl_bytes(b"\x00" * 32), 2)
    assert reader.uint32() == RPC_ERROR_CONSTRUCTOR
    assert reader.int32() == 400
    assert reader.bytes().decode() == "PASSWORD_HASH_INVALID"

    reader = invoke(check_password_prefix + _tl_bytes(client_M1), 3)
    assert reader.uint32() == AUTH_AUTHORIZATION_CONSTRUCTOR

    with database.transaction() as connection:
        key_binding = connection.execute(
            "SELECT user_id FROM auth_keys WHERE auth_key_id = ?",
            (str(auth_key_id(auth_key)),),
        ).fetchone()
        challenge = connection.execute(
            "SELECT completed_at, attempts FROM password_srp_challenges WHERE srp_id = ?",
            (srp_id,),
        ).fetchone()
        context = connection.execute(
            "SELECT 1 FROM password_login_contexts WHERE auth_key_id = ?",
            (str(auth_key_id(auth_key)),),
        ).fetchone()
    assert key_binding is not None
    assert int(key_binding["user_id"]) == issued.user_id
    assert challenge is not None and challenge["completed_at"] is not None
    assert int(challenge["attempts"]) == 1
    assert context is None

    # Privacy and Security requests the same password state from an already
    # authenticated MTProto key, without another sendCode/login context.
    reader = invoke(struct.pack("<I", ACCOUNT_GET_PASSWORD_CONSTRUCTOR), 4)
    assert reader.uint32() == ACCOUNT_PASSWORD_CONSTRUCTOR
    assert reader.uint32() == 1 << 2
    assert reader.uint32() == PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR


def test_device_login_invalidates_a_six_digit_code_after_five_bad_attempts(tmp_path) -> None:
    """Code delivery remains one-time and invalidates on the documented limit."""

    from intelligram.database import Database
    from intelligram.services.accounts import (
        AccountAuthError,
        MAX_LOGIN_CODE_ATTEMPTS,
        complete_device_login,
        register_password_account,
        start_device_login,
    )

    database = Database(tmp_path / "code-attempt-limit.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone="+15551239992",
            password="correct-horse-battery-staple",
            first_name="Attempts",
            device_label="Primary IntelliGram device",
        )
        started = start_device_login(connection, phone="+15551239992", device_label="New browser")
        assert started.challenge_id is not None
        for attempt in range(MAX_LOGIN_CODE_ATTEMPTS):
            with pytest.raises(AccountAuthError, match="PHONE_CODE_INVALID"):
                complete_device_login(
                    connection,
                    phone="+15551239992",
                    challenge_id=started.challenge_id,
                    code="000000",
                    device_label=f"Attempt {attempt}",
                )
        challenge = connection.execute(
            "SELECT attempts, denied_at FROM login_challenges WHERE id = ?",
            (started.challenge_id,),
        ).fetchone()
        assert challenge is not None
        assert int(challenge["attempts"]) == MAX_LOGIN_CODE_ATTEMPTS
        assert challenge["denied_at"] is not None
        with pytest.raises(AccountAuthError, match="PHONE_CODE_EXPIRED"):
            complete_device_login(
                connection,
                phone="+15551239992",
                challenge_id=started.challenge_id,
                code="999999",
                device_label="Post-limit browser",
            )
        # The existing primary session remains durable while a pending code is denied.
        sessions = connection.execute(
            "SELECT count(*) AS count FROM sessions WHERE user_id = ? AND revoked_at IS NULL",
            (issued.user_id,),
        ).fetchone()
        assert sessions is not None and int(sessions["count"]) == 1


def test_web_k_scrypt_only_password_fallback_uses_plaintext_inside_encrypted_mtproto(tmp_path) -> None:
    """Legacy accounts without SRP verifiers can still use PasswordCard."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_GET_PASSWORD_CONSTRUCTOR,
        ACCOUNT_PASSWORD_CONSTRUCTOR,
        AUTH_AUTHORIZATION_CONSTRUCTOR,
        AUTH_CHECK_PASSWORD_CONSTRUCTOR,
        AUTH_SEND_CODE_CONSTRUCTOR,
        INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR,
        RPC_ERROR_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
    )
    from intelligram.services.accounts import register_password_account

    code_settings_constructor = 0xAD253D78
    auth_key = bytes(range(256))
    salt, session_id = 202, 808
    database = Database(tmp_path / "plaintext-password.sqlite3")
    database.initialize()
    phone = "+15551238881"
    password = "correct-horse-battery-staple"
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone=phone,
            password=password,
            first_name="Legacy",
            device_label="Primary IntelliGram device",
        )
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (issued.user_id,))
        connection.execute("DELETE FROM password_srp_verifiers WHERE user_id = ?", (issued.user_id,))

    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database)
    first_message_id = (int(time.time()) << 32) + 4

    def invoke(query: bytes, index: int) -> TLReader:
        request_message_id = first_message_id + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id,
            seq_no=index * 2 + 1,
            body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        return reader

    send_code = (
        struct.pack("<I", AUTH_SEND_CODE_CONSTRUCTOR)
        + _tl_bytes(phone.encode())
        + struct.pack("<i", 1)
        + _tl_bytes(b"intelligram-self-hosted")
        + struct.pack("<II", code_settings_constructor, 0)
    )
    reader = invoke(send_code, 0)
    assert reader.uint32() == RPC_ERROR_CONSTRUCTOR
    assert reader.int32() == 400
    assert reader.bytes().decode() == "SESSION_PASSWORD_NEEDED"

    reader = invoke(struct.pack("<I", ACCOUNT_GET_PASSWORD_CONSTRUCTOR), 1)
    assert reader.uint32() == ACCOUNT_PASSWORD_CONSTRUCTOR
    reader.uint32()  # flags
    reader.uint32()  # current_algo constructor
    reader.bytes()  # salt1
    reader.bytes()  # salt2
    reader.int32()  # g
    reader.bytes()  # p
    reader.bytes()  # srp_B
    assert reader.int64() == 0

    check_password = (
        struct.pack("<I", AUTH_CHECK_PASSWORD_CONSTRUCTOR)
        + struct.pack("<I", INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR)
        + struct.pack("<q", 0)
        + _tl_bytes(password.encode("utf-8"))
        + _tl_bytes(b"\x00" * 32)
    )
    reader = invoke(check_password, 2)
    assert reader.uint32() == AUTH_AUTHORIZATION_CONSTRUCTOR
    assert adapter.user_id == issued.user_id
    with database.transaction() as connection:
        verifier = connection.execute(
            "SELECT 1 FROM password_srp_verifiers WHERE user_id = ?", (issued.user_id,)
        ).fetchone()
        context = connection.execute(
            "SELECT 1 FROM password_login_contexts WHERE auth_key_id = ?",
            (str(auth_key_id(auth_key)),),
        ).fetchone()
    assert verifier is not None
    assert context is None


def test_web_k_send_media_uploaded_photo_persists_and_downloads(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        INPUT_FILE_CONSTRUCTOR,
        INPUT_MEDIA_UPLOADED_PHOTO_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        INPUT_PHOTO_FILE_LOCATION_CONSTRUCTOR,
        MESSAGE_CONSTRUCTOR,
        MESSAGE_MEDIA_PHOTO_CONSTRUCTOR,
        MESSAGES_SEND_MEDIA_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        STORAGE_FILE_UNKNOWN_CONSTRUCTOR,
        TLReader,
        UPDATE_MESSAGE_ID_CONSTRUCTOR,
        UPDATE_NEW_MESSAGE_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        UPLOAD_FILE_CONSTRUCTOR,
        UPLOAD_GET_FILE_CONSTRUCTOR,
        UPLOAD_SAVE_FILE_PART_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 303, 909
    database = Database(tmp_path / "send-media.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000301", password="correct-horse-battery-staple",
            first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000302", password="correct-horse-battery-staple",
            first_name="Bob", device_label="Bob",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    file_id = 888_001
    content = b"intelligram-attachment-photo-bytes"

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

    send_media = (
        encode_uint32(MESSAGES_SEND_MEDIA_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_uint32(INPUT_MEDIA_UPLOADED_PHOTO_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_FILE_CONSTRUCTOR)
        + encode_int64(file_id)
        + encode_int32(1)
        + encode_tl_string("photo.jpg")
        + encode_tl_string("")
        + encode_tl_string("a photo")
        + encode_int64(4401)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=send_media,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 4
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    assert reader.vector_count() == 2
    assert reader.uint32() == UPDATE_MESSAGE_ID_CONSTRUCTOR
    stored_message_id = reader.int32()
    assert reader.int64() == 4401
    assert reader.uint32() == UPDATE_NEW_MESSAGE_CONSTRUCTOR
    assert reader.uint32() == MESSAGE_CONSTRUCTOR
    flags = reader.uint32()
    assert flags & (1 << 9)
    assert MESSAGE_MEDIA_PHOTO_CONSTRUCTOR.to_bytes(4, "little") in body
    assert adapter.pending_update_envelopes == [] or all(
        getattr(item, "user_id", None) != alice.user_id for item in adapter.pending_update_envelopes
    )

    with database.transaction() as connection:
        media = connection.execute(
            "SELECT file_id, kind, filename FROM message_media WHERE message_id = ?",
            (stored_message_id,),
        ).fetchone()
        stored = connection.execute(
            "SELECT content FROM stored_files WHERE id = ?", (int(media["file_id"]),)
        ).fetchone()
    assert media is not None and media["kind"] == "photo"
    assert media["filename"] == "photo.jpg"
    assert bytes(stored["content"]) == content

    photo_id = int(media["file_id"])
    get_file = (
        encode_uint32(UPLOAD_GET_FILE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PHOTO_FILE_LOCATION_CONSTRUCTOR)
        + encode_int64(photo_id)
        + encode_int64((photo_id << 32) | 1)
        + encode_tl_bytes(f"intelligram-file:{photo_id}".encode("ascii"))
        + encode_tl_string("m")
        + encode_int64(0)
        + encode_int32(len(content))
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 8, seq_no=5, body=get_file,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id + 8
    assert reader.uint32() == UPLOAD_FILE_CONSTRUCTOR
    assert reader.uint32() == STORAGE_FILE_UNKNOWN_CONSTRUCTOR
    assert reader.int32() > 0
    assert reader.bytes() == content


def test_web_k_first_outgoing_message_excludes_sender_from_pending_envelopes(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_SEND_MESSAGE_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_NEW_MESSAGE_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 404, 1010
    database = Database(tmp_path / "no-duplicate-pending.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000311", password="correct-horse-battery-staple",
            first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000312", password="correct-horse-battery-staple",
            first_name="Bob", device_label="Bob",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    query = (
        encode_uint32(MESSAGES_SEND_MESSAGE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_tl_string("hello")
        + encode_int64(5501)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=query,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    reader.int64()
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    assert UPDATE_NEW_MESSAGE_CONSTRUCTOR.to_bytes(4, "little") in body
    pending = adapter.drain_pending_update_envelopes()
    assert all(getattr(item, "user_id", None) != alice.user_id for item in pending)


def test_web_k_creates_broadcast_channel_and_shows_permanent_invite(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CHANNEL_CONSTRUCTOR,
        CHANNELS_CREATE_CHANNEL_CONSTRUCTOR,
        CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR,
        CHANNELS_GET_PARTICIPANTS_CONSTRUCTOR,
        CHANNEL_PARTICIPANTS_RECENT_CONSTRUCTOR,
        INPUT_CHANNEL_CONSTRUCTOR,
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 505, 1111
    database = Database(tmp_path / "create-channel.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection, phone="+15550000401", password="correct-horse-battery-staple",
            first_name="Owner", device_label="Owner",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    message_id = (int(time.time()) << 32) + 4
    create = (
        encode_uint32(CHANNELS_CREATE_CHANNEL_CONSTRUCTOR)
        + encode_uint32(1)  # broadcast
        + encode_tl_string("News")
        + encode_tl_string("Daily updates")
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=create,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    reader.int64()
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    assert CHANNEL_CONSTRUCTOR.to_bytes(4, "little") in body
    channel = TLReader(body[body.index(encode_uint32(CHANNEL_CONSTRUCTOR)):])
    assert channel.uint32() == CHANNEL_CONSTRUCTOR
    flags = channel.uint32()
    assert flags & (1 << 5)  # broadcast
    assert not flags & (1 << 8)  # not megagroup
    with database.transaction() as connection:
        row = connection.execute("SELECT id, title, about FROM peers WHERE kind = 'channel'").fetchone()
        invite = connection.execute("SELECT link, permanent FROM exported_invites WHERE peer_id = ?", (int(row["id"]),)).fetchone()
        settings = connection.execute("SELECT is_broadcast FROM channel_settings WHERE peer_id = ?", (int(row["id"]),)).fetchone()
    assert row["title"] == "News"
    assert row["about"] == "Daily updates"
    assert invite is not None and int(invite["permanent"]) == 1
    assert int(settings["is_broadcast"]) == 1
    channel_id = int(row["id"])

    full = (
        encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR)
        + encode_uint32(INPUT_CHANNEL_CONSTRUCTOR)
        + encode_int64(channel_id)
        + encode_int64((channel_id << 32) | 1)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 4, seq_no=3, body=full,
    ))
    assert response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    full_reader.int64()
    assert full_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR
    assert invite["link"].encode("utf-8") in full_body

    participants = (
        encode_uint32(CHANNELS_GET_PARTICIPANTS_CONSTRUCTOR)
        + encode_uint32(INPUT_CHANNEL_CONSTRUCTOR)
        + encode_int64(channel_id)
        + encode_int64((channel_id << 32) | 1)
        + encode_uint32(CHANNEL_PARTICIPANTS_RECENT_CONSTRUCTOR)
        + encode_int32(0)
        + encode_int32(50)
        + encode_int64(0)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 8, seq_no=5, body=participants,
    ))
    assert response is not None
    _, _, _, _, part_body = _decrypt_server(auth_key, response)
    part_reader = TLReader(part_body)
    assert part_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    part_reader.int64()
    assert part_reader.uint32() == 0x9AB0FEAF  # channels.channelParticipants
    assert part_reader.int32() == 1

    from intelligram.mtproto.tl import (
        INPUT_PEER_CHANNEL_CONSTRUCTOR,
        MESSAGE_CONSTRUCTOR,
        MESSAGES_EDIT_MESSAGE_CONSTRUCTOR,
        UPDATE_EDIT_CHANNEL_MESSAGE_CONSTRUCTOR,
        UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR,
        encode_int32,
    )
    from intelligram.services.messaging import send_message

    with database.transaction(immediate=True) as connection:
        stored, _ = send_message(
            connection,
            peer_id=channel_id,
            sender_user_id=owner.user_id,
            body="Before edit",
            client_random_id="channel-edit-1",
        )
    edit = (
        encode_uint32(MESSAGES_EDIT_MESSAGE_CONSTRUCTOR)
        + encode_uint32(1 << 11)
        + encode_uint32(INPUT_PEER_CHANNEL_CONSTRUCTOR)
        + encode_int64(channel_id)
        + encode_int64((channel_id << 32) | 1)
        + encode_int32(int(stored["id"]))
        + encode_tl_string("After edit")
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id + 12, seq_no=7, body=edit,
    ))
    assert response is not None
    _, _, _, _, edit_body = _decrypt_server(auth_key, response)
    edit_reader = TLReader(edit_body)
    assert edit_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    edit_reader.int64()
    assert edit_reader.uint32() == UPDATES_CONSTRUCTOR
    assert UPDATE_EDIT_CHANNEL_MESSAGE_CONSTRUCTOR.to_bytes(4, "little") in edit_body
    assert UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR.to_bytes(4, "little") not in edit_body
    message_offset = edit_body.index(encode_uint32(MESSAGE_CONSTRUCTOR))
    encoded_message = TLReader(edit_body[message_offset:])
    assert encoded_message.uint32() == MESSAGE_CONSTRUCTOR
    assert encoded_message.uint32() & (1 << 15)  # edit_date / edited badge


def test_channel_post_uses_channel_author_and_idempotent_retry_acknowledges(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_CHANNEL_CONSTRUCTOR,
        MESSAGE_CONSTRUCTOR,
        MESSAGES_SEND_MESSAGE_CONSTRUCTOR,
        PEER_CHANNEL_CONSTRUCTOR,
        RPC_ERROR_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATE_MESSAGE_ID_CONSTRUCTOR,
        UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        channel_access_hash,
        encode_int64,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import create_channel

    auth_key = bytes(range(256))
    salt, session_id = 707, 31337
    database = Database(tmp_path / "channel-post-retry.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection,
            phone="+15550000501",
            password="correct-horse-battery-staple",
            first_name="Owner",
            device_label="Owner",
        )
        channel, _ = create_channel(
            connection,
            owner_user_id=owner.user_id,
            title="Broadcast identity test",
            broadcast=True,
        )
    channel_id = int(channel["id"])
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    request_message_id = (int(time.time()) << 32) + 4
    query = (
        encode_uint32(MESSAGES_SEND_MESSAGE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_CHANNEL_CONSTRUCTOR)
        + encode_int64(channel_id)
        + encode_int64(channel_access_hash(channel_id))
        + encode_tl_string("A channel post, not a personal message")
        + encode_int64(424242)
    )

    response = adapter.handle_encrypted(
        _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=1, body=query)
    )
    assert response is not None
    _, _, _, _, first_body = _decrypt_server(auth_key, response)
    assert RPC_ERROR_CONSTRUCTOR.to_bytes(4, "little") not in first_body
    assert UPDATE_MESSAGE_ID_CONSTRUCTOR.to_bytes(4, "little") in first_body
    assert UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR.to_bytes(4, "little") in first_body
    message_offset = first_body.index(encode_uint32(MESSAGE_CONSTRUCTOR))
    encoded = TLReader(first_body[message_offset:])
    assert encoded.uint32() == MESSAGE_CONSTRUCTOR
    assert not encoded.uint32() & (1 << 1)  # channel post is not a personal outgoing “You” message
    encoded.uint32()  # flags2
    encoded.int32()   # message id
    assert encoded.uint32() == PEER_CHANNEL_CONSTRUCTOR
    assert encoded.int64() == channel_id

    retry = adapter.handle_encrypted(
        _encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id + 4,
            seq_no=3,
            body=query,
        )
    )
    assert retry is not None
    _, _, _, _, retry_body = _decrypt_server(auth_key, retry)
    retry_reader = TLReader(retry_body)
    assert retry_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    retry_reader.int64()
    assert retry_reader.uint32() == UPDATES_CONSTRUCTOR
    assert UPDATE_MESSAGE_ID_CONSTRUCTOR.to_bytes(4, "little") in retry_body
    assert UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR.to_bytes(4, "little") in retry_body
    with database.transaction() as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM messages WHERE sender_user_id = ? AND client_random_id = ?",
            (owner.user_id, "424242"),
        ).fetchone()
    assert int(count["count"]) == 1


def test_web_k_uploaded_voice_note_preserves_native_metadata_and_downloads(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR,
        DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR,
        INPUT_DOCUMENT_FILE_LOCATION_CONSTRUCTOR,
        INPUT_FILE_CONSTRUCTOR,
        INPUT_MEDIA_UPLOADED_DOCUMENT_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGE_MEDIA_DOCUMENT_CONSTRUCTOR,
        MESSAGES_GET_HISTORY_CONSTRUCTOR,
        MESSAGES_SEND_MEDIA_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        STORAGE_FILE_UNKNOWN_CONSTRUCTOR,
        TLReader,
        UPLOAD_FILE_CONSTRUCTOR,
        UPLOAD_GET_FILE_CONSTRUCTOR,
        UPLOAD_SAVE_FILE_PART_CONSTRUCTOR,
        VECTOR_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 808, 41414
    database = Database(tmp_path / "voice-note.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection,
            phone="+15550000511",
            password="correct-horse-battery-staple",
            first_name="Alice",
            device_label="Alice",
        )
        bob = register_password_account(
            connection,
            phone="+15550000512",
            password="correct-horse-battery-staple",
            first_name="Bob",
            device_label="Bob",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    request_message_id = (int(time.time()) << 32) + 4
    upload_id = 888_515
    voice_bytes = b"OggS-intelligram-controlled-voice-note"
    waveform = b"\x10\x20\x30\x40"

    save_part = (
        encode_uint32(UPLOAD_SAVE_FILE_PART_CONSTRUCTOR)
        + encode_int64(upload_id)
        + encode_int32(0)
        + encode_tl_bytes(voice_bytes)
    )
    response = adapter.handle_encrypted(
        _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=1, body=save_part)
    )
    assert response is not None
    _, _, _, _, saved_part_body = _decrypt_server(auth_key, response)
    saved_part_reader = TLReader(saved_part_body)
    assert saved_part_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    saved_part_reader.int64()
    assert saved_part_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    audio_attribute = (
        encode_uint32(DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR)
        + encode_uint32((1 << 10) | 1 | (1 << 2))
        + encode_int32(7)
        + encode_tl_string("Controlled voice")
        + encode_tl_bytes(waveform)
    )
    filename_attribute = encode_uint32(DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR) + encode_tl_string("audio.ogg")
    send_voice = (
        encode_uint32(MESSAGES_SEND_MEDIA_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_uint32(INPUT_MEDIA_UPLOADED_DOCUMENT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_FILE_CONSTRUCTOR)
        + encode_int64(upload_id)
        + encode_int32(1)
        + encode_tl_string("audio.ogg")
        + encode_tl_string("")
        + encode_tl_string("audio/ogg")
        + encode_uint32(VECTOR_CONSTRUCTOR)
        + encode_int32(2)
        + filename_attribute
        + audio_attribute
        + encode_tl_string("")
        + encode_int64(515151)
    )
    response = adapter.handle_encrypted(
        _encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id + 4,
            seq_no=3,
            body=send_voice,
        )
    )
    assert response is not None
    _, _, _, _, sent_body = _decrypt_server(auth_key, response)
    assert MESSAGE_MEDIA_DOCUMENT_CONSTRUCTOR.to_bytes(4, "little") in sent_body
    audio_offset = sent_body.index(encode_uint32(DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR))
    audio_reader = TLReader(sent_body[audio_offset:])
    assert audio_reader.uint32() == DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR
    assert audio_reader.uint32() & (1 << 10)
    assert audio_reader.int32() == 7
    assert audio_reader.bytes() == b"Controlled voice"
    assert audio_reader.bytes() == waveform

    with database.transaction() as connection:
        row = connection.execute(
            "SELECT mm.file_id, mm.mime_type, mm.attributes_json FROM message_media mm ORDER BY message_id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert str(row["mime_type"]) == "audio/ogg"
    assert '"voice":true' in str(row["attributes_json"])
    file_id = int(row["file_id"])

    get_file = (
        encode_uint32(UPLOAD_GET_FILE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_DOCUMENT_FILE_LOCATION_CONSTRUCTOR)
        + encode_int64(file_id)
        + encode_int64((file_id << 32) | 1)
        + encode_tl_bytes(f"intelligram-file:{file_id}".encode("ascii"))
        + encode_tl_string("")
        + encode_int64(0)
        + encode_int32(len(voice_bytes))
    )
    response = adapter.handle_encrypted(
        _encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id + 8,
            seq_no=5,
            body=get_file,
        )
    )
    assert response is not None
    _, _, _, _, file_body = _decrypt_server(auth_key, response)
    file_reader = TLReader(file_body)
    assert file_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    file_reader.int64()
    assert file_reader.uint32() == UPLOAD_FILE_CONSTRUCTOR
    assert file_reader.uint32() == STORAGE_FILE_UNKNOWN_CONSTRUCTOR
    file_reader.int32()
    assert file_reader.bytes() == voice_bytes

    history = (
        encode_uint32(MESSAGES_GET_HISTORY_CONSTRUCTOR)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_int32(0)
        + encode_int32(0)
        + encode_int32(0)
        + encode_int32(20)
        + encode_int32(0)
        + encode_int32(0)
        + encode_int64(0)
    )
    response = adapter.handle_encrypted(
        _encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id + 12,
            seq_no=7,
            body=history,
        )
    )
    assert response is not None
    _, _, _, _, history_body = _decrypt_server(auth_key, response)
    history_audio_offset = history_body.index(encode_uint32(DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR))
    history_audio = TLReader(history_body[history_audio_offset:])
    assert history_audio.uint32() == DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR
    assert history_audio.uint32() & (1 << 10)
    assert history_audio.int32() == 7
    assert history_audio.bytes() == b"Controlled voice"
    assert history_audio.bytes() == waveform


def test_web_k_persists_channel_signatures_after_encrypted_toggle(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        CHANNEL_CONSTRUCTOR,
        CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR,
        CHANNELS_TOGGLE_SIGNATURES_CONSTRUCTOR,
        INPUT_CHANNEL_CONSTRUCTOR,
        MESSAGES_CHAT_FULL_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        encode_int64,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import create_group, migrate_chat_to_channel

    auth_key = bytes(range(256))
    salt, session_id = 1_103, 4_204
    database = Database(tmp_path / "channel-signatures.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        owner = register_password_account(
            connection,
            phone="+15550000184",
            password="correct-horse-battery-staple",
            first_name="Owner",
            device_label="Owner",
        )
        chat_id, _ = create_group(connection, owner_user_id=owner.user_id, title="Signature channel", member_user_ids=[])
        migrate_chat_to_channel(connection, chat_id=chat_id, actor_user_id=owner.user_id)
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=owner.user_id)
    message_id = (int(time.time()) << 32) + 8
    input_channel = encode_uint32(INPUT_CHANNEL_CONSTRUCTOR) + encode_int64(chat_id) + encode_int64((chat_id << 32) | 1)

    toggle_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(CHANNELS_TOGGLE_SIGNATURES_CONSTRUCTOR) + encode_uint32(1) + input_channel,
    ))
    assert toggle_response is not None
    _, _, _, _, toggle_body = _decrypt_server(auth_key, toggle_response)
    toggle_reader = TLReader(toggle_body)
    assert toggle_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert toggle_reader.int64() == message_id
    assert toggle_reader.uint32() == UPDATES_CONSTRUCTOR
    channel_offset = toggle_body.index(encode_uint32(CHANNEL_CONSTRUCTOR))
    updated_channel = TLReader(toggle_body[channel_offset:])
    assert updated_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert updated_channel.uint32() & (1 << 11)
    with database.transaction() as connection:
        settings = connection.execute(
            "SELECT signatures_enabled FROM channel_settings WHERE peer_id = ?", (chat_id,)
        ).fetchone()
    assert settings is not None and int(settings["signatures_enabled"]) == 1

    full_response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id + 4,
        seq_no=3,
        body=encode_uint32(CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR) + input_channel,
    ))
    assert full_response is not None
    _, _, _, _, full_body = _decrypt_server(auth_key, full_response)
    full_reader = TLReader(full_body)
    assert full_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert full_reader.int64() == message_id + 4
    assert full_reader.uint32() == MESSAGES_CHAT_FULL_CONSTRUCTOR
    full_channel_offset = full_body.index(encode_uint32(CHANNEL_CONSTRUCTOR))
    reloaded_channel = TLReader(full_body[full_channel_offset:])
    assert reloaded_channel.uint32() == CHANNEL_CONSTRUCTOR
    assert reloaded_channel.uint32() & (1 << 11)


def test_web_k_send_media_uploaded_document_preserves_mime_and_downloads(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR,
        INPUT_DOCUMENT_FILE_LOCATION_CONSTRUCTOR,
        INPUT_FILE_CONSTRUCTOR,
        INPUT_MEDIA_UPLOADED_DOCUMENT_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGE_MEDIA_DOCUMENT_CONSTRUCTOR,
        MESSAGES_SEND_MEDIA_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        STORAGE_FILE_UNKNOWN_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        UPLOAD_FILE_CONSTRUCTOR,
        UPLOAD_GET_FILE_CONSTRUCTOR,
        UPLOAD_SAVE_FILE_PART_CONSTRUCTOR,
        VECTOR_CONSTRUCTOR,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 818, 51515
    database = Database(tmp_path / "document-note.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection,
            phone="+15550000521",
            password="correct-horse-battery-staple",
            first_name="Alice",
            device_label="Alice",
        )
        bob = register_password_account(
            connection,
            phone="+15550000522",
            password="correct-horse-battery-staple",
            first_name="Bob",
            device_label="Bob",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    request_message_id = (int(time.time()) << 32) + 4
    upload_id = 888_521
    document_bytes = b"%PDF-1.7\n%IntelliGram controlled document\n"

    save_part = (
        encode_uint32(UPLOAD_SAVE_FILE_PART_CONSTRUCTOR)
        + encode_int64(upload_id)
        + encode_int32(0)
        + encode_tl_bytes(document_bytes)
    )
    response = adapter.handle_encrypted(
        _encrypt_client(auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=1, body=save_part)
    )
    assert response is not None
    _, _, _, _, saved_part_body = _decrypt_server(auth_key, response)
    saved_part_reader = TLReader(saved_part_body)
    assert saved_part_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    saved_part_reader.int64()
    assert saved_part_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    filename = "controlled-report.pdf"
    filename_attribute = (
        encode_uint32(DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR)
        + encode_tl_string(filename)
    )
    send_document = (
        encode_uint32(MESSAGES_SEND_MEDIA_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(bob.user_id)
        + encode_int64(user_access_hash(bob.user_id))
        + encode_uint32(INPUT_MEDIA_UPLOADED_DOCUMENT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_FILE_CONSTRUCTOR)
        + encode_int64(upload_id)
        + encode_int32(1)
        + encode_tl_string(filename)
        + encode_tl_string("")
        + encode_tl_string("application/pdf")
        + encode_uint32(VECTOR_CONSTRUCTOR)
        + encode_int32(1)
        + filename_attribute
        + encode_tl_string("Controlled document")
        + encode_int64(521521)
    )
    response = adapter.handle_encrypted(
        _encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id + 4,
            seq_no=3,
            body=send_document,
        )
    )
    assert response is not None
    _, _, _, _, sent_body = _decrypt_server(auth_key, response)
    sent_reader = TLReader(sent_body)
    assert sent_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    sent_reader.int64()
    assert sent_reader.uint32() == UPDATES_CONSTRUCTOR
    assert sent_reader.vector_count() == 2
    # updateMessageID then updateNewMessage with messageMediaDocument.
    sent_reader.uint32()
    stored_message_id = sent_reader.int32()
    sent_reader.int64()
    assert MESSAGE_MEDIA_DOCUMENT_CONSTRUCTOR.to_bytes(4, "little") in sent_body

    with database.transaction() as connection:
        media = connection.execute(
            "SELECT file_id, kind, filename, mime_type FROM message_media WHERE message_id = ?",
            (stored_message_id,),
        ).fetchone()
        assert media is not None
        stored = connection.execute(
            "SELECT mime_type, content FROM stored_files WHERE id = ?",
            (int(media["file_id"]),),
        ).fetchone()
    assert str(media["kind"]) == "document"
    assert str(media["filename"]) == filename
    assert str(media["mime_type"]) == "application/pdf"
    assert stored is not None
    assert str(stored["mime_type"]) == "application/pdf"
    assert bytes(stored["content"]) == document_bytes

    file_id = int(media["file_id"])
    get_file = (
        encode_uint32(UPLOAD_GET_FILE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_DOCUMENT_FILE_LOCATION_CONSTRUCTOR)
        + encode_int64(file_id)
        + encode_int64((file_id << 32) | 1)
        + encode_tl_bytes(f"intelligram-file:{file_id}".encode("ascii"))
        + encode_tl_string("")
        + encode_int64(0)
        + encode_int32(len(document_bytes))
    )
    response = adapter.handle_encrypted(
        _encrypt_client(
            auth_key,
            salt=salt,
            session_id=session_id,
            msg_id=request_message_id + 8,
            seq_no=5,
            body=get_file,
        )
    )
    assert response is not None
    _, _, _, _, file_body = _decrypt_server(auth_key, response)
    file_reader = TLReader(file_body)
    assert file_reader.uint32() == RPC_RESULT_CONSTRUCTOR
    file_reader.int64()
    assert file_reader.uint32() == UPLOAD_FILE_CONSTRUCTOR
    assert file_reader.uint32() == STORAGE_FILE_UNKNOWN_CONSTRUCTOR
    file_reader.int32()
    assert file_reader.bytes() == document_bytes


def test_web_k_update_password_settings_replaces_srp_verifier(tmp_path) -> None:
    import hashlib
    import time

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_GET_PASSWORD_CONSTRUCTOR,
        ACCOUNT_PASSWORD_CONSTRUCTOR,
        ACCOUNT_PASSWORD_INPUT_SETTINGS_CONSTRUCTOR,
        ACCOUNT_UPDATE_PASSWORD_SETTINGS_CONSTRUCTOR,
        AUTH_AUTHORIZATION_CONSTRUCTOR,
        AUTH_CHECK_PASSWORD_CONSTRUCTOR,
        BOOL_TRUE_CONSTRUCTOR,
        INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR,
        PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        SECURE_PASSWORD_KDF_ALGO_UNKNOWN_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_tl_string,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.srp import G, P, P_BYTES

    auth_key = bytes(range(255, -1, -1))
    salt, session_id = 919, 61616
    old_password = "correct-horse-battery-staple"
    new_password = "new-native-srp-password"
    database = Database(tmp_path / "update-password.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone="+15550000531",
            password=old_password,
            first_name="Password Owner",
            device_label="Primary device",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=issued.user_id)
    # Real signed-in MTProto sessions persist this binding at authorization;
    # this focused fixture begins from a trusted direct adapter instead.
    adapter._associate_auth_key(issued.user_id)
    first_message_id = (int(time.time()) << 32) + 4

    def invoke(query: bytes, index: int) -> TLReader:
        request_message_id = first_message_id + index * 4
        response = adapter.handle_encrypted(
            _encrypt_client(
                auth_key,
                salt=salt,
                session_id=session_id,
                msg_id=request_message_id,
                seq_no=index * 2 + 1,
                body=query,
            )
        )
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        return reader

    def read_password_state(index: int) -> tuple[bytes, bytes, bytes, int]:
        reader = invoke(encode_uint32(ACCOUNT_GET_PASSWORD_CONSTRUCTOR), index)
        assert reader.uint32() == ACCOUNT_PASSWORD_CONSTRUCTOR
        assert reader.uint32() == 1 << 2
        assert reader.uint32() == PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR
        salt1 = reader.bytes()
        salt2 = reader.bytes()
        assert reader.int32() == G
        assert reader.bytes() == P_BYTES
        srp_B = reader.bytes()
        srp_id = reader.int64()
        assert reader.uint32() == PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR
        reader.bytes()
        reader.bytes()
        reader.int32()
        reader.bytes()
        assert reader.uint32() == SECURE_PASSWORD_KDF_ALGO_UNKNOWN_CONSTRUCTOR
        reader.bytes()
        return salt1, salt2, srp_B, srp_id

    def proof(password: str, salt1: bytes, salt2: bytes, srp_B: bytes) -> tuple[bytes, bytes]:
        def sha(value: bytes) -> bytes:
            return hashlib.sha256(value).digest()

        def pad(value: int) -> bytes:
            return value.to_bytes(256, "big")

        first_hash = sha(salt1 + password.encode() + salt1)
        second_hash = sha(salt2 + first_hash + salt2)
        stretched = hashlib.pbkdf2_hmac("sha512", second_hash, salt1, 100_000, dklen=64)
        x = int.from_bytes(sha(salt2 + stretched + salt2), "big")
        private_a = 0xA5A5A5A5A5A5A5
        public_A = pow(G, private_a, P)
        public_B = int.from_bytes(srp_B, "big")
        multiplier = int.from_bytes(sha(pad(P) + pad(G)), "big")
        scrambling = int.from_bytes(sha(pad(public_A) + pad(public_B)), "big")
        shared_secret = pow((public_B - multiplier * pow(G, x, P)) % P, private_a + scrambling * x, P)
        session_key = sha(pad(shared_secret))
        hash_prime_xor_generator = bytes(left ^ right for left, right in zip(sha(pad(P)), sha(pad(G)), strict=True))
        m1 = sha(
            hash_prime_xor_generator + sha(salt1) + sha(salt2)
            + pad(public_A) + pad(public_B) + session_key
        )
        return pad(public_A), m1

    salt1, salt2, srp_B, srp_id = read_password_state(0)
    client_A, client_M1 = proof(old_password, salt1, salt2, srp_B)
    new_salt1 = salt1 + b"\x81" * 32
    new_first = hashlib.sha256(new_salt1 + new_password.encode() + new_salt1).digest()
    new_second = hashlib.sha256(salt2 + new_first + salt2).digest()
    new_stretched = hashlib.pbkdf2_hmac("sha512", new_second, new_salt1, 100_000, dklen=64)
    new_x = int.from_bytes(hashlib.sha256(salt2 + new_stretched + salt2).digest(), "big")
    new_verifier = pow(G, new_x, P).to_bytes(256, "big")
    update_request = (
        encode_uint32(ACCOUNT_UPDATE_PASSWORD_SETTINGS_CONSTRUCTOR)
        + encode_uint32(INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR)
        + encode_int64(srp_id)
        + encode_tl_bytes(client_A)
        + encode_tl_bytes(client_M1)
        + encode_uint32(ACCOUNT_PASSWORD_INPUT_SETTINGS_CONSTRUCTOR)
        + encode_uint32(1)
        + encode_uint32(PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR)
        + encode_tl_bytes(new_salt1)
        + encode_tl_bytes(salt2)
        + encode_int32(G)
        + encode_tl_bytes(P_BYTES)
        + encode_tl_bytes(new_verifier)
        + encode_tl_string("updated natively")
    )
    reader = invoke(update_request, 1)
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    refreshed_salt1, refreshed_salt2, refreshed_B, refreshed_id = read_password_state(2)
    assert refreshed_salt1 == new_salt1
    assert refreshed_salt2 == salt2
    new_A, new_M1 = proof(new_password, refreshed_salt1, refreshed_salt2, refreshed_B)
    reader = invoke(
        encode_uint32(AUTH_CHECK_PASSWORD_CONSTRUCTOR)
        + encode_uint32(INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR)
        + encode_int64(refreshed_id)
        + encode_tl_bytes(new_A)
        + encode_tl_bytes(new_M1),
        3,
    )
    assert reader.uint32() == AUTH_AUTHORIZATION_CONSTRUCTOR

    with database.transaction() as connection:
        legacy_hash = connection.execute("SELECT password_hash FROM users WHERE id = ?", (issued.user_id,)).fetchone()
    assert legacy_hash is not None and legacy_hash["password_hash"] is None


def test_web_k_authorization_removal_revokes_live_other_adapters(tmp_path) -> None:
    import time

    from intelligram.database import Database
    from intelligram.mtproto.crypto import auth_key_id
    from intelligram.mtproto.tl import (
        ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR,
        ACCOUNT_RESET_AUTHORIZATION_CONSTRUCTOR,
        AUTH_RESET_AUTHORIZATIONS_CONSTRUCTOR,
        BOOL_TRUE_CONSTRUCTOR,
        RPC_ERROR_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int64,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    database = Database(tmp_path / "authorization-revocation.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection,
            phone="+15550000541",
            password="correct-horse-battery-staple",
            first_name="Session Owner",
            device_label="Primary REST session",
        )
    salt, session_id = 1001, 71717
    primary_key = bytes(range(256))
    removed_key = bytes(reversed(range(256)))
    all_reset_key = bytes((value ^ 0x55) for value in range(256))
    primary = MTProtoSessionAdapter(auth_key=primary_key, server_salt=salt, database=database, user_id=issued.user_id)
    removed = MTProtoSessionAdapter(auth_key=removed_key, server_salt=salt, database=database, user_id=issued.user_id)
    all_reset = MTProtoSessionAdapter(auth_key=all_reset_key, server_salt=salt, database=database, user_id=issued.user_id)
    for adapter in (primary, removed, all_reset):
        adapter._associate_auth_key(issued.user_id)
    first_message_id = (int(time.time()) << 32) + 4

    def invoke(adapter: MTProtoSessionAdapter, key: bytes, query: bytes, index: int) -> TLReader:
        request_message_id = first_message_id + index * 4
        response = adapter.handle_encrypted(
            _encrypt_client(
                key,
                salt=salt,
                session_id=session_id,
                msg_id=request_message_id,
                seq_no=index * 2 + 1,
                body=query,
            )
        )
        assert response is not None
        _, _, _, _, body = _decrypt_server(key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == request_message_id
        return reader

    removed_key_id = auth_key_id(removed_key)
    signed_removed_key_id = removed_key_id if removed_key_id < (1 << 63) else removed_key_id - (1 << 64)
    reader = invoke(
        primary,
        primary_key,
        encode_uint32(ACCOUNT_RESET_AUTHORIZATION_CONSTRUCTOR) + encode_int64(signed_removed_key_id),
        0,
    )
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    reader = invoke(removed, removed_key, encode_uint32(ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR), 1)
    assert reader.uint32() == RPC_ERROR_CONSTRUCTOR
    assert reader.int32() == 401
    assert reader.bytes() == b"AUTH_KEY_UNREGISTERED"

    reader = invoke(primary, primary_key, encode_uint32(AUTH_RESET_AUTHORIZATIONS_CONSTRUCTOR), 2)
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    reader = invoke(all_reset, all_reset_key, encode_uint32(ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR), 3)
    assert reader.uint32() == RPC_ERROR_CONSTRUCTOR
    assert reader.int32() == 401
    assert reader.bytes() == b"AUTH_KEY_UNREGISTERED"

    reader = invoke(primary, primary_key, encode_uint32(ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR), 4)
    # The current device remains authorized and returns account.authorizations.
    assert reader.uint32() != RPC_ERROR_CONSTRUCTOR


def test_generic_attachment_accepts_unknown_extension_at_50_mib_and_rejects_overage(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import MessagingError

    database = Database(tmp_path / "attachment-limit.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        user = register_password_account(
            connection,
            phone="+15550000542",
            password="correct-horse-battery-staple",
            first_name="Attachment Boundary",
            device_label="Attachment test",
        )

    adapter = MTProtoSessionAdapter(
        auth_key=bytes(range(256)),
        server_salt=123,
        database=database,
        user_id=user.user_id,
    )
    exact = b"x" * (50 * 1024 * 1024)
    with database.transaction(immediate=True) as connection:
        connection.execute(
            "INSERT INTO upload_parts(file_id, user_id, part_index, content, created_at) VALUES (?, ?, ?, ?, ?)",
            (9001, user.user_id, 0, exact, 1),
        )
        stored = adapter._assemble_uploaded_file(
            connection,
            user_id=user.user_id,
            file={"file_id": 9001, "parts": 1, "name": "archive.unknownext"},
        )
        assert stored["mime_type"] == "application/octet-stream"
        assert int(stored["id"]) > 0

    overage = b"x" * (50 * 1024 * 1024) + b"y"
    with database.transaction(immediate=True) as connection:
        connection.execute(
            "INSERT INTO upload_parts(file_id, user_id, part_index, content, created_at) VALUES (?, ?, ?, ?, ?)",
            (9002, user.user_id, 0, overage, 1),
        )
        with pytest.raises(MessagingError, match="FILE_TOO_BIG"):
            adapter._assemble_uploaded_file(
                connection,
                user_id=user.user_id,
                file={"file_id": 9002, "parts": 1, "name": "payload.no_known_extension"},
            )


def test_web_k_gzip_packed_upload_part_is_accepted(tmp_path) -> None:
    """Web K gzips upload parts for files whose mime type is not already
    compressed, so .jar/.md/.txt attachments arrive wrapped in gzip_packed."""
    import gzip

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        GZIP_PACKED_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        UPLOAD_SAVE_FILE_PART_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_int64,
        encode_tl_bytes,
        encode_uint32,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 971, 314
    database = Database(tmp_path / "gzip-upload.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        user = register_password_account(
            connection,
            phone="+15550000901",
            password="correct-horse-battery-staple",
            first_name="Uploader",
            device_label="Uploader",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=user.user_id)
    payload = b"PK\x03\x04ViaVersion-jar-part-bytes"
    query = (
        encode_uint32(UPLOAD_SAVE_FILE_PART_CONSTRUCTOR)
        + encode_int64(16373782892030258)
        + encode_int32(0)
        + encode_tl_bytes(payload)
    )
    message_id = (int(time.time()) << 32) + 4
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key,
        salt=salt,
        session_id=session_id,
        msg_id=message_id,
        seq_no=1,
        body=encode_uint32(GZIP_PACKED_CONSTRUCTOR) + encode_tl_bytes(gzip.compress(_wrapped_query(query))),
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR
    with database.transaction() as connection:
        stored = connection.execute(
            "SELECT content FROM upload_parts WHERE file_id = ? AND part_index = ?",
            (16373782892030258, 0),
        ).fetchone()
        assert stored is not None and bytes(stored["content"]) == payload


def _read_encoded_user(reader) -> dict:
    """Decode one ``user`` constructor into the fields this suite asserts on."""
    from intelligram.mtproto.tl import USER_CONSTRUCTOR

    assert reader.uint32() == USER_CONSTRUCTOR
    flags = reader.uint32()
    reader.uint32()  # flags2
    decoded = {
        "id": reader.int64(),
        "access_hash": reader.int64(),
        "self": bool(flags & (1 << 10)),
        "contact": bool(flags & (1 << 11)),
        "mutual_contact": bool(flags & (1 << 12)),
        "first_name": None,
        "last_name": None,
        "username": None,
        "phone": None,
    }
    if flags & (1 << 1):
        decoded["first_name"] = reader.bytes().decode("utf-8")
    if flags & (1 << 2):
        decoded["last_name"] = reader.bytes().decode("utf-8")
    if flags & (1 << 3):
        decoded["username"] = reader.bytes().decode("utf-8")
    if flags & (1 << 4):
        decoded["phone"] = reader.bytes().decode("utf-8")
    return decoded


def test_web_k_contact_management_round_trip(tmp_path) -> None:
    """Saving a contact must set the contact flag, apply the saved name, and
    leave unsaved accounts unflagged -- Web K keys its whole contact list off
    ``user.pFlags.contact``, so flagging everyone makes "add contact" a no-op."""
    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        BOOL_TRUE_CONSTRUCTOR,
        CONTACTS_ADD_CONTACT_CONSTRUCTOR,
        CONTACTS_BLOCKED_CONSTRUCTOR,
        CONTACTS_BLOCK_CONSTRUCTOR,
        CONTACTS_CONTACTS_CONSTRUCTOR,
        CONTACTS_DELETE_CONTACTS_CONSTRUCTOR,
        CONTACTS_GET_BLOCKED_CONSTRUCTOR,
        CONTACTS_GET_CONTACTS_CONSTRUCTOR,
        CONTACT_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        INPUT_USER_CONSTRUCTOR,
        PEER_BLOCKED_CONSTRUCTOR,
        PEER_USER_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        UPDATES_CONSTRUCTOR,
        USERS_GET_USERS_CONSTRUCTOR,
        TLReader,
        encode_int32,
        encode_int64,
        encode_tl_string,
        encode_uint32,
        encode_vector,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 977, 315
    database = Database(tmp_path / "contact-management.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000801", password="correct-horse-battery-staple",
            first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000802", password="correct-horse-battery-staple",
            first_name="Bob", device_label="Bob",
        )
        carol = register_password_account(
            connection, phone="+15550000803", password="correct-horse-battery-staple",
            first_name="Carol", device_label="Carol",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    seq = 0

    def invoke(body: bytes) -> TLReader:
        nonlocal message_id, seq
        message_id += 4
        seq += 2
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=seq, body=body,
        ))
        assert response is not None
        _, _, _, _, decrypted = _decrypt_server(auth_key, response)
        reader = TLReader(decrypted)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        assert reader.int64() == message_id
        return reader

    def input_user(user_id: int) -> bytes:
        return encode_uint32(INPUT_USER_CONSTRUCTOR) + encode_int64(user_id) + encode_int64(user_access_hash(user_id))

    reader = invoke(
        encode_uint32(CONTACTS_ADD_CONTACT_CONSTRUCTOR)
        + encode_uint32(0)
        + input_user(bob.user_id)
        + encode_tl_string("Bobby")
        + encode_tl_string("Saved")
        + encode_tl_string("+15550000802")
    )
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    reader.vector_count()  # updates
    reader.uint32()  # updateUser
    assert reader.int64() == bob.user_id
    assert reader.vector_count() == 1
    saved = _read_encoded_user(reader)
    assert saved["id"] == bob.user_id
    assert saved["contact"] is True and saved["mutual_contact"] is False
    assert (saved["first_name"], saved["last_name"]) == ("Bobby", "Saved")
    assert saved["phone"] == "+15550000802"

    with database.transaction() as connection:
        row = connection.execute(
            "SELECT first_name, last_name, phone FROM contacts WHERE user_id = ? AND contact_user_id = ?",
            (alice.user_id, bob.user_id),
        ).fetchone()
        assert row is not None
        assert (row["first_name"], row["last_name"]) == ("Bobby", "Saved")
        # The shared profile row keeps the account's own name.
        assert connection.execute("SELECT first_name FROM users WHERE id = ?", (bob.user_id,)).fetchone()["first_name"] == "Bob"

    reader = invoke(encode_uint32(CONTACTS_GET_CONTACTS_CONSTRUCTOR) + encode_int64(0))
    assert reader.uint32() == CONTACTS_CONTACTS_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == CONTACT_CONSTRUCTOR
    assert reader.int64() == bob.user_id
    reader.uint32()  # mutual Bool
    assert reader.int32() == 1  # saved_count
    assert reader.vector_count() == 1
    assert _read_encoded_user(reader)["first_name"] == "Bobby"

    # Carol was never saved, so she must not look like a contact and must not
    # leak her phone number to Alice.
    reader = invoke(encode_uint32(USERS_GET_USERS_CONSTRUCTOR) + encode_vector([input_user(carol.user_id)]))
    assert reader.vector_count() == 1
    stranger = _read_encoded_user(reader)
    assert stranger["id"] == carol.user_id
    assert stranger["contact"] is False
    assert stranger["phone"] is None

    reader = invoke(
        encode_uint32(CONTACTS_BLOCK_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(carol.user_id)
        + encode_int64(user_access_hash(carol.user_id))
    )
    assert reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    reader = invoke(
        encode_uint32(CONTACTS_GET_BLOCKED_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(0)
        + encode_int32(100)
    )
    assert reader.uint32() == CONTACTS_BLOCKED_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == PEER_BLOCKED_CONSTRUCTOR
    assert reader.uint32() == PEER_USER_CONSTRUCTOR
    assert reader.int64() == carol.user_id

    reader = invoke(encode_uint32(CONTACTS_DELETE_CONTACTS_CONSTRUCTOR) + encode_vector([input_user(bob.user_id)]))
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    assert reader.vector_count() == 1

    reader = invoke(encode_uint32(CONTACTS_GET_CONTACTS_CONSTRUCTOR) + encode_int64(0))
    assert reader.uint32() == CONTACTS_CONTACTS_CONSTRUCTOR
    assert reader.vector_count() == 0


def _read_forward_fwd_header_from_response(body: bytes, message_id: int) -> tuple[int | None, str | None, int | None]:
    """Unwrap a forward RPC update and return (fwd from_id user, from_name, fwd date)."""
    from intelligram.mtproto.tl import (
        MESSAGE_CONSTRUCTOR,
        MESSAGE_FWD_HEADER_CONSTRUCTOR,
        PEER_USER_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        UPDATES_CONSTRUCTOR,
        UPDATE_MESSAGE_ID_CONSTRUCTOR,
        UPDATE_NEW_MESSAGE_CONSTRUCTOR,
    )

    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == message_id
    assert reader.uint32() == UPDATES_CONSTRUCTOR
    update_count = reader.vector_count()
    fwd_user_id: int | None = None
    fwd_name: str | None = None
    fwd_date: int | None = None
    for _ in range(update_count):
        ctor = reader.uint32()
        if ctor == UPDATE_MESSAGE_ID_CONSTRUCTOR:
            reader.int32()
            reader.int64()
            continue
        assert ctor == UPDATE_NEW_MESSAGE_CONSTRUCTOR
        assert reader.uint32() == MESSAGE_CONSTRUCTOR
        flags = reader.uint32()
        reader.uint32()  # flags2
        reader.int32()  # message id
        reader.uint32()  # from_id peer constructor
        reader.int64()
        reader.uint32()  # peer_id constructor
        reader.int64()
        if flags & (1 << 2):
            assert reader.uint32() == MESSAGE_FWD_HEADER_CONSTRUCTOR
            fwd_flags = reader.uint32()
            if fwd_flags & 1:
                assert reader.uint32() == PEER_USER_CONSTRUCTOR
                fwd_user_id = reader.int64()
            else:
                fwd_user_id = None
                fwd_name = reader.bytes().decode("utf-8")
            fwd_date = reader.int32()
        break
    return fwd_user_id, fwd_name, fwd_date


def test_web_k_forwarded_message_carries_message_fwd_header(tmp_path) -> None:
    """A forward into Saved Messages keeps the clickable original author."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_SELF_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR,
        encode_int64,
        encode_uint32,
        encode_vector_ints,
        encode_vector_longs,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    auth_key = bytes(range(256))
    salt, session_id = 927, 202
    database = Database(tmp_path / "forward-fwd.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000251", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000252", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        source_peer = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        stored, _ = send_message(
            connection, peer_id=source_peer, sender_user_id=alice.user_id, body="Forward me", client_random_id="fwd-source",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=bob.user_id)
    message_id = (int(time.time()) << 32) + 4
    request = (
        encode_uint32(MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(alice.user_id)
        + encode_int64(user_access_hash(alice.user_id))
        + encode_vector_ints([int(stored["id"])])
        + encode_vector_longs([987_654_322])
        + encode_uint32(INPUT_PEER_SELF_CONSTRUCTOR)
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=request,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    fwd_user_id, fwd_name, fwd_date = _read_forward_fwd_header_from_response(body, message_id)
    assert fwd_user_id == alice.user_id
    assert fwd_name is None
    assert fwd_date == int(stored["sent_at"])
    with database.transaction() as connection:
        saved_peer = get_or_create_direct_peer(connection, user_id=bob.user_id, other_user_id=bob.user_id)
        fwd_row = connection.execute(
            "SELECT fwd_from_user_id, fwd_from_peer_id, fwd_date, fwd_hidden, fwd_from_name FROM messages WHERE peer_id = ? ORDER BY id DESC LIMIT 1",
            (saved_peer,),
        ).fetchone()
        assert fwd_row is not None
        assert int(fwd_row["fwd_from_user_id"]) == alice.user_id
        assert int(fwd_row["fwd_from_peer_id"]) == source_peer
        assert int(fwd_row["fwd_date"]) == int(stored["sent_at"])
        assert int(fwd_row["fwd_hidden"]) == 0


def test_forward_into_another_user_hides_the_private_sender(tmp_path) -> None:
    """Forwarding a direct-chat message out hides the author: from_name only."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR,
        encode_int64,
        encode_uint32,
        encode_vector_ints,
        encode_vector_longs,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    auth_key = bytes(range(256))
    salt, session_id = 928, 203
    database = Database(tmp_path / "forward-hide.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000261", password="correct-horse-battery-staple", first_name="Alice", device_label="Alice",
        )
        bob = register_password_account(
            connection, phone="+15550000262", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        carol = register_password_account(
            connection, phone="+15550000263", password="correct-horse-battery-staple", first_name="Carol", device_label="Carol",
        )
        source_peer = get_or_create_direct_peer(connection, user_id=alice.user_id, other_user_id=bob.user_id)
        destination_peer = get_or_create_direct_peer(connection, user_id=bob.user_id, other_user_id=carol.user_id)
        stored, _ = send_message(
            connection, peer_id=source_peer, sender_user_id=alice.user_id, body="Private word", client_random_id="hide-source",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=bob.user_id)
    message_id = (int(time.time()) << 32) + 4
    request = (
        encode_uint32(MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(alice.user_id)
        + encode_int64(user_access_hash(alice.user_id))
        + encode_vector_ints([int(stored["id"])])
        + encode_vector_longs([987_654_333])
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(carol.user_id)
        + encode_int64(user_access_hash(carol.user_id))
    )
    response = adapter.handle_encrypted(_encrypt_client(
        auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=1, body=request,
    ))
    assert response is not None
    _, _, _, _, body = _decrypt_server(auth_key, response)
    fwd_user_id, fwd_name, fwd_date = _read_forward_fwd_header_from_response(body, message_id)
    assert fwd_user_id is None
    assert fwd_name == "Alice"
    assert fwd_date == int(stored["sent_at"])
    with database.transaction() as connection:
        fwd_row = connection.execute(
            "SELECT fwd_from_user_id, fwd_date, fwd_hidden, fwd_from_name FROM messages WHERE peer_id = ? ORDER BY id DESC LIMIT 1",
            (destination_peer,),
        ).fetchone()
        assert fwd_row is not None
        assert int(fwd_row["fwd_from_user_id"]) == alice.user_id
        assert int(fwd_row["fwd_hidden"]) == 1
        assert str(fwd_row["fwd_from_name"]) == "Alice"


def test_author_forwards_privacy_blocks_forwarding_by_strangers(tmp_path) -> None:
    """The author's "who can forward my messages" key gates messages.forwardMessages."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_PRIVACY_RULES_CONSTRUCTOR,
        ACCOUNT_SET_PRIVACY_CONSTRUCTOR,
        INPUT_PRIVACY_VALUE_DISALLOW_ALL_CONSTRUCTOR,
        INPUT_PEER_SELF_CONSTRUCTOR,
        INPUT_PEER_USER_CONSTRUCTOR,
        MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR,
        RPC_ERROR_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_int64,
        encode_uint32,
        encode_vector,
        encode_vector_ints,
        encode_vector_longs,
        user_access_hash,
    )
    from intelligram.services.accounts import register_password_account
    from intelligram.services.messaging import get_or_create_direct_peer, send_message

    database = Database(tmp_path / "forward-privacy.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        carol = register_password_account(
            connection, phone="+15550000271", password="correct-horse-battery-staple", first_name="Carol", device_label="Carol",
        )
        bob = register_password_account(
            connection, phone="+15550000272", password="correct-horse-battery-staple", first_name="Bob", device_label="Bob",
        )
        source_peer = get_or_create_direct_peer(connection, user_id=carol.user_id, other_user_id=bob.user_id)
        stored, _ = send_message(
            connection, peer_id=source_peer, sender_user_id=carol.user_id, body="Do not spread", client_random_id="privacy-source",
        )

    def invoke(adapter: MTProtoSessionAdapter, key: bytes, index: int, query: bytes) -> bytes:
        request_message_id = (int(time.time()) << 32) + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            key, salt=911, session_id=505, msg_id=request_message_id, seq_no=index, body=query,
        ))
        assert response is not None
        return _decrypt_server(key, response)[4]

    bob_key = bytes(range(256))
    carol_key = bytes([(i * 7 + 3) % 256 for i in range(256)])
    bob_adapter = MTProtoSessionAdapter(auth_key=bob_key, server_salt=911, database=database, user_id=bob.user_id)
    carol_adapter = MTProtoSessionAdapter(auth_key=carol_key, server_salt=911, database=database, user_id=carol.user_id)

    set_privacy = (
        encode_uint32(ACCOUNT_SET_PRIVACY_CONSTRUCTOR)
        + encode_uint32(0xA4DD4C08)  # inputPrivacyKeyForwards
        + encode_vector([encode_uint32(INPUT_PRIVACY_VALUE_DISALLOW_ALL_CONSTRUCTOR)])
    )
    body = invoke(carol_adapter, carol_key, 1, set_privacy)
    reader = TLReader(body)
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    reader.int64()  # echoed request message id
    assert reader.uint32() == ACCOUNT_PRIVACY_RULES_CONSTRUCTOR

    forward = (
        encode_uint32(MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(carol.user_id)
        + encode_int64(user_access_hash(carol.user_id))
        + encode_vector_ints([int(stored["id"])])
        + encode_vector_longs([987_654_344])
        + encode_uint32(INPUT_PEER_SELF_CONSTRUCTOR)
    )
    reader = TLReader(invoke(bob_adapter, bob_key, 1, forward))
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    reader.int64()  # echoed request message id
    assert reader.uint32() == RPC_ERROR_CONSTRUCTOR
    assert reader.int32() == 400
    assert reader.bytes().decode() == "USER_PRIVACY_RESTRICTED"


def test_web_k_privacy_rules_persist_and_survive_reload(tmp_path) -> None:
    """account.setPrivacy persists; account.getPrivacy echoes the stored rules."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_GET_PRIVACY_CONSTRUCTOR,
        ACCOUNT_PRIVACY_RULES_CONSTRUCTOR,
        ACCOUNT_SET_PRIVACY_CONSTRUCTOR,
        INPUT_PRIVACY_VALUE_ALLOW_CONTACTS_CONSTRUCTOR,
        PRIVACY_VALUE_ALLOW_CONTACTS_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_uint32,
        encode_vector,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 929, 204
    database = Database(tmp_path / "privacy-set-get.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection, phone="+15550000281", password="correct-horse-battery-staple", first_name="Issued", device_label="Issued",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=issued.user_id)

    def invoke(query: bytes, index: int) -> TLReader:
        request_message_id = (int(time.time()) << 32) + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=index * 2 + 1, body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        reader.int64()  # echoed request message id
        return reader

    set_privacy = (
        encode_uint32(ACCOUNT_SET_PRIVACY_CONSTRUCTOR)
        + encode_uint32(0x4F96CB18)  # inputPrivacyKeyStatusTimestamp
        + encode_vector([encode_uint32(INPUT_PRIVACY_VALUE_ALLOW_CONTACTS_CONSTRUCTOR)])
    )
    reader = invoke(set_privacy, 1)
    assert reader.uint32() == ACCOUNT_PRIVACY_RULES_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == PRIVACY_VALUE_ALLOW_CONTACTS_CONSTRUCTOR

    reader = invoke(encode_uint32(ACCOUNT_GET_PRIVACY_CONSTRUCTOR) + encode_uint32(0x4F96CB18), 2)
    assert reader.uint32() == ACCOUNT_PRIVACY_RULES_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == PRIVACY_VALUE_ALLOW_CONTACTS_CONSTRUCTOR

    with database.transaction() as connection:
        row = connection.execute(
            "SELECT rules FROM privacy_rules WHERE user_id = ? AND key = 'status_timestamp'",
            (issued.user_id,),
        ).fetchone()
        assert row is not None and "allow_contacts" in str(row["rules"])


def test_free_account_cannot_narrow_voice_message_privacy(tmp_path) -> None:
    """Restricting voice messages is a Premium feature; free accounts are locked to default."""

    from intelligram.database import Database
    from intelligram.mtproto.tl import (
        ACCOUNT_PRIVACY_RULES_CONSTRUCTOR,
        ACCOUNT_SET_PRIVACY_CONSTRUCTOR,
        INPUT_PRIVACY_VALUE_DISALLOW_ALL_CONSTRUCTOR,
        PRIVACY_VALUE_DISALLOW_ALL_CONSTRUCTOR,
        RPC_ERROR_CONSTRUCTOR,
        RPC_RESULT_CONSTRUCTOR,
        TLReader,
        encode_uint32,
        encode_vector,
    )
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 930, 205
    database = Database(tmp_path / "privacy-premium.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        issued = register_password_account(
            connection, phone="+15550000291", password="correct-horse-battery-staple", first_name="Issued", device_label="Issued",
        )
    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=issued.user_id)

    def invoke(query: bytes, index: int) -> tuple[TLReader, int]:
        request_message_id = (int(time.time()) << 32) + index * 4
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key, salt=salt, session_id=session_id, msg_id=request_message_id, seq_no=index * 2 + 1, body=query,
        ))
        assert response is not None
        _, _, _, _, body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
        reader.int64()  # echoed request message id
        return reader, index

    voice_key = 0xAEE69D68  # inputPrivacyKeyVoiceMessages
    narrow = (
        encode_uint32(ACCOUNT_SET_PRIVACY_CONSTRUCTOR)
        + encode_uint32(voice_key)
        + encode_vector([encode_uint32(INPUT_PRIVACY_VALUE_DISALLOW_ALL_CONSTRUCTOR)])
    )
    reader, _ = invoke(narrow, 1)
    assert reader.uint32() == RPC_ERROR_CONSTRUCTOR
    assert reader.int32() == 400
    assert reader.bytes().decode() == "PREMIUM_ACCOUNT_REQUIRED"

    with database.transaction(immediate=True) as connection:
        connection.execute("UPDATE users SET premium = 1 WHERE id = ?", (issued.user_id,))
    reader, _ = invoke(narrow, 2)
    assert reader.uint32() == ACCOUNT_PRIVACY_RULES_CONSTRUCTOR
    assert reader.vector_count() == 1
    assert reader.uint32() == PRIVACY_VALUE_DISALLOW_ALL_CONSTRUCTOR
