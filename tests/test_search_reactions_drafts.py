from __future__ import annotations

import struct
import time

from intelligram.mtproto.adapter import MTProtoSessionAdapter
from intelligram.mtproto.crypto import auth_key_id, aes_ige_decrypt, aes_ige_encrypt, derive_aes_key_iv
from intelligram.mtproto.tl import (
    BOOL_TRUE_CONSTRUCTOR,
    DRAFT_MESSAGE_EMPTY_CONSTRUCTOR,
    INPUT_MESSAGES_FILTER_EMPTY_CONSTRUCTOR,
    INPUT_PEER_EMPTY_CONSTRUCTOR,
    INPUT_PEER_USER_CONSTRUCTOR,
    MESSAGES_GET_ALL_DRAFTS_CONSTRUCTOR,
    MESSAGES_GET_MESSAGE_REACTIONS_LIST_CONSTRUCTOR,
    MESSAGES_GET_MESSAGES_REACTIONS_CONSTRUCTOR,
    MESSAGES_GET_RECENT_REACTIONS_CONSTRUCTOR,
    MESSAGES_GET_SEARCH_COUNTERS_CONSTRUCTOR,
    MESSAGES_GET_SEARCH_RESULTS_CALENDAR_CONSTRUCTOR,
    MESSAGES_MESSAGE_REACTIONS_LIST_CONSTRUCTOR,
    MESSAGES_MESSAGES_SLICE_CONSTRUCTOR,
    MESSAGES_SAVE_DRAFT_CONSTRUCTOR,
    MESSAGES_SEARCH_CONSTRUCTOR,
    MESSAGES_SEARCH_GLOBAL_CONSTRUCTOR,
    MESSAGES_SEND_MESSAGE_CONSTRUCTOR,
    MESSAGES_SEND_REACTION_CONSTRUCTOR,
    RPC_RESULT_CONSTRUCTOR,
    TLReader,
    UPDATE_DRAFT_MESSAGE_CONSTRUCTOR,
    UPDATE_MESSAGE_REACTIONS_CONSTRUCTOR,
    UPDATES_CONSTRUCTOR,
    VECTOR_CONSTRUCTOR,
    encode_bool,
    encode_int64,
    encode_reaction,
    encode_tl_string,
    encode_uint32,
    encode_vector,
    user_access_hash,
)


def _encrypt_client(auth_key: bytes, *, salt: int, session_id: int, msg_id: int, seq_no: int, body: bytes) -> bytes:
    inner = struct.pack("<QQQII", salt, session_id, msg_id, seq_no, len(body)) + body
    padding_length = 12
    while (len(inner) + padding_length) % 16:
        padding_length += 1
    plaintext = inner + b"\x01" * padding_length
    msg_key = __import__("hashlib").sha256(auth_key[88:120] + plaintext).digest()[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=True)
    return struct.pack("<Q", auth_key_id(auth_key)) + msg_key + aes_ige_encrypt(key, iv, plaintext)


def _decrypt_server(auth_key: bytes, envelope: bytes) -> bytes:
    msg_key = envelope[8:24]
    key, iv = derive_aes_key_iv(auth_key, msg_key, from_client=False)
    plaintext = aes_ige_decrypt(key, iv, envelope[24:])
    assert msg_key == __import__("hashlib").sha256(auth_key[96:128] + plaintext).digest()[8:24]
    _, _, _, _, body_length = struct.unpack_from("<QQQII", plaintext, 0)
    return plaintext[32:32 + body_length]


def _input_peer_user(user_id: int) -> bytes:
    return (
        encode_uint32(INPUT_PEER_USER_CONSTRUCTOR)
        + encode_int64(user_id)
        + encode_int64(user_access_hash(user_id))
    )


def _assert_rpc_result(reader: TLReader, request_id: int) -> None:
    assert reader.uint32() == RPC_RESULT_CONSTRUCTOR
    assert reader.int64() == request_id


def test_search_reactions_and_drafts_round_trip(tmp_path) -> None:
    from intelligram.database import Database
    from intelligram.services.accounts import register_password_account

    auth_key = bytes(range(256))
    salt, session_id = 123, 456
    database = Database(tmp_path / "search-reactions-drafts.sqlite3")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        alice = register_password_account(
            connection, phone="+15550000901", password="correct-horse-battery-staple", first_name="Alice", device_label="alice"
        )
        bob = register_password_account(
            connection, phone="+15550000902", password="correct-horse-battery-staple", first_name="Bob", device_label="bob"
        )

    adapter = MTProtoSessionAdapter(auth_key=auth_key, server_salt=salt, database=database, user_id=alice.user_id)
    message_id = (int(time.time()) << 32) + 4
    sequence_no = 1

    def invoke(query: bytes) -> TLReader:
        nonlocal message_id, sequence_no
        response = adapter.handle_encrypted(_encrypt_client(
            auth_key, salt=salt, session_id=session_id, msg_id=message_id, seq_no=sequence_no, body=query
        ))
        assert response is not None
        body = _decrypt_server(auth_key, response)
        reader = TLReader(body)
        _assert_rpc_result(reader, message_id)
        message_id += 4
        sequence_no += 2
        return reader

    # Send two messages to Bob.
    for index, text in enumerate(["find the needle", "another needle in haystack"]):
        invoke(
            encode_uint32(MESSAGES_SEND_MESSAGE_CONSTRUCTOR)
            + encode_uint32(0)
            + _input_peer_user(bob.user_id)
            + encode_tl_string(text)
            + encode_int64(1000 + index)
        )

    # Resolve the real message id of the first sent message.
    with database.transaction() as connection:
        first_msg_id = int(connection.execute(
            "SELECT id FROM messages WHERE body = ? ORDER BY id ASC LIMIT 1", ("find the needle",)
        ).fetchone()["id"])

    # messages.search should return both messages.
    search_reader = invoke(
        encode_uint32(MESSAGES_SEARCH_CONSTRUCTOR)
        + encode_uint32(0)  # flags
        + _input_peer_user(bob.user_id)
        + encode_tl_string("needle")
        + encode_uint32(INPUT_MESSAGES_FILTER_EMPTY_CONSTRUCTOR)
        + struct.pack("<ii", 0, 0)  # min_date, max_date
        + struct.pack("<iiii", 0, 0, 20, 0)  # offset_id, add_offset, limit, max_id
        + struct.pack("<i", 0)  # min_id
        + encode_int64(0)  # hash
    )
    assert search_reader.uint32() == MESSAGES_MESSAGES_SLICE_CONSTRUCTOR
    search_reader.uint32()  # flags
    count = search_reader.int32()
    assert count == 2
    assert search_reader.uint32() == VECTOR_CONSTRUCTOR
    assert search_reader.int32() == count

    # messages.searchGlobal should find the same bodies across peers.
    global_reader = invoke(
        encode_uint32(MESSAGES_SEARCH_GLOBAL_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_tl_string("needle")
        + encode_uint32(INPUT_MESSAGES_FILTER_EMPTY_CONSTRUCTOR)
        + struct.pack("<ii", 0, 0)
        + struct.pack("<i", 0)  # offset_rate
        + encode_uint32(INPUT_PEER_EMPTY_CONSTRUCTOR)
        + struct.pack("<ii", 0, 20)  # offset_id, limit
    )
    assert global_reader.uint32() == MESSAGES_MESSAGES_SLICE_CONSTRUCTOR

    # messages.getSearchCounters returns a vector of messages.searchCounter.
    counters_reader = invoke(
        encode_uint32(MESSAGES_GET_SEARCH_COUNTERS_CONSTRUCTOR)
        + encode_uint32(0)
        + _input_peer_user(bob.user_id)
        + encode_vector([encode_uint32(INPUT_MESSAGES_FILTER_EMPTY_CONSTRUCTOR)])
    )
    assert counters_reader.uint32() == VECTOR_CONSTRUCTOR
    assert counters_reader.int32() >= 1

    # messages.getSearchResultsCalendar returns an empty calendar.
    calendar_reader = invoke(
        encode_uint32(MESSAGES_GET_SEARCH_RESULTS_CALENDAR_CONSTRUCTOR)
        + encode_uint32(0)
        + _input_peer_user(bob.user_id)
        + encode_uint32(INPUT_MESSAGES_FILTER_EMPTY_CONSTRUCTOR)
        + struct.pack("<ii", 0, 0)  # offset_id, offset_date
    )
    assert calendar_reader.uint32() == 0x147EE23C

    # messages.sendReaction reacts to the first message.
    reaction = encode_reaction({"kind": "emoji", "emoticon": "👍"})
    reaction_reader = invoke(
        encode_uint32(MESSAGES_SEND_REACTION_CONSTRUCTOR)
        + encode_uint32((1 << 0) | (1 << 1))  # reaction present + big
        + encode_bool(True)  # big
        + _input_peer_user(bob.user_id)
        + struct.pack("<i", first_msg_id)  # msg_id (first sent message id)
        + encode_vector([reaction])
    )
    assert reaction_reader.uint32() == UPDATES_CONSTRUCTOR
    assert reaction_reader.uint32() == VECTOR_CONSTRUCTOR
    assert reaction_reader.int32() == 1
    assert reaction_reader.uint32() == UPDATE_MESSAGE_REACTIONS_CONSTRUCTOR

    # messages.getMessageReactionsList lists the single reactor.
    list_reader = invoke(
        encode_uint32(MESSAGES_GET_MESSAGE_REACTIONS_LIST_CONSTRUCTOR)
        + encode_uint32(0)
        + _input_peer_user(bob.user_id)
        + struct.pack("<i", first_msg_id)  # id
        + struct.pack("<i", 50)  # limit
    )
    assert list_reader.uint32() == MESSAGES_MESSAGE_REACTIONS_LIST_CONSTRUCTOR
    list_reader.uint32()  # flags
    list_count = list_reader.int32()
    assert list_count == 1
    assert list_reader.uint32() == VECTOR_CONSTRUCTOR
    assert list_reader.int32() == list_count

    # messages.getRecentReactions returns messages.Reactions.
    recent_reader = invoke(
        encode_uint32(MESSAGES_GET_RECENT_REACTIONS_CONSTRUCTOR)
        + struct.pack("<i", 0)  # limit
        + encode_int64(0)  # hash
    )
    assert recent_reader.uint32() == 0xEAFDF716

    # messages.getMessagesReactions returns Updates with the reaction update.
    get_reader = invoke(
        encode_uint32(MESSAGES_GET_MESSAGES_REACTIONS_CONSTRUCTOR)
        + _input_peer_user(bob.user_id)
        + encode_vector([struct.pack("<i", first_msg_id)])
    )
    assert get_reader.uint32() == UPDATES_CONSTRUCTOR

    # messages.saveDraft then messages.getAllDrafts round-trips the draft.
    draft_reader = invoke(
        encode_uint32(MESSAGES_SAVE_DRAFT_CONSTRUCTOR)
        + encode_uint32(0)
        + _input_peer_user(bob.user_id)
        + encode_tl_string("draft hello")
    )
    assert draft_reader.uint32() == BOOL_TRUE_CONSTRUCTOR

    drafts_reader = invoke(encode_uint32(MESSAGES_GET_ALL_DRAFTS_CONSTRUCTOR))
    assert drafts_reader.uint32() == UPDATES_CONSTRUCTOR
    # updates: Vector<Update>
    assert drafts_reader.uint32() == VECTOR_CONSTRUCTOR
    n_updates = drafts_reader.int32()
    assert n_updates >= 1
    first_update = drafts_reader.uint32()
    assert first_update == UPDATE_DRAFT_MESSAGE_CONSTRUCTOR
