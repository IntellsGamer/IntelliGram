"""Minimal Telegram TL codec used by the IntelliGram MTProto adapter.

The codec starts with the MTProto service constructors required to establish a
transport and prove encrypted request/response behavior. Application-layer API
constructors are added as their handlers become compatible.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any, Iterable


VECTOR_CONSTRUCTOR = 0x1CB5C415
RPC_RESULT_CONSTRUCTOR = 0xF35C6D01
RPC_ERROR_CONSTRUCTOR = 0x2144CA19
PONG_CONSTRUCTOR = 0x347773C5
PING_CONSTRUCTOR = 0x7ABE77EC
MSGS_ACK_CONSTRUCTOR = 0x62D6B459
NEW_SESSION_CREATED_CONSTRUCTOR = 0x9EC20908
BAD_SERVER_SALT_CONSTRUCTOR = 0xEDAB447B
BOOL_TRUE_CONSTRUCTOR = 0x997275B5
BOOL_FALSE_CONSTRUCTOR = 0xBC799737
INVOKE_WITH_LAYER_CONSTRUCTOR = 0xDA9B0D0D
INIT_CONNECTION_CONSTRUCTOR = 0xC1CD5EA9
HELP_GET_CONFIG_CONSTRUCTOR = 0xC4F9186B
CONFIG_CONSTRUCTOR = 0xCC1A241E
DC_OPTION_CONSTRUCTOR = 0x18B7A10D
AUTH_EXPORT_LOGIN_TOKEN_CONSTRUCTOR = 0xB7E085FE
AUTH_IMPORT_LOGIN_TOKEN_CONSTRUCTOR = 0x95AC5CE4
AUTH_LOGIN_TOKEN_CONSTRUCTOR = 0x629F1980
UPDATES_GET_STATE_CONSTRUCTOR = 0xEDD4882A
UPDATES_STATE_CONSTRUCTOR = 0xA56C2A3E
AUTH_SEND_CODE_CONSTRUCTOR = 0xA677244F
AUTH_SIGN_IN_CONSTRUCTOR = 0x8D52A951
AUTH_SIGN_UP_CONSTRUCTOR = 0xAAC7B717
AUTH_SENT_CODE_CONSTRUCTOR = 0x5E002502
AUTH_SENT_CODE_SUCCESS_CONSTRUCTOR = 0x2390FE44
AUTH_SENT_CODE_TYPE_APP_CONSTRUCTOR = 0x3DBB5986
AUTH_AUTHORIZATION_SIGN_UP_REQUIRED_CONSTRUCTOR = 0x44747E9A
AUTH_AUTHORIZATION_CONSTRUCTOR = 0x2EA2C0D4
USER_EMPTY_CONSTRUCTOR = 0xD3BC4B7A
USER_CONSTRUCTOR = 0xB1B8CC83
USER_STATUS_EMPTY_CONSTRUCTOR = 0x09D05049
PEER_USER_CONSTRUCTOR = 0x59511722
PEER_CHAT_CONSTRUCTOR = 0x36C6019A
INPUT_PEER_EMPTY_CONSTRUCTOR = 0x7F3B18EA
INPUT_PEER_SELF_CONSTRUCTOR = 0x7DA07EC9
INPUT_PEER_USER_CONSTRUCTOR = 0xDDE8A54C
INPUT_PEER_CHAT_CONSTRUCTOR = 0x35A95CB9
INPUT_USER_SELF_CONSTRUCTOR = 0xF7C1B13F
INPUT_USER_CONSTRUCTOR = 0xF210AAE0
INPUT_DIALOG_PEER_CONSTRUCTOR = 0xFCAAFEB7
MESSAGE_CONSTRUCTOR = 0x75F3F635
DIALOG_CONSTRUCTOR = 0xFC89F7F3
PEER_NOTIFY_SETTINGS_CONSTRUCTOR = 0x99622C0C
PEER_SETTINGS_CONSTRUCTOR = 0xF47741F7
CONTACT_CONSTRUCTOR = 0x145ADE0B
CONTACTS_CONTACTS_CONSTRUCTOR = 0xEAE87E42
MESSAGES_DIALOGS_CONSTRUCTOR = 0x15BA6C40
MESSAGES_MESSAGES_CONSTRUCTOR = 0x1D73E7EA
MESSAGES_PEER_DIALOGS_CONSTRUCTOR = 0x3371C354
USER_FULL_CONSTRUCTOR = 0x06CBC1E5
USERS_USER_FULL_CONSTRUCTOR = 0x3B6D152E
UPDATE_NEW_MESSAGE_CONSTRUCTOR = 0x1F2B0AFD
UPDATE_MESSAGE_ID_CONSTRUCTOR = 0x4E90BFD6
UPDATES_CONSTRUCTOR = 0x74AE4240
USERS_GET_USERS_CONSTRUCTOR = 0x0D91A548
USERS_GET_FULL_USER_CONSTRUCTOR = 0xB60F5918
CONTACTS_GET_CONTACTS_CONSTRUCTOR = 0x5DD69E12
MESSAGES_GET_DIALOGS_CONSTRUCTOR = 0xA0F4CB4F
MESSAGES_GET_HISTORY_CONSTRUCTOR = 0x4423E6C5
MESSAGES_SEND_MESSAGE_CONSTRUCTOR = 0xFEF48F62
MESSAGES_GET_PEER_DIALOGS_CONSTRUCTOR = 0xE470BCFD
ACCOUNT_UPDATE_STATUS_CONSTRUCTOR = 0x6628562C
ACCOUNT_GET_PRIVACY_CONSTRUCTOR = 0xDADBC950
PRIVACY_VALUE_ALLOW_ALL_CONSTRUCTOR = 0x65427B82
ACCOUNT_PRIVACY_RULES_CONSTRUCTOR = 0x50A04E45
CHAT_CONSTRUCTOR = 0x41CBF256
CHAT_PHOTO_EMPTY_CONSTRUCTOR = 0x37C1011C
MESSAGES_INVITED_USERS_CONSTRUCTOR = 0x7F5DEFA6
MESSAGES_CREATE_CHAT_CONSTRUCTOR = 0x92CEDDD4
ACCOUNT_UPDATE_PROFILE_CONSTRUCTOR = 0x78515775
INPUT_FILE_CONSTRUCTOR = 0xF52FF27F
INPUT_FILE_BIG_CONSTRUCTOR = 0xFA4F0BB5
UPLOAD_SAVE_FILE_PART_CONSTRUCTOR = 0xB304A621
UPLOAD_SAVE_BIG_FILE_PART_CONSTRUCTOR = 0xDE7B673D
PHOTOS_UPLOAD_PROFILE_PHOTO_CONSTRUCTOR = 0x0388A3B5
PHOTO_CONSTRUCTOR = 0xFB197A65
PHOTO_SIZE_CONSTRUCTOR = 0x75C78E60
PHOTOS_PHOTO_CONSTRUCTOR = 0x20212CA8
UPLOAD_GET_FILE_CONSTRUCTOR = 0xBE5335BE
INPUT_PHOTO_FILE_LOCATION_CONSTRUCTOR = 0x40181FFE
STORAGE_FILE_UNKNOWN_CONSTRUCTOR = 0xAA963B05
UPLOAD_FILE_CONSTRUCTOR = 0x096A18D5
UPDATES_GET_DIFFERENCE_CONSTRUCTOR = 0x19C2F763
UPDATES_DIFFERENCE_EMPTY_CONSTRUCTOR = 0x5D75A138
UPDATES_DIFFERENCE_CONSTRUCTOR = 0x00F49CA0
MESSAGES_GET_FULL_CHAT_CONSTRUCTOR = 0xAEB00B34
CHAT_FULL_CONSTRUCTOR = 0x2633421B
CHAT_PARTICIPANT_CONSTRUCTOR = 0x38E79FDE
CHAT_PARTICIPANTS_CONSTRUCTOR = 0x3CBC93F8
MESSAGES_CHAT_FULL_CONSTRUCTOR = 0xE5D7D19C
AUTH_LOG_OUT_CONSTRUCTOR = 0x3E72BA19
AUTH_LOGGED_OUT_CONSTRUCTOR = 0xC3A2835F
MESSAGES_READ_HISTORY_CONSTRUCTOR = 0x0E306D3A
MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR = 0x84D19185
MESSAGES_SET_TYPING_CONSTRUCTOR = 0x58943EE2
MESSAGES_GET_PEER_SETTINGS_CONSTRUCTOR = 0xEFD9A6A2
MESSAGES_PEER_SETTINGS_CONSTRUCTOR = 0x6880B94D
LANGPACK_GET_LANG_PACK_CONSTRUCTOR = 0xF2F2330A
LANG_PACK_DIFFERENCE_CONSTRUCTOR = 0xF385C1F6
HELP_GET_COUNTRIES_LIST_CONSTRUCTOR = 0x735787A8
HELP_COUNTRIES_LIST_CONSTRUCTOR = 0x93CC1F32
CONTACTS_RESOLVE_USERNAME_CONSTRUCTOR = 0x725AFBBC
CONTACTS_RESOLVED_PEER_CONSTRUCTOR = 0x7F077AD9
UPDATE_READ_HISTORY_INBOX_CONSTRUCTOR = 0x9E84BC99
UPDATE_CHAT_PARTICIPANTS_CONSTRUCTOR = 0x07761198
MESSAGES_EDIT_CHAT_TITLE_CONSTRUCTOR = 0x73783FFD
MESSAGES_ADD_CHAT_USER_CONSTRUCTOR = 0xCBC6D107
MESSAGES_DELETE_CHAT_USER_CONSTRUCTOR = 0xA2185CAB
MESSAGES_EDIT_CHAT_ABOUT_CONSTRUCTOR = 0xDEF60797


class TLDecodeError(ValueError):
    """A TL payload is malformed or unsupported by the active adapter."""


@dataclass(frozen=True, slots=True)
class TLRequest:
    constructor_id: int
    name: str
    fields: dict[str, Any]


class TLReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def int32(self) -> int:
        self._require(4)
        value = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        return value

    def uint32(self) -> int:
        self._require(4)
        value = struct.unpack_from("<I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def int64(self) -> int:
        self._require(8)
        value = struct.unpack_from("<q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def raw_bytes(self, length: int) -> bytes:
        self._require(length)
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def bytes(self) -> bytes:
        self._require(1)
        first = self.data[self.offset]
        self.offset += 1
        if first == 254:
            self._require(3)
            length = int.from_bytes(self.data[self.offset:self.offset + 3], "little")
            self.offset += 3
            header_size = 4
        elif first < 254:
            length = first
            header_size = 1
        else:
            raise TLDecodeError("TL bytes length marker is invalid")
        self._require(length)
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        padding = (-((header_size + length) % 4)) % 4
        self._require(padding)
        self.offset += padding
        return value

    def vector_longs(self) -> list[int]:
        return [self.int64() for _ in range(self.vector_count())]

    def vector_count(self) -> int:
        if self.uint32() != VECTOR_CONSTRUCTOR:
            raise TLDecodeError("Expected a Vector constructor")
        count = self.int32()
        if count < 0 or count > 8192:
            raise TLDecodeError("Vector length is invalid")
        return count

    def _require(self, length: int) -> None:
        if length < 0 or self.remaining < length:
            raise TLDecodeError("Truncated TL payload")


def encode_int32(value: int) -> bytes:
    return struct.pack("<i", value)


def encode_uint32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def encode_int64(value: int) -> bytes:
    return struct.pack("<q", value)


def encode_tl_bytes(value: bytes) -> bytes:
    length = len(value)
    if length < 254:
        encoded = bytes([length]) + value
    elif length < 1 << 24:
        encoded = b"\xfe" + length.to_bytes(3, "little") + value
    else:
        raise ValueError("TL byte string is larger than 16 MiB")
    return encoded + b"\x00" * (-len(encoded) % 4)


def encode_tl_string(value: str) -> bytes:
    return encode_tl_bytes(value.encode("utf-8"))


def encode_vector_longs(values: Iterable[int]) -> bytes:
    sequence = list(values)
    return encode_uint32(VECTOR_CONSTRUCTOR) + encode_int32(len(sequence)) + b"".join(encode_int64(value) for value in sequence)


def unwrap_client_query(data: bytes) -> bytes:
    """Strip Telegram Web A's standard invokeWithLayer/initConnection wrappers."""
    reader = TLReader(data)
    constructor_id = reader.uint32()
    if constructor_id == INVOKE_WITH_LAYER_CONSTRUCTOR:
        reader.int32()  # layer
        return unwrap_client_query(reader.raw_bytes(reader.remaining))
    if constructor_id == INIT_CONNECTION_CONSTRUCTOR:
        flags = reader.uint32()
        reader.int32()  # api_id
        for _ in range(6):
            reader.bytes()  # device/app/language metadata
        if flags:
            # The imported client currently supplies no proxy or JSON params.
            # Refuse unknown optional wrapper values rather than desynchronizing.
            raise TLDecodeError("Unsupported initConnection optional fields")
        return unwrap_client_query(reader.raw_bytes(reader.remaining))
    return data


def _read_input_peer(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_PEER_EMPTY_CONSTRUCTOR:
        return {"kind": "empty"}
    if constructor_id == INPUT_PEER_SELF_CONSTRUCTOR:
        return {"kind": "self"}
    if constructor_id == INPUT_PEER_USER_CONSTRUCTOR:
        return {
            "kind": "user",
            "user_id": reader.int64(),
            "access_hash": reader.int64(),
        }
    if constructor_id == INPUT_PEER_CHAT_CONSTRUCTOR:
        return {"kind": "chat", "chat_id": reader.int64()}
    raise TLDecodeError(f"Unsupported InputPeer constructor: 0x{constructor_id:08x}")


def _read_input_user(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_USER_SELF_CONSTRUCTOR:
        return {"kind": "self"}
    if constructor_id == INPUT_USER_CONSTRUCTOR:
        return {
            "kind": "user",
            "user_id": reader.int64(),
            "access_hash": reader.int64(),
        }
    raise TLDecodeError(f"Unsupported InputUser constructor: 0x{constructor_id:08x}")


def _read_input_file(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_FILE_CONSTRUCTOR:
        return {
            "kind": "regular",
            "file_id": reader.int64(),
            "parts": reader.int32(),
            "name": reader.bytes().decode("utf-8"),
            "md5_checksum": reader.bytes().decode("utf-8"),
        }
    if constructor_id == INPUT_FILE_BIG_CONSTRUCTOR:
        return {
            "kind": "big",
            "file_id": reader.int64(),
            "parts": reader.int32(),
            "name": reader.bytes().decode("utf-8"),
        }
    raise TLDecodeError(f"Unsupported InputFile constructor: 0x{constructor_id:08x}")


def _read_input_file_location(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_PHOTO_FILE_LOCATION_CONSTRUCTOR:
        return {
            "kind": "photo",
            "photo_id": reader.int64(),
            "access_hash": reader.int64(),
            "file_reference": reader.bytes(),
            "thumb_size": reader.bytes().decode("utf-8"),
        }
    raise TLDecodeError(f"Unsupported InputFileLocation constructor: 0x{constructor_id:08x}")


def _read_bool(reader: TLReader) -> bool:
    constructor_id = reader.uint32()
    if constructor_id == BOOL_TRUE_CONSTRUCTOR:
        return True
    if constructor_id == BOOL_FALSE_CONSTRUCTOR:
        return False
    raise TLDecodeError("Expected a Bool constructor")


def parse_request(data: bytes) -> TLRequest:
    reader = TLReader(data)
    constructor_id = reader.uint32()
    if constructor_id == PING_CONSTRUCTOR:
        request = TLRequest(constructor_id, "ping", {"ping_id": reader.int64()})
    elif constructor_id == MSGS_ACK_CONSTRUCTOR:
        request = TLRequest(constructor_id, "msgs_ack", {"msg_ids": reader.vector_longs()})
    elif constructor_id == HELP_GET_CONFIG_CONSTRUCTOR:
        request = TLRequest(constructor_id, "help_get_config", {})
    elif constructor_id == LANGPACK_GET_LANG_PACK_CONSTRUCTOR:
        request = TLRequest(constructor_id, "langpack_get_lang_pack", {
            "lang_pack": reader.bytes().decode("utf-8"),
            "lang_code": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == HELP_GET_COUNTRIES_LIST_CONSTRUCTOR:
        request = TLRequest(constructor_id, "help_get_countries_list", {
            "lang_code": reader.bytes().decode("utf-8"),
            "hash": reader.int32(),
        })
    elif constructor_id == AUTH_EXPORT_LOGIN_TOKEN_CONSTRUCTOR:
        request = TLRequest(constructor_id, "auth_export_login_token", {
            "api_id": reader.int32(),
            "api_hash": reader.bytes().decode("utf-8"),
            "except_ids": reader.vector_longs(),
        })
    elif constructor_id == AUTH_IMPORT_LOGIN_TOKEN_CONSTRUCTOR:
        request = TLRequest(constructor_id, "auth_import_login_token", {"token": reader.bytes()})
    elif constructor_id == UPDATES_GET_STATE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "updates_get_state", {})
    elif constructor_id == AUTH_SEND_CODE_CONSTRUCTOR:
        phone_number = reader.bytes().decode("utf-8")
        api_id = reader.int32()
        api_hash = reader.bytes().decode("utf-8")
        reader.uint32()  # codeSettings constructor
        settings_flags = reader.uint32()
        if settings_flags:
            raise TLDecodeError("Unsupported codeSettings optional fields")
        request = TLRequest(constructor_id, "auth_send_code", {
            "phone_number": phone_number,
            "api_id": api_id,
            "api_hash": api_hash,
        })
    elif constructor_id == AUTH_SIGN_IN_CONSTRUCTOR:
        flags = reader.uint32()
        phone_number = reader.bytes().decode("utf-8")
        phone_code_hash = reader.bytes().decode("utf-8")
        phone_code = reader.bytes().decode("utf-8") if flags & 1 else ""
        if flags & ~1:
            raise TLDecodeError("Unsupported auth.signIn optional fields")
        request = TLRequest(constructor_id, "auth_sign_in", {
            "phone_number": phone_number,
            "phone_code_hash": phone_code_hash,
            "phone_code": phone_code,
        })
    elif constructor_id == AUTH_SIGN_UP_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~1:
            raise TLDecodeError("Unsupported auth.signUp optional fields")
        request = TLRequest(constructor_id, "auth_sign_up", {
            "phone_number": reader.bytes().decode("utf-8"),
            "phone_code_hash": reader.bytes().decode("utf-8"),
            "first_name": reader.bytes().decode("utf-8"),
            "last_name": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == USERS_GET_USERS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "users_get_users", {
            "users": [_read_input_user(reader) for _ in range(reader.vector_count())],
        })
    elif constructor_id == USERS_GET_FULL_USER_CONSTRUCTOR:
        request = TLRequest(constructor_id, "users_get_full_user", {"user": _read_input_user(reader)})
    elif constructor_id == CONTACTS_GET_CONTACTS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "contacts_get_contacts", {"hash": reader.int64()})
    elif constructor_id == CONTACTS_RESOLVE_USERNAME_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~1:
            raise TLDecodeError("Unsupported contacts.resolveUsername optional fields")
        request = TLRequest(constructor_id, "contacts_resolve_username", {
            "username": reader.bytes().decode("utf-8"),
            "referer": reader.bytes().decode("utf-8") if flags & 1 else None,
        })
    elif constructor_id == MESSAGES_GET_DIALOGS_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b11:
            raise TLDecodeError("Unsupported messages.getDialogs optional fields")
        request = TLRequest(constructor_id, "messages_get_dialogs", {
            "exclude_pinned": bool(flags & 1),
            "folder_id": reader.int32() if flags & 2 else None,
            "offset_date": reader.int32(),
            "offset_id": reader.int32(),
            "offset_peer": _read_input_peer(reader),
            "limit": reader.int32(),
            "hash": reader.int64(),
        })
    elif constructor_id == MESSAGES_GET_HISTORY_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_history", {
            "peer": _read_input_peer(reader),
            "offset_id": reader.int32(),
            "offset_date": reader.int32(),
            "add_offset": reader.int32(),
            "limit": reader.int32(),
            "max_id": reader.int32(),
            "min_id": reader.int32(),
            "hash": reader.int64(),
        })
    elif constructor_id == MESSAGES_SEND_MESSAGE_CONSTRUCTOR:
        flags = reader.uint32()
        supported_boolean_flags = (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 14) | (1 << 15) | (1 << 16) | (1 << 19)
        if flags & ~supported_boolean_flags:
            raise TLDecodeError("Unsupported messages.sendMessage optional fields")
        request = TLRequest(constructor_id, "messages_send_message", {
            "peer": _read_input_peer(reader),
            "message": reader.bytes().decode("utf-8"),
            "random_id": reader.int64(),
            "silent": bool(flags & (1 << 5)),
        })
    elif constructor_id == MESSAGES_CREATE_CHAT_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~1:
            raise TLDecodeError("Unsupported messages.createChat optional fields")
        request = TLRequest(constructor_id, "messages_create_chat", {
            "users": [_read_input_user(reader) for _ in range(reader.vector_count())],
            "title": reader.bytes().decode("utf-8"),
            "ttl_period": reader.int32() if flags & 1 else None,
        })
    elif constructor_id == MESSAGES_GET_PEER_DIALOGS_CONSTRUCTOR:
        peers: list[dict[str, Any]] = []
        for _ in range(reader.vector_count()):
            if reader.uint32() != INPUT_DIALOG_PEER_CONSTRUCTOR:
                raise TLDecodeError("Expected an inputDialogPeer constructor")
            peers.append(_read_input_peer(reader))
        request = TLRequest(constructor_id, "messages_get_peer_dialogs", {"peers": peers})
    elif constructor_id == MESSAGES_GET_FULL_CHAT_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_full_chat", {"chat_id": reader.int64()})
    elif constructor_id == MESSAGES_EDIT_CHAT_TITLE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_edit_chat_title", {
            "chat_id": reader.int64(),
            "title": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == MESSAGES_ADD_CHAT_USER_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_add_chat_user", {
            "chat_id": reader.int64(),
            "user": _read_input_user(reader),
            "fwd_limit": reader.int32(),
        })
    elif constructor_id == MESSAGES_DELETE_CHAT_USER_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~1:
            raise TLDecodeError("Unsupported messages.deleteChatUser optional fields")
        request = TLRequest(constructor_id, "messages_delete_chat_user", {
            "chat_id": reader.int64(),
            "user": _read_input_user(reader),
            "revoke_history": bool(flags & 1),
        })
    elif constructor_id == MESSAGES_EDIT_CHAT_ABOUT_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_edit_chat_about", {
            "peer": _read_input_peer(reader),
            "about": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == MESSAGES_READ_HISTORY_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_read_history", {
            "peer": _read_input_peer(reader),
            "max_id": reader.int32(),
        })
    elif constructor_id == MESSAGES_SET_TYPING_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~1:
            raise TLDecodeError("Unsupported messages.setTyping optional fields")
        peer = _read_input_peer(reader)
        top_msg_id = reader.int32() if flags & 1 else None
        # SendMessageAction is the final request field. Preserve its encoded form
        # so every official typing action is safely accepted without losing TL alignment.
        action = reader.raw_bytes(reader.remaining)
        if not action:
            raise TLDecodeError("Missing SendMessageAction")
        request = TLRequest(constructor_id, "messages_set_typing", {
            "peer": peer,
            "top_msg_id": top_msg_id,
            "action": action,
        })
    elif constructor_id == MESSAGES_GET_PEER_SETTINGS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_peer_settings", {"peer": _read_input_peer(reader)})
    elif constructor_id == AUTH_LOG_OUT_CONSTRUCTOR:
        request = TLRequest(constructor_id, "auth_log_out", {})
    elif constructor_id == UPDATES_GET_DIFFERENCE_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b111:
            raise TLDecodeError("Unsupported updates.getDifference optional fields")
        pts = reader.int32()
        if flags & (1 << 1):
            reader.int32()  # pts_limit
        if flags & 1:
            reader.int32()  # pts_total_limit
        request = TLRequest(constructor_id, "updates_get_difference", {
            "pts": pts,
            "date": reader.int32(),
            "qts": reader.int32(),
        })
        if flags & (1 << 2):
            reader.int32()  # qts_limit
    elif constructor_id == UPLOAD_GET_FILE_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b11:
            raise TLDecodeError("Unsupported upload.getFile optional fields")
        request = TLRequest(constructor_id, "upload_get_file", {
            "location": _read_input_file_location(reader),
            "offset": reader.int64(),
            "limit": reader.int32(),
        })
    elif constructor_id == UPLOAD_SAVE_FILE_PART_CONSTRUCTOR:
        request = TLRequest(constructor_id, "upload_save_file_part", {
            "file_id": reader.int64(),
            "file_part": reader.int32(),
            "bytes": reader.bytes(),
        })
    elif constructor_id == UPLOAD_SAVE_BIG_FILE_PART_CONSTRUCTOR:
        request = TLRequest(constructor_id, "upload_save_big_file_part", {
            "file_id": reader.int64(),
            "file_part": reader.int32(),
            "file_total_parts": reader.int32(),
            "bytes": reader.bytes(),
        })
    elif constructor_id == PHOTOS_UPLOAD_PROFILE_PHOTO_CONSTRUCTOR:
        flags = reader.uint32()
        # The initial self-hosted avatar flow accepts an image file and optional
        # fallback flag; video, bot-target, and video-emoji uploads follow later.
        if flags & ~((1 << 0) | (1 << 3)):
            raise TLDecodeError("Unsupported photos.uploadProfilePhoto optional fields")
        request = TLRequest(constructor_id, "photos_upload_profile_photo", {
            "file": _read_input_file(reader) if flags & 1 else None,
            "fallback": bool(flags & (1 << 3)),
        })
    elif constructor_id == ACCOUNT_UPDATE_PROFILE_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b111:
            raise TLDecodeError("Unsupported account.updateProfile optional fields")
        request = TLRequest(constructor_id, "account_update_profile", {
            "first_name": reader.bytes().decode("utf-8") if flags & 1 else None,
            "last_name": reader.bytes().decode("utf-8") if flags & 2 else None,
            "about": reader.bytes().decode("utf-8") if flags & 4 else None,
        })
    elif constructor_id == ACCOUNT_UPDATE_STATUS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "account_update_status", {"offline": _read_bool(reader)})
    elif constructor_id == ACCOUNT_GET_PRIVACY_CONSTRUCTOR:
        reader.uint32()  # InputPrivacyKey constructor; all current variants have no fields.
        request = TLRequest(constructor_id, "account_get_privacy", {})
    else:
        raise TLDecodeError(f"Unsupported TL constructor: 0x{constructor_id:08x}")
    if reader.remaining:
        raise TLDecodeError("Trailing data after TL request")
    return request


def encode_pong(*, message_id: int, ping_id: int) -> bytes:
    return encode_uint32(PONG_CONSTRUCTOR) + encode_int64(message_id) + encode_int64(ping_id)


def encode_bool(value: bool) -> bytes:
    return encode_uint32(BOOL_TRUE_CONSTRUCTOR if value else BOOL_FALSE_CONSTRUCTOR)


def encode_contacts_resolved_peer(*, peer: bytes, chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return encode_uint32(CONTACTS_RESOLVED_PEER_CONSTRUCTOR) + peer + encode_vector(chats) + encode_vector(users)


def encode_lang_pack_difference(*, lang_code: str, from_version: int = 0, version: int = 0) -> bytes:
    return (
        encode_uint32(LANG_PACK_DIFFERENCE_CONSTRUCTOR)
        + encode_tl_string(lang_code)
        + encode_int32(from_version)
        + encode_int32(version)
        + encode_vector([])
    )


def encode_help_countries_list(*, countries: Iterable[bytes] = (), hash_value: int = 0) -> bytes:
    return encode_uint32(HELP_COUNTRIES_LIST_CONSTRUCTOR) + encode_vector(countries) + encode_int32(hash_value)


def encode_messages_affected_messages(*, pts: int, pts_count: int) -> bytes:
    return encode_uint32(MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR) + encode_int32(pts) + encode_int32(pts_count)


def encode_auth_logged_out() -> bytes:
    return encode_uint32(AUTH_LOGGED_OUT_CONSTRUCTOR) + encode_uint32(0)


def encode_messages_peer_settings(*, settings: bytes, chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return encode_uint32(MESSAGES_PEER_SETTINGS_CONSTRUCTOR) + settings + encode_vector(chats) + encode_vector(users)


def encode_vector(values: Iterable[bytes]) -> bytes:
    sequence = list(values)
    return encode_uint32(VECTOR_CONSTRUCTOR) + encode_int32(len(sequence)) + b"".join(sequence)


def encode_dc_option(*, dc_id: int, host: str, port: int) -> bytes:
    return (
        encode_uint32(DC_OPTION_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(dc_id)
        + encode_tl_string(host)
        + encode_int32(port)
    )


def encode_config(*, dc_id: int, host: str, port: int, date: int, expires: int) -> bytes:
    # `config` has many mandatory scalar fields. These conservative self-hosted
    # limits deliberately disable Telegram-specific optional capabilities.
    scalar_limits = [
        200, 200_000, 100, 30_000, 5_000, 30_000, 60_000, 1_000, 1_000,
        60_000, 100, 172_800, 172_800, 172_800, 2_416_000, 20, 86_400,
    ]
    call_timeouts = [15_000, 15_000, 20_000, 15_000]
    return (
        encode_uint32(CONFIG_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int32(date)
        + encode_int32(expires)
        + encode_bool(False)
        + encode_int32(dc_id)
        + encode_vector([encode_dc_option(dc_id=dc_id, host=host, port=port)])
        + encode_tl_string("")
        + b"".join(encode_int32(value) for value in scalar_limits)
        + b"".join(encode_int32(value) for value in call_timeouts)
        + encode_tl_string("")
        + encode_int32(1_024)
        + encode_int32(4_096)
        + encode_int32(dc_id)
    )


def encode_auth_login_token(*, expires: int, token: bytes) -> bytes:
    return encode_uint32(AUTH_LOGIN_TOKEN_CONSTRUCTOR) + encode_int32(expires) + encode_tl_bytes(token)


def encode_auth_sent_code(*, phone_code_hash: str, length: int = 6) -> bytes:
    return (
        encode_uint32(AUTH_SENT_CODE_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_uint32(AUTH_SENT_CODE_TYPE_APP_CONSTRUCTOR)
        + encode_int32(length)
        + encode_tl_string(phone_code_hash)
    )


def encode_auth_authorization_sign_up_required() -> bytes:
    return encode_uint32(AUTH_AUTHORIZATION_SIGN_UP_REQUIRED_CONSTRUCTOR) + encode_uint32(0)


def encode_auth_sent_code_success_for_sign_up() -> bytes:
    return encode_uint32(AUTH_SENT_CODE_SUCCESS_CONSTRUCTOR) + encode_auth_authorization_sign_up_required()


def user_access_hash(user_id: int) -> int:
    """Return a deterministic non-zero access hash for a self-hosted user."""

    return (user_id << 32) | 1


def encode_user_empty(*, user_id: int) -> bytes:
    return encode_uint32(USER_EMPTY_CONSTRUCTOR) + encode_int64(user_id)


def encode_user(*, user: dict[str, Any], self_user_id: int | None = None, contact: bool = False) -> bytes:
    user_id = int(user["id"])
    first_name = str(user.get("first_name") or "")
    last_name = str(user.get("last_name") or "")
    username = user.get("username")
    phone = user.get("phone")
    flags = 1  # access_hash
    if first_name:
        flags |= 1 << 1
    if last_name:
        flags |= 1 << 2
    if username:
        flags |= 1 << 3
    if phone:
        flags |= 1 << 4
    if self_user_id == user_id:
        flags |= 1 << 10
    elif contact:
        flags |= 1 << 11
    result = (
        encode_uint32(USER_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_uint32(0)  # flags2
        + encode_int64(user_id)
        + encode_int64(user_access_hash(user_id))
    )
    if flags & (1 << 1):
        result += encode_tl_string(first_name)
    if flags & (1 << 2):
        result += encode_tl_string(last_name)
    if flags & (1 << 3):
        result += encode_tl_string(str(username))
    if flags & (1 << 4):
        result += encode_tl_string(str(phone))
    return result


def encode_peer_user(*, user_id: int) -> bytes:
    return encode_uint32(PEER_USER_CONSTRUCTOR) + encode_int64(user_id)


def encode_peer_chat(*, chat_id: int) -> bytes:
    return encode_uint32(PEER_CHAT_CONSTRUCTOR) + encode_int64(chat_id)


def encode_upload_file(*, mtime: int, content: bytes) -> bytes:
    return (
        encode_uint32(UPLOAD_FILE_CONSTRUCTOR)
        + encode_uint32(STORAGE_FILE_UNKNOWN_CONSTRUCTOR)
        + encode_int32(mtime)
        + encode_tl_bytes(content)
    )


def encode_photo_size(*, type_: str, width: int, height: int, size: int) -> bytes:
    return (
        encode_uint32(PHOTO_SIZE_CONSTRUCTOR)
        + encode_tl_string(type_)
        + encode_int32(width)
        + encode_int32(height)
        + encode_int32(size)
    )


def encode_photo(*, photo_id: int, file_reference: bytes, date: int, size: int, dc_id: int = 1) -> bytes:
    return (
        encode_uint32(PHOTO_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(photo_id)
        + encode_int64((photo_id << 32) | 1)
        + encode_tl_bytes(file_reference)
        + encode_int32(date)
        + encode_vector([encode_photo_size(type_="m", width=0, height=0, size=size)])
        + encode_int32(dc_id)
    )


def encode_photos_photo(*, photo: bytes, users: Iterable[bytes]) -> bytes:
    return encode_uint32(PHOTOS_PHOTO_CONSTRUCTOR) + photo + encode_vector(users)


def encode_chat_participant(*, user_id: int, inviter_id: int, date: int, rank: str | None = None) -> bytes:
    flags = 1 if rank else 0
    result = (
        encode_uint32(CHAT_PARTICIPANT_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_int64(user_id)
        + encode_int64(inviter_id)
        + encode_int32(date)
    )
    return result + (encode_tl_string(rank) if rank else b"")


def encode_chat_participants(*, chat_id: int, participants: Iterable[bytes], version: int = 1) -> bytes:
    return (
        encode_uint32(CHAT_PARTICIPANTS_CONSTRUCTOR)
        + encode_int64(chat_id)
        + encode_vector(participants)
        + encode_int32(version)
    )


def encode_chat_full(*, chat_id: int, about: str, participants: bytes) -> bytes:
    return (
        encode_uint32(CHAT_FULL_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(chat_id)
        + encode_tl_string(about)
        + participants
        + encode_peer_notify_settings()
    )


def encode_messages_chat_full(*, full_chat: bytes, chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(MESSAGES_CHAT_FULL_CONSTRUCTOR)
        + full_chat
        + encode_vector(chats)
        + encode_vector(users)
    )


def encode_chat(*, chat_id: int, title: str, participants_count: int, date: int, creator: bool = False, version: int = 1) -> bytes:
    flags = 1 if creator else 0
    return (
        encode_uint32(CHAT_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_int64(chat_id)
        + encode_tl_string(title)
        + encode_uint32(CHAT_PHOTO_EMPTY_CONSTRUCTOR)
        + encode_int32(participants_count)
        + encode_int32(date)
        + encode_int32(version)
    )


def encode_peer_notify_settings() -> bytes:
    return encode_uint32(PEER_NOTIFY_SETTINGS_CONSTRUCTOR) + encode_uint32(0)


def encode_peer_settings() -> bytes:
    return encode_uint32(PEER_SETTINGS_CONSTRUCTOR) + encode_uint32(0)


def encode_dialog(
    *,
    peer: bytes,
    top_message_id: int,
    read_inbox_max_id: int = 0,
    read_outbox_max_id: int = 0,
    unread_count: int = 0,
    pinned: bool = False,
) -> bytes:
    flags = 1 << 2 if pinned else 0
    return (
        encode_uint32(DIALOG_CONSTRUCTOR)
        + encode_uint32(flags)
        + peer
        + encode_int32(top_message_id)
        + encode_int32(read_inbox_max_id)
        + encode_int32(read_outbox_max_id)
        + encode_int32(unread_count)
        + encode_int32(0)  # unread_mentions_count
        + encode_int32(0)  # unread_reactions_count
        + encode_int32(0)  # unread_poll_votes_count
        + encode_peer_notify_settings()
    )


def encode_message(*, message: dict[str, Any], recipient_peer: bytes, outgoing: bool) -> bytes:
    flags = (1 << 8) | ((1 << 1) if outgoing else 0)
    return (
        encode_uint32(MESSAGE_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_uint32(0)  # flags2
        + encode_int32(int(message["id"]))
        + encode_peer_user(user_id=int(message["sender_user_id"]))
        + recipient_peer
        + encode_int32(int(message["sent_at"]))
        + encode_tl_string(str(message["body"]))
    )


def encode_contact(*, user_id: int, mutual: bool = False) -> bytes:
    return encode_uint32(CONTACT_CONSTRUCTOR) + encode_int64(user_id) + encode_bool(mutual)


def encode_contacts_contacts(*, contacts: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(CONTACTS_CONTACTS_CONSTRUCTOR)
        + encode_vector(contacts)
        + encode_int32(0)
        + encode_vector(users)
    )


def encode_messages_invited_users(*, updates: bytes, missing_invitees: Iterable[bytes] = ()) -> bytes:
    return (
        encode_uint32(MESSAGES_INVITED_USERS_CONSTRUCTOR)
        + updates
        + encode_vector(missing_invitees)
    )


def encode_messages_dialogs(*, dialogs: Iterable[bytes], messages: Iterable[bytes], chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(MESSAGES_DIALOGS_CONSTRUCTOR)
        + encode_vector(dialogs)
        + encode_vector(messages)
        + encode_vector(chats)
        + encode_vector(users)
    )


def encode_messages_messages(*, messages: Iterable[bytes], chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(MESSAGES_MESSAGES_CONSTRUCTOR)
        + encode_vector(messages)
        + encode_vector([])  # topics
        + encode_vector(chats)
        + encode_vector(users)
    )


def encode_messages_peer_dialogs(
    *, dialogs: Iterable[bytes], messages: Iterable[bytes], chats: Iterable[bytes], users: Iterable[bytes],
    pts: int, qts: int, date: int, seq: int, unread_count: int,
) -> bytes:
    return (
        encode_uint32(MESSAGES_PEER_DIALOGS_CONSTRUCTOR)
        + encode_vector(dialogs)
        + encode_vector(messages)
        + encode_vector(chats)
        + encode_vector(users)
        + encode_updates_state(pts=pts, qts=qts, date=date, seq=seq, unread_count=unread_count)
    )


def encode_users_user_full(*, user: dict[str, Any], self_user_id: int | None = None) -> bytes:
    user_id = int(user["id"])
    about = str(user.get("about") or "")
    flags = 1 << 1 if about else 0
    full_user = (
        encode_uint32(USER_FULL_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_uint32(0)  # flags2
        + encode_int64(user_id)
        + (encode_tl_string(about) if about else b"")
        + encode_peer_settings()
        + encode_peer_notify_settings()
        + encode_int32(0)  # common_chats_count
    )
    return (
        encode_uint32(USERS_USER_FULL_CONSTRUCTOR)
        + full_user
        + encode_vector([])
        + encode_vector([encode_user(user=user, self_user_id=self_user_id)])
    )


def encode_update_new_message(*, message: bytes, pts: int, pts_count: int) -> bytes:
    return encode_uint32(UPDATE_NEW_MESSAGE_CONSTRUCTOR) + message + encode_int32(pts) + encode_int32(pts_count)


def encode_update_chat_participants(*, participants: bytes) -> bytes:
    return encode_uint32(UPDATE_CHAT_PARTICIPANTS_CONSTRUCTOR) + participants


def encode_update_read_history_inbox(
    *, peer: bytes, max_id: int, still_unread_count: int, pts: int, pts_count: int, top_msg_id: int | None = None
) -> bytes:
    flags = 2 if top_msg_id is not None else 0
    result = encode_uint32(UPDATE_READ_HISTORY_INBOX_CONSTRUCTOR) + encode_uint32(flags) + peer
    if top_msg_id is not None:
        result += encode_int32(top_msg_id)
    return result + encode_int32(max_id) + encode_int32(still_unread_count) + encode_int32(pts) + encode_int32(pts_count)


def encode_update_message_id(*, message_id: int, random_id: int) -> bytes:
    return encode_uint32(UPDATE_MESSAGE_ID_CONSTRUCTOR) + encode_int32(message_id) + encode_int64(random_id)


def encode_updates(*, updates: Iterable[bytes], users: Iterable[bytes], chats: Iterable[bytes], date: int, seq: int) -> bytes:
    return (
        encode_uint32(UPDATES_CONSTRUCTOR)
        + encode_vector(updates)
        + encode_vector(users)
        + encode_vector(chats)
        + encode_int32(date)
        + encode_int32(seq)
    )


def encode_account_privacy_rules() -> bytes:
    return (
        encode_uint32(ACCOUNT_PRIVACY_RULES_CONSTRUCTOR)
        + encode_vector([encode_uint32(PRIVACY_VALUE_ALLOW_ALL_CONSTRUCTOR)])
        + encode_vector([])
        + encode_vector([])
    )


def encode_auth_authorization(*, user: dict[str, Any]) -> bytes:
    return (
        encode_uint32(AUTH_AUTHORIZATION_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_user(user=user, self_user_id=int(user["id"]))
    )


def encode_updates_difference_empty(*, date: int, seq: int) -> bytes:
    return encode_uint32(UPDATES_DIFFERENCE_EMPTY_CONSTRUCTOR) + encode_int32(date) + encode_int32(seq)


def encode_updates_difference(
    *,
    new_messages: Iterable[bytes],
    other_updates: Iterable[bytes],
    chats: Iterable[bytes],
    users: Iterable[bytes],
    pts: int,
    qts: int,
    date: int,
    seq: int,
) -> bytes:
    return (
        encode_uint32(UPDATES_DIFFERENCE_CONSTRUCTOR)
        + encode_vector(new_messages)
        + encode_vector([])  # new_encrypted_messages
        + encode_vector(other_updates)
        + encode_vector(chats)
        + encode_vector(users)
        + encode_updates_state(pts=pts, qts=qts, date=date, seq=seq, unread_count=0)
    )


def encode_updates_state(*, pts: int, qts: int, date: int, seq: int, unread_count: int) -> bytes:
    return (
        encode_uint32(UPDATES_STATE_CONSTRUCTOR)
        + encode_int32(pts)
        + encode_int32(qts)
        + encode_int32(date)
        + encode_int32(seq)
        + encode_int32(unread_count)
    )


def encode_rpc_error(*, code: int, message: str) -> bytes:
    return encode_uint32(RPC_ERROR_CONSTRUCTOR) + encode_int32(code) + encode_tl_string(message)


def encode_rpc_result(*, request_message_id: int, result: bytes) -> bytes:
    return encode_uint32(RPC_RESULT_CONSTRUCTOR) + encode_int64(request_message_id) + result


def encode_new_session_created(*, first_message_id: int, unique_id: int, server_salt: int) -> bytes:
    return (
        encode_uint32(NEW_SESSION_CREATED_CONSTRUCTOR)
        + encode_int64(first_message_id)
        + encode_int64(unique_id)
        + encode_int64(server_salt)
    )


def encode_bad_server_salt(*, bad_message_id: int, bad_message_seq_no: int, new_server_salt: int) -> bytes:
    return (
        encode_uint32(BAD_SERVER_SALT_CONSTRUCTOR)
        + encode_int64(bad_message_id)
        + encode_int32(bad_message_seq_no)
        + encode_int32(48)
        + encode_int64(new_server_salt)
    )
