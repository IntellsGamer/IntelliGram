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
PING_DELAY_DISCONNECT_CONSTRUCTOR = 0xF3427B8C
MSGS_ACK_CONSTRUCTOR = 0x62D6B459
NEW_SESSION_CREATED_CONSTRUCTOR = 0x9EC20908
BAD_SERVER_SALT_CONSTRUCTOR = 0xEDAB447B
BOOL_TRUE_CONSTRUCTOR = 0x997275B5
BOOL_FALSE_CONSTRUCTOR = 0xBC799737
INVOKE_WITH_LAYER_CONSTRUCTOR = 0xDA9B0D0D
INIT_CONNECTION_CONSTRUCTOR = 0xC1CD5EA9
HELP_GET_CONFIG_CONSTRUCTOR = 0xC4F9186B
HELP_GET_NEAREST_DC_CONSTRUCTOR = 531836966
HELP_GET_APP_CONFIG_CONSTRUCTOR = 0x61E3F854
HELP_APP_CONFIG_CONSTRUCTOR = 0xDD18782E
NEAREST_DC_CONSTRUCTOR = -1910892683
JSON_OBJECT_CONSTRUCTOR = 0x99C1D49D
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
PEER_CHANNEL_CONSTRUCTOR = 0xA2A5371E
INPUT_PEER_EMPTY_CONSTRUCTOR = 0x7F3B18EA
INPUT_USER_EMPTY_CONSTRUCTOR = 0xB98886CF
INPUT_PEER_SELF_CONSTRUCTOR = 0x7DA07EC9
INPUT_PEER_USER_CONSTRUCTOR = 0xDDE8A54C
INPUT_PEER_CHAT_CONSTRUCTOR = 0x35A95CB9
INPUT_PEER_CHANNEL_CONSTRUCTOR = 0x27BCBBFC
INPUT_USER_SELF_CONSTRUCTOR = 0xF7C1B13F
INPUT_USER_CONSTRUCTOR = 0xF210AAE0
INPUT_CHANNEL_CONSTRUCTOR = 0xF35AEC28
INPUT_DIALOG_PEER_CONSTRUCTOR = 0xFCAAFEB7
MESSAGE_CONSTRUCTOR = 0x7600B9D3
MESSAGE_REPLY_HEADER_CONSTRUCTOR = 0x1B97DD66
INPUT_REPLY_TO_MESSAGE_CONSTRUCTOR = 0x3BD4B7C2
DIALOG_CONSTRUCTOR = 0xFC89F7F3
PEER_NOTIFY_SETTINGS_CONSTRUCTOR = 0x99622C0C
PEER_SETTINGS_CONSTRUCTOR = 0xF47741F7
CONTACT_CONSTRUCTOR = 0x145ADE0B
CONTACTS_CONTACTS_CONSTRUCTOR = 0xEAE87E42
MESSAGES_DIALOGS_CONSTRUCTOR = 0x15BA6C40
MESSAGES_DIALOGS_SLICE_CONSTRUCTOR = 0x71E094F3
MESSAGES_MESSAGES_CONSTRUCTOR = 0x1D73E7EA
MESSAGES_MESSAGES_SLICE_CONSTRUCTOR = 0x5F206716
MESSAGES_PEER_DIALOGS_CONSTRUCTOR = 0x3371C354
USER_FULL_CONSTRUCTOR = 0x06CBE645
USERS_USER_FULL_CONSTRUCTOR = 0x3B6D152E
UPDATE_NEW_MESSAGE_CONSTRUCTOR = 0x1F2B0AFD
UPDATE_MESSAGE_ID_CONSTRUCTOR = 0x4E90BFD6
UPDATE_CHANNEL_CONSTRUCTOR = 0x635B4C09
UPDATE_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR = 0x54C01850
UPDATES_CONSTRUCTOR = 0x74AE4240
USERS_GET_USERS_CONSTRUCTOR = 0x0D91A548
USERS_GET_FULL_USER_CONSTRUCTOR = 0xB60F5918
CONTACTS_GET_CONTACTS_CONSTRUCTOR = 0x5DD69E12
MESSAGES_GET_DIALOGS_CONSTRUCTOR = 0xA0F4CB4F
MESSAGES_GET_HISTORY_CONSTRUCTOR = 0x4423E6C5
MESSAGES_SEND_MESSAGE_CONSTRUCTOR = 0xFEF48F62
MESSAGES_SEND_MEDIA_CONSTRUCTOR = 0x0330E77F
MESSAGES_UPLOAD_MEDIA_CONSTRUCTOR = 0x14967978
INPUT_MEDIA_EMPTY_CONSTRUCTOR = 0x9664F57F  # -1771768449
INPUT_MEDIA_UPLOADED_PHOTO_CONSTRUCTOR = 0x7D8375DA  # 2105767386
INPUT_MEDIA_UPLOADED_DOCUMENT_CONSTRUCTOR = 0x037C9330  # 58495792
INPUT_MEDIA_PHOTO_CONSTRUCTOR = 0xE3AF4434  # -475053004
INPUT_MEDIA_DOCUMENT_CONSTRUCTOR = 0xA8763AB5  # -1468646731
MESSAGE_MEDIA_PHOTO_CONSTRUCTOR = 0xE216EB63  # -501814429
MESSAGE_MEDIA_DOCUMENT_CONSTRUCTOR = 0x52D8CCD9  # 1389939929
DOCUMENT_CONSTRUCTOR = 0x8FD4C4D8  # -1881881384
DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR = 0x15590068  # 358154344
INPUT_DOCUMENT_FILE_LOCATION_CONSTRUCTOR = 0xBAD07584  # -1160743548
INPUT_PHOTO_CONSTRUCTOR = 0x3BB3B94A  # 1001634122
INPUT_DOCUMENT_CONSTRUCTOR = 0x1ABFB575  # 448771445
DOCUMENT_ATTRIBUTE_IMAGE_SIZE_CONSTRUCTOR = 0x6C37C15C  # 1815593308
DOCUMENT_ATTRIBUTE_VIDEO_CONSTRUCTOR = 0x43C57C48  # 1137015880
DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR = 0x9852F9C6  # -1739392570
DOCUMENT_ATTRIBUTE_ANIMATED_CONSTRUCTOR = 0x11B58939  # 297109817
INPUT_MEDIA_WEB_PAGE_CONSTRUCTOR = 0xC21B8849  # -1038383031
UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR = 0x62BA04D9  # 1656358105
MESSAGES_GET_EMOJI_GROUPS_CONSTRUCTOR = 0x7488CE5B
MESSAGES_GET_EMOJI_STATUS_GROUPS_CONSTRUCTOR = 0x2ECD56CD
MESSAGES_GET_EMOJI_PROFILE_PHOTO_GROUPS_CONSTRUCTOR = 0x21A548F3
MESSAGES_GET_ALL_STICKERS_CONSTRUCTOR = 0xB8A0A1A8
MESSAGES_GET_STICKER_SET_CONSTRUCTOR = 0xC8A0EC74
MESSAGES_GET_EMOJI_STICKERS_CONSTRUCTOR = 0xFBFCA18F
MESSAGES_GET_EMOJI_KEYWORDS_DIFFERENCE_CONSTRUCTOR = 0x1508B6AF
MESSAGES_EMOJI_GROUPS_NOT_MODIFIED_CONSTRUCTOR = 0x6FB4AD87
MESSAGES_ALL_STICKERS_NOT_MODIFIED_CONSTRUCTOR = 0xE86602C3
MESSAGES_STICKER_SET_NOT_MODIFIED_CONSTRUCTOR = 0xD3F924EB
EMOJI_KEYWORDS_DIFFERENCE_CONSTRUCTOR = 0x5CC761BD
INPUT_STICKER_SET_EMPTY_CONSTRUCTOR = 0xFFB62B95
INPUT_STICKER_SET_ID_CONSTRUCTOR = 0x9DE7A269
INPUT_STICKER_SET_SHORT_NAME_CONSTRUCTOR = 0x861CC8A0
MESSAGES_GET_PEER_DIALOGS_CONSTRUCTOR = 0xE470BCFD
ACCOUNT_UPDATE_STATUS_CONSTRUCTOR = 0x6628562C
ACCOUNT_GET_PRIVACY_CONSTRUCTOR = 0xDADBC950
ACCOUNT_GET_CONTENT_SETTINGS_CONSTRUCTOR = 0x8B9B4DAE
ACCOUNT_CONTENT_SETTINGS_CONSTRUCTOR = 0x57E28221
PRIVACY_VALUE_ALLOW_ALL_CONSTRUCTOR = 0x65427B82
ACCOUNT_PRIVACY_RULES_CONSTRUCTOR = 0x50A04E45
CHAT_CONSTRUCTOR = 0x41CBF256
CHANNEL_CONSTRUCTOR = 0xD49F34C6
CHANNEL_FULL_CONSTRUCTOR = 0xA04E8D3A
CHAT_PHOTO_EMPTY_CONSTRUCTOR = 0x37C1011C
PHOTO_EMPTY_CONSTRUCTOR = 0x2331B22D
USER_PROFILE_PHOTO_CONSTRUCTOR = 0x82D1F706
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
INPUT_PEER_PHOTO_FILE_LOCATION_CONSTRUCTOR = 0x37257E99
STORAGE_FILE_UNKNOWN_CONSTRUCTOR = 0xAA963B05
UPLOAD_FILE_CONSTRUCTOR = 0x096A18D5
UPDATES_GET_DIFFERENCE_CONSTRUCTOR = 0x19C2F763
UPDATES_DIFFERENCE_EMPTY_CONSTRUCTOR = 0x5D75A138
UPDATES_DIFFERENCE_CONSTRUCTOR = 0x00F49CA0
MESSAGES_GET_FULL_CHAT_CONSTRUCTOR = 0xAEB00B34
MESSAGES_MIGRATE_CHAT_CONSTRUCTOR = 0xA2875319
CHANNELS_GET_CHANNELS_CONSTRUCTOR = 0x0A7F6BBB
CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR = 0x08736A09
CHANNELS_CREATE_CHANNEL_CONSTRUCTOR = 0x91006707  # -1862244601
CHANNELS_INVITE_TO_CHANNEL_CONSTRUCTOR = 0xC9E33D54  # -907854508
CHANNELS_GET_PARTICIPANTS_CONSTRUCTOR = 0x77CED9D0  # 2010044880
CHANNELS_GET_PARTICIPANT_CONSTRUCTOR = 0xA0AB6CC6  # -1599378234
CHANNELS_EDIT_TITLE_CONSTRUCTOR = 0x566DECD0  # 1450044624
CHANNELS_EDIT_PHOTO_CONSTRUCTOR = 0xF12E57C9  # -248621111
CHANNELS_DELETE_CHANNEL_CONSTRUCTOR = 0xC0111FE3  # -1072619549
CHANNELS_JOIN_CHANNEL_CONSTRUCTOR = 0x7F6A1E22  # 2137660962
CHANNELS_LEAVE_CHANNEL_CONSTRUCTOR = 0xF836AA95  # -130635115
UPDATES_GET_CHANNEL_DIFFERENCE_CONSTRUCTOR = 0x03173D78  # 51854712
MESSAGES_GET_EXPORTED_CHAT_INVITE_CONSTRUCTOR = 0x73746F5C  # 1937010524
MESSAGES_CHECK_CHAT_INVITE_CONSTRUCTOR = 0x3EADB1BB  # 1051570619
MESSAGES_IMPORT_CHAT_INVITE_CONSTRUCTOR = 0xDE8C0C64  # -560905362
MESSAGES_GET_ADMINS_WITH_INVITES_CONSTRUCTOR = 0x39224859  # 958457583
MESSAGES_GET_CHAT_INVITE_IMPORTERS_CONSTRUCTOR = 0xDF04DD4E  # -553329330
UPDATE_EDIT_CHANNEL_MESSAGE_CONSTRUCTOR = 0x1B3F4DF7  # 457133559
CHANNEL_PARTICIPANT_CONSTRUCTOR = 0x1BD54456  # 466961494
CHANNEL_PARTICIPANT_SELF_CONSTRUCTOR = 0xA9478A1A  # -1454929382
CHANNEL_PARTICIPANT_CREATOR_CONSTRUCTOR = 0x2FE601D3  # 803602899
CHANNEL_PARTICIPANTS_RECENT_CONSTRUCTOR = 0xDE3F3C79  # -566281095
CHANNEL_PARTICIPANTS_ADMINS_CONSTRUCTOR = 0xB4608969  # -1268741783
CHANNEL_PARTICIPANTS_SEARCH_CONSTRUCTOR = 0x0656AC4B  # 106343499
CHANNEL_PARTICIPANTS_KICKED_CONSTRUCTOR = 0xA3B54985  # -1548400251
CHANNEL_PARTICIPANTS_BANNED_CONSTRUCTOR = 0x1427A5E1  # 338142689
CHANNELS_CHANNEL_PARTICIPANTS_CONSTRUCTOR = 0x9AB0FEAF  # -1699676497
CHANNELS_CHANNEL_PARTICIPANT_CONSTRUCTOR = 0xDFB80317  # -541588713
CHANNELS_CHANNEL_PARTICIPANTS_NOT_MODIFIED_CONSTRUCTOR = 0xF0173FE9  # -266911767
CHAT_ADMIN_RIGHTS_CONSTRUCTOR = 0x5FB224D5  # 1605510357
CHAT_INVITE_CONSTRUCTOR = 0x5C98615A  # 1553807106
CHAT_INVITE_ALREADY_CONSTRUCTOR = 0x5A686D7C  # 1516793212
MESSAGES_CHAT_INVITE_JOIN_RESULT_OK_CONSTRUCTOR = 0x445663A7  # 1146512295
MESSAGES_CHAT_ADMINS_WITH_INVITES_CONSTRUCTOR = 0xB69B72D7  # -1231326505
MESSAGES_CHAT_INVITE_IMPORTERS_CONSTRUCTOR = 0x81B6B00A  # -2118733814
UPDATES_CHANNEL_DIFFERENCE_EMPTY_CONSTRUCTOR = 0x3E11AFFB  # 1041346555
CHANNEL_MESSAGES_FILTER_EMPTY_CONSTRUCTOR = 0x94D42EE7  # -1798033689
CHANNEL_MESSAGES_FILTER_CONSTRUCTOR = 0xCD77D957  # -847783593
INPUT_CHANNEL_EMPTY_CONSTRUCTOR = 0xEE8C1E86  # -292807034
INPUT_GEO_POINT_EMPTY_CONSTRUCTOR = 0xE4C123D6  # -457104426
INPUT_CHAT_PHOTO_EMPTY_CONSTRUCTOR = 0x1CA48F57
INPUT_CHAT_UPLOADED_PHOTO_CONSTRUCTOR = 0xBDCDAEC0  # -1110593856
INPUT_CHAT_PHOTO_CONSTRUCTOR = 0x8953AD37  # -1991004873
CHANNELS_TOGGLE_SLOW_MODE_CONSTRUCTOR = 0xEDD49EF0
CHANNELS_TOGGLE_JOIN_REQUEST_CONSTRUCTOR = 0x0ECC2618
CHANNELS_TOGGLE_SIGNATURES_CONSTRUCTOR = 0x418D549C
MESSAGES_EDIT_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR = 0xA5866B41
CHAT_BANNED_RIGHTS_CONSTRUCTOR = 0x9F120418
MESSAGES_SET_CHAT_AVAILABLE_REACTIONS_CONSTRUCTOR = 0x864B2581
CHAT_REACTIONS_NONE_CONSTRUCTOR = 0xEAFC32BC
CHAT_REACTIONS_ALL_CONSTRUCTOR = 0x52928BCA
CHAT_REACTIONS_SOME_CONSTRUCTOR = 0x661D4037
REACTION_EMOJI_CONSTRUCTOR = 0x1B2286B8
MESSAGES_EXPORT_CHAT_INVITE_CONSTRUCTOR = 0xA455DE90
MESSAGES_EDIT_EXPORTED_CHAT_INVITE_CONSTRUCTOR = 0xBDCA2F75
MESSAGES_DELETE_REVOKED_EXPORTED_CHAT_INVITES_CONSTRUCTOR = 0x56987BD5
MESSAGES_DELETE_EXPORTED_CHAT_INVITE_CONSTRUCTOR = 0xD464A42B
MESSAGES_TOGGLE_NO_FORWARDS_CONSTRUCTOR = 0xB2081A35
CHANNELS_CHECK_USERNAME_CONSTRUCTOR = 0x10E6BD2C
CHANNELS_UPDATE_USERNAME_CONSTRUCTOR = 0x3514B3DE
CHANNELS_DEACTIVATE_ALL_USERNAMES_CONSTRUCTOR = 0x0A245DD3
CHAT_INVITE_EXPORTED_CONSTRUCTOR = 0xA22CBD96
MESSAGES_EXPORTED_CHAT_INVITE_CONSTRUCTOR = 0x1871BE50
MESSAGES_EXPORTED_CHAT_INVITE_REPLACED_CONSTRUCTOR = 0x222600EF
MESSAGES_GET_EXPORTED_CHAT_INVITES_CONSTRUCTOR = 0xA2B5A3F6
MESSAGES_EXPORTED_CHAT_INVITES_CONSTRUCTOR = 0xBDC62DCC
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
MESSAGES_GET_PAID_REACTION_PRIVACY_CONSTRUCTOR = 0x472455AA
MESSAGES_GET_AVAILABLE_REACTIONS_CONSTRUCTOR = 0x18DEA0AC
MESSAGES_PEER_SETTINGS_CONSTRUCTOR = 0x6880B94D
MESSAGES_AVAILABLE_REACTIONS_CONSTRUCTOR = 0x768E3AAD
MESSAGES_CHATS_CONSTRUCTOR = 0x64FF9FD5
COMMUNITIES_GET_JOINED_COMMUNITIES_CONSTRUCTOR = 0xA663E830
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
MESSAGES_DELETE_MESSAGES_CONSTRUCTOR = 0xE58E95D2
MESSAGES_EDIT_MESSAGE_CONSTRUCTOR = 0xB107A14C
MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR = 0x13704A7C
UPDATE_DELETE_MESSAGES_CONSTRUCTOR = 0xA20DB0E5
UPDATE_EDIT_MESSAGE_CONSTRUCTOR = 0xE40370A3
UPDATES_TOO_LONG_CONSTRUCTOR = 0xE317AF7E
INPUT_PHONE_CONTACT_CONSTRUCTOR = 0x6A1DC4BE
CONTACTS_IMPORT_CONTACTS_CONSTRUCTOR = 0x2C800BE5
IMPORTED_CONTACT_CONSTRUCTOR = 0xC13E3C50
CONTACTS_IMPORTED_CONTACTS_CONSTRUCTOR = 0x77D01C3B
CONTACTS_SEARCH_CONSTRUCTOR = 0x05F58D0F
CONTACTS_FOUND_CONSTRUCTOR = 0xB3134D9D
ACCOUNT_AUTHORIZATION_CONSTRUCTOR = 0xAD01D61D
ACCOUNT_AUTHORIZATIONS_CONSTRUCTOR = 0x4BFF8EA0
ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR = 0xE320C158
ACCOUNT_RESET_AUTHORIZATION_CONSTRUCTOR = 0xDF77F3BC
ACCOUNT_GET_PASSWORD_CONSTRUCTOR = 0x548A30F5
AUTH_CHECK_PASSWORD_CONSTRUCTOR = 0xD18B4D16
ACCOUNT_PASSWORD_CONSTRUCTOR = 0x957B50FB
PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR = 0x3A912D4A
SECURE_PASSWORD_KDF_ALGO_UNKNOWN_CONSTRUCTOR = 0x004A8537
INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR = 0xD27FF082


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

    def double(self) -> float:
        self._require(8)
        value = struct.unpack_from("<d", self.data, self.offset)[0]
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


def encode_vector_ints(values: Iterable[int]) -> bytes:
    sequence = list(values)
    return encode_uint32(VECTOR_CONSTRUCTOR) + encode_int32(len(sequence)) + b"".join(encode_int32(value) for value in sequence)


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
    if constructor_id == INPUT_PEER_CHANNEL_CONSTRUCTOR:
        return {"kind": "channel", "channel_id": reader.int64(), "access_hash": reader.int64()}
    raise TLDecodeError(f"Unsupported InputPeer constructor: 0x{constructor_id:08x}")


def _read_input_phone_contact(reader: TLReader) -> dict[str, Any]:
    if reader.uint32() != INPUT_PHONE_CONTACT_CONSTRUCTOR:
        raise TLDecodeError("Expected an inputPhoneContact constructor")
    flags = reader.uint32()
    if flags:
        raise TLDecodeError("Unsupported inputPhoneContact optional fields")
    return {
        "client_id": reader.int64(),
        "phone": reader.bytes().decode("utf-8"),
        "first_name": reader.bytes().decode("utf-8"),
        "last_name": reader.bytes().decode("utf-8"),
    }


def _read_input_reply_to(reader: TLReader) -> dict[str, Any]:
    if reader.uint32() != INPUT_REPLY_TO_MESSAGE_CONSTRUCTOR:
        raise TLDecodeError("Only inputReplyToMessage is supported")
    flags = reader.uint32()
    if flags:
        raise TLDecodeError("Extended inputReplyToMessage fields are not supported")
    return {"reply_to_message_id": reader.int32()}


def _read_input_user(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_USER_EMPTY_CONSTRUCTOR:
        return {"kind": "empty"}
    if constructor_id == INPUT_USER_SELF_CONSTRUCTOR:
        return {"kind": "self"}
    if constructor_id == INPUT_USER_CONSTRUCTOR:
        return {
            "kind": "user",
            "user_id": reader.int64(),
            "access_hash": reader.int64(),
        }
    raise TLDecodeError(f"Unsupported InputUser constructor: 0x{constructor_id:08x}")


def _read_reaction(reader: TLReader) -> dict[str, str]:
    if reader.uint32() != REACTION_EMOJI_CONSTRUCTOR:
        raise TLDecodeError("Only standard emoji reactions are supported")
    return {"emoticon": reader.bytes().decode("utf-8")}


def _read_chat_reactions(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == CHAT_REACTIONS_NONE_CONSTRUCTOR:
        return {"mode": "none", "allow_custom": False, "emoticons": []}
    if constructor_id == CHAT_REACTIONS_ALL_CONSTRUCTOR:
        return {"mode": "all", "allow_custom": bool(reader.uint32() & 1), "emoticons": []}
    if constructor_id == CHAT_REACTIONS_SOME_CONSTRUCTOR:
        return {
            "mode": "some",
            "allow_custom": False,
            "emoticons": [reaction["emoticon"] for reaction in (_read_reaction(reader) for _ in range(reader.vector_count()))],
        }
    raise TLDecodeError(f"Unsupported ChatReactions constructor: 0x{constructor_id:08x}")


def _read_chat_banned_rights(reader: TLReader) -> dict[str, int]:
    if reader.uint32() != CHAT_BANNED_RIGHTS_CONSTRUCTOR:
        raise TLDecodeError("Expected a chatBannedRights constructor")
    return {"flags": reader.uint32(), "until_date": reader.int32()}


def _read_input_channel(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_CHANNEL_EMPTY_CONSTRUCTOR:
        return {"kind": "empty", "channel_id": 0, "access_hash": 0}
    if constructor_id != INPUT_CHANNEL_CONSTRUCTOR:
        raise TLDecodeError("Expected an inputChannel constructor")
    return {"kind": "channel", "channel_id": reader.int64(), "access_hash": reader.int64()}


def _read_input_geo_point(reader: TLReader) -> None:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_GEO_POINT_EMPTY_CONSTRUCTOR:
        return
    flags = reader.uint32()
    reader.double()
    reader.double()
    if flags & 1:
        reader.int32()


def _read_input_chat_photo(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_CHAT_PHOTO_EMPTY_CONSTRUCTOR:
        return {"kind": "empty"}
    if constructor_id == INPUT_CHAT_UPLOADED_PHOTO_CONSTRUCTOR:
        flags = reader.uint32()
        media = {"kind": "uploaded"}
        if flags & 1:
            media["file"] = _read_input_file(reader)
        if flags & 2:
            media["video"] = _read_input_file(reader)
        if flags & 4:
            media["video_start_ts"] = reader.double()
        if flags & 8:
            raise TLDecodeError("Video emoji markup is not supported")
        return media
    if constructor_id == INPUT_CHAT_PHOTO_CONSTRUCTOR:
        return {"kind": "photo", "photo": _read_input_photo(reader)}
    raise TLDecodeError(f"Unsupported InputChatPhoto constructor: 0x{constructor_id:08x}")


def _read_channel_participants_filter(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id in {
        CHANNEL_PARTICIPANTS_RECENT_CONSTRUCTOR,
        CHANNEL_PARTICIPANTS_ADMINS_CONSTRUCTOR,
    }:
        return {"kind": "recent" if constructor_id == CHANNEL_PARTICIPANTS_RECENT_CONSTRUCTOR else "admins"}
    if constructor_id in {
        CHANNEL_PARTICIPANTS_SEARCH_CONSTRUCTOR,
        CHANNEL_PARTICIPANTS_KICKED_CONSTRUCTOR,
        CHANNEL_PARTICIPANTS_BANNED_CONSTRUCTOR,
    }:
        return {"kind": "search", "q": reader.bytes().decode("utf-8")}
    # Empty-bodied official filters (bots/contacts/mentions) are treated as recent.
    return {"kind": "recent"}


def _read_channel_messages_filter(reader: TLReader) -> None:
    constructor_id = reader.uint32()
    if constructor_id == CHANNEL_MESSAGES_FILTER_EMPTY_CONSTRUCTOR:
        return
    if constructor_id == CHANNEL_MESSAGES_FILTER_CONSTRUCTOR:
        reader.uint32()
        for _ in range(reader.vector_count()):
            reader.int32()
            reader.int32()
        return
    raise TLDecodeError(f"Unsupported ChannelMessagesFilter constructor: 0x{constructor_id:08x}")


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
    if constructor_id == INPUT_PEER_PHOTO_FILE_LOCATION_CONSTRUCTOR:
        flags = reader.uint32()
        return {
            "kind": "peer_photo",
            "big": bool(flags & 1),
            "peer": _read_input_peer(reader),
            "photo_id": reader.int64(),
        }
    if constructor_id == INPUT_DOCUMENT_FILE_LOCATION_CONSTRUCTOR:
        return {
            "kind": "document",
            "document_id": reader.int64(),
            "access_hash": reader.int64(),
            "file_reference": reader.bytes(),
            "thumb_size": reader.bytes().decode("utf-8"),
        }
    raise TLDecodeError(f"Unsupported InputFileLocation constructor: 0x{constructor_id:08x}")


def _read_input_photo(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_PHOTO_CONSTRUCTOR:
        return {
            "id": reader.int64(),
            "access_hash": reader.int64(),
            "file_reference": reader.bytes(),
        }
    raise TLDecodeError(f"Unsupported InputPhoto constructor: 0x{constructor_id:08x}")


def _read_input_document(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_DOCUMENT_CONSTRUCTOR:
        return {
            "id": reader.int64(),
            "access_hash": reader.int64(),
            "file_reference": reader.bytes(),
        }
    raise TLDecodeError(f"Unsupported InputDocument constructor: 0x{constructor_id:08x}")


def _read_document_attribute(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR:
        return {"kind": "filename", "file_name": reader.bytes().decode("utf-8")}
    if constructor_id == DOCUMENT_ATTRIBUTE_IMAGE_SIZE_CONSTRUCTOR:
        return {"kind": "image_size", "w": reader.int32(), "h": reader.int32()}
    if constructor_id == DOCUMENT_ATTRIBUTE_ANIMATED_CONSTRUCTOR:
        return {"kind": "animated"}
    if constructor_id == DOCUMENT_ATTRIBUTE_VIDEO_CONSTRUCTOR:
        flags = reader.uint32()
        attribute = {
            "kind": "video",
            "duration": reader.double(),
            "w": reader.int32(),
            "h": reader.int32(),
        }
        if flags & (1 << 2):
            attribute["preload_prefix_size"] = reader.int32()
        if flags & (1 << 4):
            attribute["video_start_ts"] = reader.double()
        if flags & (1 << 5):
            attribute["video_codec"] = reader.bytes().decode("utf-8")
        return attribute
    if constructor_id == DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR:
        flags = reader.uint32()
        attribute = {"kind": "audio", "duration": reader.int32()}
        if flags & (1 << 10):
            attribute["voice"] = True
        if flags & 1:
            attribute["title"] = reader.bytes().decode("utf-8")
        if flags & 2:
            attribute["performer"] = reader.bytes().decode("utf-8")
        if flags & 4:
            attribute["waveform"] = reader.bytes()
        return attribute
    raise TLDecodeError(f"Unsupported DocumentAttribute constructor: 0x{constructor_id:08x}")


def _read_input_media(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_MEDIA_EMPTY_CONSTRUCTOR:
        return {"kind": "empty"}
    if constructor_id == INPUT_MEDIA_UPLOADED_PHOTO_CONSTRUCTOR:
        flags = reader.uint32()
        media = {"kind": "uploaded_photo", "file": _read_input_file(reader)}
        if flags & 1:
            for _ in range(reader.vector_count()):
                _read_input_document(reader)
        if flags & 2:
            media["ttl_seconds"] = reader.int32()
        if flags & 8:
            _read_input_document(reader)
        return media
    if constructor_id == INPUT_MEDIA_UPLOADED_DOCUMENT_CONSTRUCTOR:
        flags = reader.uint32()
        media = {"kind": "uploaded_document", "file": _read_input_file(reader)}
        if flags & 4:
            media["thumb"] = _read_input_file(reader)
        media["mime_type"] = reader.bytes().decode("utf-8")
        media["attributes"] = [_read_document_attribute(reader) for _ in range(reader.vector_count())]
        if flags & 1:
            for _ in range(reader.vector_count()):
                _read_input_document(reader)
        if flags & 64:
            _read_input_photo(reader)
        if flags & 128:
            media["video_timestamp"] = reader.int32()
        if flags & 2:
            media["ttl_seconds"] = reader.int32()
        return media
    if constructor_id == INPUT_MEDIA_PHOTO_CONSTRUCTOR:
        flags = reader.uint32()
        photo = _read_input_photo(reader)
        if flags & 1:
            reader.int32()
        if flags & 4:
            _read_input_document(reader)
        return {"kind": "photo", "id": photo["id"]}
    if constructor_id == INPUT_MEDIA_DOCUMENT_CONSTRUCTOR:
        flags = reader.uint32()
        document = _read_input_document(reader)
        if flags & 8:
            _read_input_photo(reader)
        if flags & 16:
            reader.int32()
        if flags & 1:
            reader.int32()
        if flags & 2:
            reader.bytes()
        return {"kind": "document", "id": document["id"]}
    if constructor_id == INPUT_MEDIA_WEB_PAGE_CONSTRUCTOR:
        flags = reader.uint32()
        url = reader.bytes().decode("utf-8")
        return {"kind": "webpage", "url": url}
    raise TLDecodeError(f"Unsupported InputMedia constructor: 0x{constructor_id:08x}")


def _read_input_sticker_set(reader: TLReader) -> dict[str, Any]:
    constructor_id = reader.uint32()
    if constructor_id == INPUT_STICKER_SET_EMPTY_CONSTRUCTOR:
        return {"kind": "empty"}
    if constructor_id == INPUT_STICKER_SET_ID_CONSTRUCTOR:
        return {"kind": "id", "id": reader.int64(), "access_hash": reader.int64()}
    if constructor_id == INPUT_STICKER_SET_SHORT_NAME_CONSTRUCTOR:
        return {"kind": "short_name", "short_name": reader.bytes().decode("utf-8")}
    raise TLDecodeError(f"Unsupported InputStickerSet constructor: 0x{constructor_id:08x}")


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
    elif constructor_id == PING_DELAY_DISCONNECT_CONSTRUCTOR:
        request = TLRequest(constructor_id, "ping_delay_disconnect", {
            "ping_id": reader.int64(),
            "disconnect_delay": reader.int32(),
        })
    elif constructor_id == MSGS_ACK_CONSTRUCTOR:
        request = TLRequest(constructor_id, "msgs_ack", {"msg_ids": reader.vector_longs()})
    elif constructor_id == HELP_GET_CONFIG_CONSTRUCTOR:
        request = TLRequest(constructor_id, "help_get_config", {})
    elif constructor_id == HELP_GET_NEAREST_DC_CONSTRUCTOR:
        request = TLRequest(constructor_id, "help_get_nearest_dc", {})
    elif constructor_id == HELP_GET_APP_CONFIG_CONSTRUCTOR:
        request = TLRequest(constructor_id, "help_get_app_config", {"hash": reader.int32()})
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
    elif constructor_id == ACCOUNT_GET_PASSWORD_CONSTRUCTOR:
        request = TLRequest(constructor_id, "account_get_password", {})
    elif constructor_id == AUTH_CHECK_PASSWORD_CONSTRUCTOR:
        password_constructor = reader.uint32()
        if password_constructor != INPUT_CHECK_PASSWORD_SRP_CONSTRUCTOR:
            raise TLDecodeError("Expected inputCheckPasswordSRP")
        request = TLRequest(constructor_id, "auth_check_password", {
            "srp_id": reader.int64(),
            "A": reader.bytes(),
            "M1": reader.bytes(),
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
    elif constructor_id == CONTACTS_IMPORT_CONTACTS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "contacts_import_contacts", {
            "contacts": [_read_input_phone_contact(reader) for _ in range(reader.vector_count())],
        })
    elif constructor_id == CONTACTS_SEARCH_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b11:
            raise TLDecodeError("Unsupported contacts.search optional fields")
        request = TLRequest(constructor_id, "contacts_search", {
            "query": reader.bytes().decode("utf-8"),
            "limit": reader.int32(),
        })
    elif constructor_id == ACCOUNT_GET_AUTHORIZATIONS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "account_get_authorizations", {})
    elif constructor_id == ACCOUNT_RESET_AUTHORIZATION_CONSTRUCTOR:
        request = TLRequest(constructor_id, "account_reset_authorization", {"hash": reader.int64()})
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
        if flags & ~(supported_boolean_flags | 1):
            raise TLDecodeError("Unsupported messages.sendMessage optional fields")
        request = TLRequest(constructor_id, "messages_send_message", {
            "peer": _read_input_peer(reader),
            "reply_to": _read_input_reply_to(reader) if flags & 1 else None,
            "message": reader.bytes().decode("utf-8"),
            "random_id": reader.int64(),
            "silent": bool(flags & (1 << 5)),
        })
    elif constructor_id == MESSAGES_SEND_MEDIA_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_send_media", {
            "peer": _read_input_peer(reader),
            "reply_to": _read_input_reply_to(reader) if flags & 1 else None,
            "media": _read_input_media(reader),
            "message": reader.bytes().decode("utf-8"),
            "random_id": reader.int64(),
            "silent": bool(flags & (1 << 5)),
        })
        if reader.remaining:
            reader.raw_bytes(reader.remaining)
    elif constructor_id == MESSAGES_UPLOAD_MEDIA_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_upload_media", {
            "business_connection_id": reader.bytes().decode("utf-8") if flags & 1 else None,
            "peer": _read_input_peer(reader),
            "media": _read_input_media(reader),
        })
    elif constructor_id == MESSAGES_GET_EMOJI_GROUPS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_emoji_groups", {"hash": reader.int32()})
    elif constructor_id == MESSAGES_GET_EMOJI_STATUS_GROUPS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_emoji_status_groups", {"hash": reader.int32()})
    elif constructor_id == MESSAGES_GET_EMOJI_PROFILE_PHOTO_GROUPS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_emoji_profile_photo_groups", {"hash": reader.int32()})
    elif constructor_id == MESSAGES_GET_ALL_STICKERS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_all_stickers", {"hash": reader.int64()})
    elif constructor_id == MESSAGES_GET_EMOJI_STICKERS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_emoji_stickers", {"hash": reader.int64()})
    elif constructor_id == MESSAGES_GET_STICKER_SET_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_sticker_set", {
            "stickerset": _read_input_sticker_set(reader),
            "hash": reader.int32(),
        })
    elif constructor_id == MESSAGES_GET_EMOJI_KEYWORDS_DIFFERENCE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_emoji_keywords_difference", {
            "lang_code": reader.bytes().decode("utf-8"),
            "from_version": reader.int32(),
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
    elif constructor_id == MESSAGES_MIGRATE_CHAT_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_migrate_chat", {"chat_id": reader.int64()})
    elif constructor_id == CHANNELS_GET_CHANNELS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_get_channels", {
            "channels": [_read_input_channel(reader) for _ in range(reader.vector_count())],
        })
    elif constructor_id == CHANNELS_GET_FULL_CHANNEL_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_get_full_channel", {"channel": _read_input_channel(reader)})
    elif constructor_id == CHANNELS_CREATE_CHANNEL_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "channels_create_channel", {
            "broadcast": bool(flags & 1),
            "megagroup": bool(flags & 2),
            "title": reader.bytes().decode("utf-8"),
            "about": reader.bytes().decode("utf-8"),
        })
        if flags & 4:
            _read_input_geo_point(reader)
            reader.bytes()
        if flags & 16:
            reader.int32()
    elif constructor_id == CHANNELS_INVITE_TO_CHANNEL_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_invite_to_channel", {
            "channel": _read_input_channel(reader),
            "users": [_read_input_user(reader) for _ in range(reader.vector_count())],
        })
    elif constructor_id == CHANNELS_GET_PARTICIPANTS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_get_participants", {
            "channel": _read_input_channel(reader),
            "filter": _read_channel_participants_filter(reader),
            "offset": reader.int32(),
            "limit": reader.int32(),
            "hash": reader.int64(),
        })
    elif constructor_id == CHANNELS_GET_PARTICIPANT_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_get_participant", {
            "channel": _read_input_channel(reader),
            "participant": _read_input_peer(reader),
        })
    elif constructor_id == CHANNELS_EDIT_TITLE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_edit_title", {
            "channel": _read_input_channel(reader),
            "title": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == CHANNELS_EDIT_PHOTO_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_edit_photo", {
            "channel": _read_input_channel(reader),
            "photo": _read_input_chat_photo(reader),
        })
    elif constructor_id == CHANNELS_DELETE_CHANNEL_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_delete_channel", {"channel": _read_input_channel(reader)})
    elif constructor_id == CHANNELS_JOIN_CHANNEL_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_join_channel", {"channel": _read_input_channel(reader)})
    elif constructor_id == CHANNELS_LEAVE_CHANNEL_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_leave_channel", {"channel": _read_input_channel(reader)})
    elif constructor_id == UPDATES_GET_CHANNEL_DIFFERENCE_CONSTRUCTOR:
        flags = reader.uint32()
        channel = _read_input_channel(reader)
        _read_channel_messages_filter(reader)
        request = TLRequest(constructor_id, "updates_get_channel_difference", {
            "channel": channel,
            "pts": reader.int32(),
            "limit": reader.int32(),
            "force": bool(flags & 1),
        })
    elif constructor_id == MESSAGES_GET_EXPORTED_CHAT_INVITE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_exported_chat_invite", {
            "peer": _read_input_peer(reader),
            "link": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == MESSAGES_CHECK_CHAT_INVITE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_check_chat_invite", {
            "hash": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == MESSAGES_IMPORT_CHAT_INVITE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_import_chat_invite", {
            "hash": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == MESSAGES_GET_ADMINS_WITH_INVITES_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_admins_with_invites", {
            "peer": _read_input_peer(reader),
        })
    elif constructor_id == MESSAGES_GET_CHAT_INVITE_IMPORTERS_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_get_chat_invite_importers", {
            "requested": bool(flags & 1),
            "peer": _read_input_peer(reader),
            "link": reader.bytes().decode("utf-8") if flags & 2 else None,
            "q": reader.bytes().decode("utf-8") if flags & 4 else None,
            "offset_date": reader.int32(),
            "offset_user": _read_input_user(reader),
            "limit": reader.int32(),
        })
    elif constructor_id == CHANNELS_TOGGLE_SLOW_MODE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_toggle_slow_mode", {
            "channel": _read_input_channel(reader),
            "seconds": reader.int32(),
        })
    elif constructor_id == CHANNELS_TOGGLE_SIGNATURES_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b11:
            raise TLDecodeError("Unsupported channels.toggleSignatures flags")
        request = TLRequest(constructor_id, "channels_toggle_signatures", {
            "signatures_enabled": bool(flags & 1),
            "profiles_enabled": bool(flags & 2),
            "channel": _read_input_channel(reader),
        })
    elif constructor_id == CHANNELS_TOGGLE_JOIN_REQUEST_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~0b11:
            raise TLDecodeError("Unsupported channels.toggleJoinRequest optional fields")
        request = TLRequest(constructor_id, "channels_toggle_join_request", {
            "apply_to_invites": bool(flags & 1),
            "channel": _read_input_channel(reader),
            "enabled": _read_bool(reader),
            "guard_bot": _read_input_user(reader) if flags & (1 << 1) else None,
        })
    elif constructor_id == MESSAGES_EDIT_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_edit_chat_default_banned_rights", {
            "peer": _read_input_peer(reader),
            "banned_rights": _read_chat_banned_rights(reader),
        })
    elif constructor_id == MESSAGES_SET_CHAT_AVAILABLE_REACTIONS_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_set_chat_available_reactions", {
            "peer": _read_input_peer(reader),
            "available_reactions": _read_chat_reactions(reader),
            "reactions_limit": reader.int32() if flags & 1 else None,
            "paid_enabled": _read_bool(reader) if flags & 2 else None,
        })
    elif constructor_id == MESSAGES_EXPORT_CHAT_INVITE_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_export_chat_invite", {
            "legacy_revoke_permanent": bool(flags & (1 << 2)),
            "request_needed": bool(flags & (1 << 3)),
            "peer": _read_input_peer(reader),
            "expire_date": reader.int32() if flags & 1 else None,
            "usage_limit": reader.int32() if flags & (1 << 1) else None,
            "title": reader.bytes().decode("utf-8") if flags & (1 << 4) else None,
            "subscription_pricing": None if not flags & (1 << 5) else (_ for _ in ()).throw(
                TLDecodeError("Paid invite subscriptions are not supported")
            ),
        })
    elif constructor_id == MESSAGES_EDIT_EXPORTED_CHAT_INVITE_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_edit_exported_chat_invite", {
            "revoked": bool(flags & (1 << 2)),
            "peer": _read_input_peer(reader),
            "link": reader.bytes().decode("utf-8"),
            "expire_date": reader.int32() if flags & 1 else None,
            "expire_date_provided": bool(flags & 1),
            "usage_limit": reader.int32() if flags & (1 << 1) else None,
            "usage_limit_provided": bool(flags & (1 << 1)),
            "request_needed": _read_bool(reader) if flags & (1 << 3) else None,
            "title": reader.bytes().decode("utf-8") if flags & (1 << 4) else None,
            "title_provided": bool(flags & (1 << 4)),
        })
    elif constructor_id == CHANNELS_CHECK_USERNAME_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_check_username", {
            "channel": _read_input_channel(reader),
            "username": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == CHANNELS_UPDATE_USERNAME_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_update_username", {
            "channel": _read_input_channel(reader),
            "username": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == CHANNELS_DEACTIVATE_ALL_USERNAMES_CONSTRUCTOR:
        request = TLRequest(constructor_id, "channels_deactivate_all_usernames", {
            "channel": _read_input_channel(reader),
        })
    elif constructor_id == MESSAGES_TOGGLE_NO_FORWARDS_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_toggle_no_forwards", {
            "peer": _read_input_peer(reader),
            "enabled": _read_bool(reader),
            "request_msg_id": reader.int32() if flags & 1 else None,
        })
    elif constructor_id == MESSAGES_DELETE_REVOKED_EXPORTED_CHAT_INVITES_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_delete_revoked_exported_chat_invites", {
            "peer": _read_input_peer(reader),
            "admin": _read_input_user(reader),
        })
    elif constructor_id == MESSAGES_DELETE_EXPORTED_CHAT_INVITE_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_delete_exported_chat_invite", {
            "peer": _read_input_peer(reader),
            "link": reader.bytes().decode("utf-8"),
        })
    elif constructor_id == MESSAGES_GET_EXPORTED_CHAT_INVITES_CONSTRUCTOR:
        flags = reader.uint32()
        request = TLRequest(constructor_id, "messages_get_exported_chat_invites", {
            "revoked": bool(flags & (1 << 3)),
            "peer": _read_input_peer(reader),
            "admin": _read_input_user(reader),
            "offset_date": reader.int32() if flags & (1 << 2) else None,
            "offset_link": reader.bytes().decode("utf-8") if flags & (1 << 2) else None,
            "limit": reader.int32(),
        })
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
    elif constructor_id == MESSAGES_DELETE_MESSAGES_CONSTRUCTOR:
        flags = reader.uint32()
        if flags & ~1:
            raise TLDecodeError("Unsupported messages.deleteMessages optional fields")
        request = TLRequest(constructor_id, "messages_delete_messages", {
            "revoke": bool(flags & 1),
            "message_ids": [reader.int32() for _ in range(reader.vector_count())],
        })
    elif constructor_id == MESSAGES_EDIT_MESSAGE_CONSTRUCTOR:
        flags = reader.uint32()
        supported_flags = (1 << 1) | (1 << 11) | (1 << 16)
        if flags & ~supported_flags:
            raise TLDecodeError("Unsupported messages.editMessage optional fields")
        peer = _read_input_peer(reader)
        message_id = reader.int32()
        body = reader.bytes().decode("utf-8") if flags & (1 << 11) else None
        if body is None:
            raise TLDecodeError("messages.editMessage requires a text message")
        request = TLRequest(constructor_id, "messages_edit_message", {
            "peer": peer,
            "message_id": message_id,
            "body": body,
        })
    elif constructor_id == MESSAGES_FORWARD_MESSAGES_CONSTRUCTOR:
        flags = reader.uint32()
        supported_flags = (1 << 5) | (1 << 6) | (1 << 8) | (1 << 11) | (1 << 12) | (1 << 14) | (1 << 19)
        if flags & ~supported_flags:
            raise TLDecodeError("Unsupported messages.forwardMessages optional fields")
        request = TLRequest(constructor_id, "messages_forward_messages", {
            "from_peer": _read_input_peer(reader),
            "message_ids": [reader.int32() for _ in range(reader.vector_count())],
            "random_ids": [reader.int64() for _ in range(reader.vector_count())],
            "to_peer": _read_input_peer(reader),
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
    elif constructor_id == MESSAGES_GET_PAID_REACTION_PRIVACY_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_paid_reaction_privacy", {})
    elif constructor_id == MESSAGES_GET_AVAILABLE_REACTIONS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "messages_get_available_reactions", {"hash": reader.int32()})
    elif constructor_id == COMMUNITIES_GET_JOINED_COMMUNITIES_CONSTRUCTOR:
        request = TLRequest(constructor_id, "communities_get_joined_communities", {})
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
    elif constructor_id == ACCOUNT_GET_CONTENT_SETTINGS_CONSTRUCTOR:
        request = TLRequest(constructor_id, "account_get_content_settings", {})
    else:
        raise TLDecodeError(f"Unsupported TL constructor: 0x{constructor_id:08x}")
    if reader.remaining:
        raise TLDecodeError("Trailing data after TL request")
    return request


def encode_pong(*, message_id: int, ping_id: int) -> bytes:
    return encode_uint32(PONG_CONSTRUCTOR) + encode_int64(message_id) + encode_int64(ping_id)


def encode_help_app_config(*, config_hash: int = 0) -> bytes:
    """Return an empty but valid layer-228 application configuration object."""
    return (
        encode_uint32(HELP_APP_CONFIG_CONSTRUCTOR)
        + encode_int32(config_hash)
        + encode_uint32(JSON_OBJECT_CONSTRUCTOR)
        + encode_vector([])
    )


def encode_bool(value: bool) -> bytes:
    return encode_uint32(BOOL_TRUE_CONSTRUCTOR if value else BOOL_FALSE_CONSTRUCTOR)


def encode_account_content_settings(*, sensitive_enabled: bool = False, sensitive_can_change: bool = False) -> bytes:
    flags = (1 if sensitive_enabled else 0) | (2 if sensitive_can_change else 0)
    return encode_uint32(ACCOUNT_CONTENT_SETTINGS_CONSTRUCTOR) + encode_uint32(flags)


def encode_imported_contact(*, user_id: int, client_id: int) -> bytes:
    return encode_uint32(IMPORTED_CONTACT_CONSTRUCTOR) + encode_int64(user_id) + encode_int64(client_id)


def encode_contacts_imported_contacts(*, imported: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(CONTACTS_IMPORTED_CONTACTS_CONSTRUCTOR)
        + encode_vector(imported)
        + encode_vector([])
        + encode_vector_longs([])
        + encode_vector(users)
    )


def encode_contacts_found(*, my_results: Iterable[bytes], results: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(CONTACTS_FOUND_CONSTRUCTOR)
        + encode_vector(my_results)
        + encode_vector(results)
        + encode_vector([])
        + encode_vector(users)
    )


def encode_account_authorization(*, key_id: int, device_label: str, created_at: int, current: bool) -> bytes:
    flags = 1 if current else 0
    return (
        encode_uint32(ACCOUNT_AUTHORIZATION_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_int64(key_id if key_id < (1 << 63) else key_id - (1 << 64))
        + encode_tl_string(device_label)
        + encode_tl_string("Web")
        + encode_tl_string("IntelliGram")
        + encode_int32(0)
        + encode_tl_string("IntelliGram Web K")
        + encode_tl_string("self-hosted")
        + encode_int32(created_at)
        + encode_int32(created_at)
        + encode_tl_string("127.0.0.1")
        + encode_tl_string("Self-hosted")
        + encode_tl_string("")
    )


def encode_account_authorizations(*, authorizations: Iterable[bytes]) -> bytes:
    return encode_uint32(ACCOUNT_AUTHORIZATIONS_CONSTRUCTOR) + encode_int32(365) + encode_vector(authorizations)


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


def encode_help_nearest_dc(*, country: str, this_dc: int, nearest_dc: int) -> bytes:
    return (
        encode_uint32(NEAREST_DC_CONSTRUCTOR)
        + encode_tl_string(country)
        + encode_int32(this_dc)
        + encode_int32(nearest_dc)
    )


def encode_help_countries_list(*, countries: Iterable[bytes] = (), hash_value: int = 0) -> bytes:
    return encode_uint32(HELP_COUNTRIES_LIST_CONSTRUCTOR) + encode_vector(countries) + encode_int32(hash_value)


def encode_messages_affected_messages(*, pts: int, pts_count: int) -> bytes:
    return encode_uint32(MESSAGES_AFFECTED_MESSAGES_CONSTRUCTOR) + encode_int32(pts) + encode_int32(pts_count)


def encode_auth_logged_out() -> bytes:
    return encode_uint32(AUTH_LOGGED_OUT_CONSTRUCTOR) + encode_uint32(0)


def encode_messages_peer_settings(*, settings: bytes, chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return encode_uint32(MESSAGES_PEER_SETTINGS_CONSTRUCTOR) + settings + encode_vector(chats) + encode_vector(users)


def encode_messages_available_reactions(*, hash_value: int = 0, reactions: Iterable[bytes] = ()) -> bytes:
    """Return a layer-228 reaction catalogue; self-hosted instances may start empty."""

    return encode_uint32(MESSAGES_AVAILABLE_REACTIONS_CONSTRUCTOR) + encode_int32(hash_value) + encode_vector(reactions)


def encode_messages_chats(*, chats: Iterable[bytes] = ()) -> bytes:
    """Return the ordinary `messages.Chats` container used by communities discovery."""

    return encode_uint32(MESSAGES_CHATS_CONSTRUCTOR) + encode_vector(chats)


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


def encode_password_kdf_algo(*, salt1: bytes, salt2: bytes) -> bytes:
    """Encode the exact password KDF algorithm implemented by Web K SRP."""

    from intelligram.services.srp import G, P_BYTES

    return (
        encode_uint32(PASSWORD_KDF_ALGO_SRP_CONSTRUCTOR)
        + encode_tl_bytes(salt1)
        + encode_tl_bytes(salt2)
        + encode_int32(G)
        + encode_tl_bytes(P_BYTES)
    )


def encode_account_password(*, srp_id: int, salt1: bytes, salt2: bytes, srp_B: bytes) -> bytes:
    """Encode a password state consumed by the unmodified Web K PasswordCard."""

    algorithm = encode_password_kdf_algo(salt1=salt1, salt2=salt2)
    flags = 1 << 2  # has_password/current_algo/srp_B/srp_id
    return (
        encode_uint32(ACCOUNT_PASSWORD_CONSTRUCTOR)
        + encode_uint32(flags)
        + algorithm
        + encode_tl_bytes(srp_B)
        + encode_int64(srp_id)
        + algorithm  # new_algo is mandatory even when no password update is offered.
        + encode_uint32(SECURE_PASSWORD_KDF_ALGO_UNKNOWN_CONSTRUCTOR)
        + encode_tl_bytes(b"\x00" * 32)
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


def encode_user_profile_photo(*, photo_id: int, dc_id: int = 1) -> bytes:
    """Encode the Layer 228 metadata required to resolve a user's profile photo."""

    return (
        encode_uint32(USER_PROFILE_PHOTO_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(photo_id)
        + encode_int32(dc_id)
    )


def encode_user(*, user: dict[str, Any], self_user_id: int | None = None, contact: bool = False) -> bytes:
    user_id = int(user["id"])
    first_name = str(user.get("first_name") or "")
    last_name = str(user.get("last_name") or "")
    username = user.get("username")
    phone = user.get("phone")
    profile_photo_id = user.get("profile_photo_id")
    flags = 1  # access_hash
    if first_name:
        flags |= 1 << 1
    if last_name:
        flags |= 1 << 2
    if username:
        flags |= 1 << 3
    if phone:
        flags |= 1 << 4
    if profile_photo_id is not None:
        flags |= 1 << 5
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
    if flags & (1 << 5):
        result += encode_user_profile_photo(photo_id=int(profile_photo_id))
    return result


def encode_peer_user(*, user_id: int) -> bytes:
    return encode_uint32(PEER_USER_CONSTRUCTOR) + encode_int64(user_id)


def encode_peer_chat(*, chat_id: int) -> bytes:
    return encode_uint32(PEER_CHAT_CONSTRUCTOR) + encode_int64(chat_id)


def channel_access_hash(channel_id: int) -> int:
    """Return a deterministic non-zero access hash for an IntelliGram channel."""

    return (channel_id << 32) | 1


def encode_peer_channel(*, channel_id: int) -> bytes:
    return encode_uint32(PEER_CHANNEL_CONSTRUCTOR) + encode_int64(channel_id)


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


def encode_photo(
    *, photo_id: int, file_reference: bytes, date: int, size: int, dc_id: int = 1, width: int = 0, height: int = 0,
) -> bytes:
    return (
        encode_uint32(PHOTO_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(photo_id)
        + encode_int64((photo_id << 32) | 1)
        + encode_tl_bytes(file_reference)
        + encode_int32(date)
        + encode_vector([encode_photo_size(type_="m", width=width, height=height, size=size)])
        + encode_int32(dc_id)
    )


def encode_photos_photo(*, photo: bytes, users: Iterable[bytes]) -> bytes:
    return encode_uint32(PHOTOS_PHOTO_CONSTRUCTOR) + photo + encode_vector(users)


def encode_photo_empty(*, photo_id: int = 0) -> bytes:
    return encode_uint32(PHOTO_EMPTY_CONSTRUCTOR) + encode_int64(photo_id)


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


def encode_chat_banned_rights(*, flags: int, until_date: int = 0) -> bytes:
    return encode_uint32(CHAT_BANNED_RIGHTS_CONSTRUCTOR) + encode_uint32(flags) + encode_int32(until_date)


def encode_exported_chat_invite(
    *,
    link: str,
    admin_user_id: int,
    created_at: int,
    expire_date: int | None = None,
    usage_limit: int | None = None,
    usage: int = 0,
    request_needed: bool = False,
    permanent: bool = False,
    revoked: bool = False,
    title: str | None = None,
) -> bytes:
    flags = 0
    if revoked:
        flags |= 1
    if expire_date is not None:
        flags |= 1 << 1
    if usage_limit is not None:
        flags |= 1 << 2
    if usage_limit is not None:
        flags |= 1 << 3
    if permanent:
        flags |= 1 << 5
    if request_needed:
        flags |= 1 << 6
    if title is not None:
        flags |= 1 << 8
    return (
        encode_uint32(CHAT_INVITE_EXPORTED_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_tl_string(link)
        + encode_int64(admin_user_id)
        + encode_int32(created_at)
        + (encode_int32(expire_date) if expire_date is not None else b"")
        + (encode_int32(usage_limit) if usage_limit is not None else b"")
        + (encode_int32(usage) if usage_limit is not None else b"")
        + (encode_tl_string(title) if title is not None else b"")
    )


def encode_messages_exported_chat_invite(*, invite: bytes, users: Iterable[bytes] = ()) -> bytes:
    return encode_uint32(MESSAGES_EXPORTED_CHAT_INVITE_CONSTRUCTOR) + invite + encode_vector(users)


def encode_messages_exported_chat_invite_replaced(
    *, invite: bytes, new_invite: bytes, users: Iterable[bytes] = ()
) -> bytes:
    return (
        encode_uint32(MESSAGES_EXPORTED_CHAT_INVITE_REPLACED_CONSTRUCTOR)
        + invite
        + new_invite
        + encode_vector(users)
    )


def encode_messages_exported_chat_invites(
    *, count: int, invites: Iterable[bytes], users: Iterable[bytes] = ()
) -> bytes:
    return (
        encode_uint32(MESSAGES_EXPORTED_CHAT_INVITES_CONSTRUCTOR)
        + encode_int32(count)
        + encode_vector(invites)
        + encode_vector(users)
    )


def encode_reaction_emoji(*, emoticon: str) -> bytes:
    return encode_uint32(REACTION_EMOJI_CONSTRUCTOR) + encode_tl_string(emoticon)


def encode_chat_reactions(*, mode: str, allow_custom: bool = False, emoticons: Iterable[str] = ()) -> bytes:
    if mode == "none":
        return encode_uint32(CHAT_REACTIONS_NONE_CONSTRUCTOR)
    if mode == "all":
        return encode_uint32(CHAT_REACTIONS_ALL_CONSTRUCTOR) + encode_uint32(1 if allow_custom else 0)
    if mode == "some":
        return encode_uint32(CHAT_REACTIONS_SOME_CONSTRUCTOR) + encode_vector(
            [encode_reaction_emoji(emoticon=emoticon) for emoticon in emoticons]
        )
    raise ValueError("Unsupported reaction mode")


def encode_chat_full(*, chat_id: int, about: str, participants: bytes) -> bytes:
    return (
        encode_uint32(CHAT_FULL_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(chat_id)
        + encode_tl_string(about)
        + participants
        + encode_peer_notify_settings()
    )


def encode_channel(
    *,
    channel_id: int,
    title: str,
    username: str | None = None,
    participants_count: int,
    date: int,
    creator: bool,
    slowmode_enabled: bool = False,
    noforwards: bool = False,
    join_request_enabled: bool = False,
    default_banned_rights_flags: int | None = None,
    broadcast: bool = False,
    signatures: bool = False,
) -> bytes:
    flags = (1 << 13) | (1 << 17)
    if broadcast:
        flags |= 1 << 5
    else:
        flags |= 1 << 8
    if creator:
        flags |= 1
    if username:
        flags |= 1 << 6
    if signatures:
        flags |= 1 << 11
    if slowmode_enabled:
        flags |= 1 << 22
    if noforwards:
        flags |= 1 << 27
    if join_request_enabled:
        flags |= 1 << 29
    if default_banned_rights_flags is not None:
        flags |= 1 << 18
    return (
        encode_uint32(CHANNEL_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_uint32(0)
        + encode_int64(channel_id)
        + encode_int64(channel_access_hash(channel_id))
        + encode_tl_string(title)
        + (encode_tl_string(username) if username else b"")
        + encode_uint32(CHAT_PHOTO_EMPTY_CONSTRUCTOR)
        + encode_int32(date)
        + (encode_chat_banned_rights(flags=default_banned_rights_flags) if default_banned_rights_flags is not None else b"")
        + encode_int32(participants_count)
    )


def encode_channel_full(
    *,
    channel_id: int,
    about: str,
    participants_count: int,
    admins_count: int,
    slowmode_seconds: int = 0,
    reaction_mode: str | None = None,
    reaction_allow_custom: bool = False,
    reaction_emoticons: Iterable[str] = (),
    exported_invite: bytes | None = None,
    pts: int = 0,
) -> bytes:
    flags = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 6)
    if slowmode_seconds:
        flags |= 1 << 17
    if exported_invite is not None:
        flags |= 1 << 23
    if reaction_mode is not None:
        flags |= 1 << 30
    return (
        encode_uint32(CHANNEL_FULL_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_uint32(1)  # flags2: can_delete_channel
        + encode_int64(channel_id)
        + encode_tl_string(about)
        + encode_int32(participants_count)
        + encode_int32(admins_count)
        + encode_int32(0)  # read_inbox_max_id
        + encode_int32(0)  # read_outbox_max_id
        + encode_int32(0)  # unread_count
        + encode_photo_empty()
        + encode_peer_notify_settings()
        + (exported_invite if exported_invite is not None else b"")
        + encode_vector([])  # bot_info
        + (encode_int32(slowmode_seconds) if slowmode_seconds else b"")
        + encode_int32(pts)
        + (encode_chat_reactions(
            mode=reaction_mode,
            allow_custom=reaction_allow_custom,
            emoticons=reaction_emoticons,
        ) if reaction_mode is not None else b"")
    )


def encode_messages_chat_full(*, full_chat: bytes, chats: Iterable[bytes], users: Iterable[bytes]) -> bytes:
    return (
        encode_uint32(MESSAGES_CHAT_FULL_CONSTRUCTOR)
        + full_chat
        + encode_vector(chats)
        + encode_vector(users)
    )


def encode_chat(
    *,
    chat_id: int,
    title: str,
    participants_count: int,
    date: int,
    creator: bool = False,
    version: int = 1,
    default_banned_rights_flags: int | None = None,
) -> bytes:
    flags = 1 if creator else 0
    if default_banned_rights_flags is not None:
        flags |= 1 << 18
    return (
        encode_uint32(CHAT_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_int64(chat_id)
        + encode_tl_string(title)
        + encode_uint32(CHAT_PHOTO_EMPTY_CONSTRUCTOR)
        + encode_int32(participants_count)
        + encode_int32(date)
        + encode_int32(version)
        + (encode_chat_banned_rights(flags=default_banned_rights_flags) if default_banned_rights_flags is not None else b"")
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


def encode_message_reply_header(*, reply_to_message_id: int) -> bytes:
    return (
        encode_uint32(MESSAGE_REPLY_HEADER_CONSTRUCTOR)
        + encode_uint32(1 << 4)
        + encode_int32(reply_to_message_id)
    )


def encode_document_attribute_filename(*, file_name: str) -> bytes:
    return encode_uint32(DOCUMENT_ATTRIBUTE_FILENAME_CONSTRUCTOR) + encode_tl_string(file_name)


def encode_document_attribute_audio(*, attribute: dict[str, Any]) -> bytes:
    """Encode Layer 228 documentAttributeAudio, including the voice-note bit."""

    flags = 0
    title = attribute.get("title")
    performer = attribute.get("performer")
    waveform = attribute.get("waveform")
    if attribute.get("voice"):
        flags |= 1 << 10
    if isinstance(title, str) and title:
        flags |= 1
    if isinstance(performer, str) and performer:
        flags |= 1 << 1
    if isinstance(waveform, bytes) and waveform:
        flags |= 1 << 2
    return (
        encode_uint32(DOCUMENT_ATTRIBUTE_AUDIO_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_int32(max(0, int(attribute.get("duration") or 0)))
        + (encode_tl_string(title) if flags & 1 else b"")
        + (encode_tl_string(performer) if flags & (1 << 1) else b"")
        + (encode_tl_bytes(waveform) if flags & (1 << 2) else b"")
    )


def encode_document(*, media: dict[str, Any]) -> bytes:
    file_id = int(media["file_id"])
    attributes = [
        encode_document_attribute_filename(file_name=str(media.get("filename") or "attachment")),
    ]
    for attribute in media.get("attributes") or []:
        if isinstance(attribute, dict) and attribute.get("kind") == "audio":
            attributes.append(encode_document_attribute_audio(attribute=attribute))
    return (
        encode_uint32(DOCUMENT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(file_id)
        + encode_int64((file_id << 32) | 1)
        + encode_tl_bytes(f"intelligram-file:{file_id}".encode("ascii"))
        + encode_int32(int(media.get("date") or 0))
        + encode_tl_string(str(media.get("mime_type") or "application/octet-stream"))
        + encode_int64(int(media.get("size") or 0))
        + encode_int32(1)
        + encode_vector(attributes)
    )


def encode_message_media(media: dict[str, Any] | None) -> bytes | None:
    if not media:
        return None
    kind = str(media.get("kind") or "")
    file_id = int(media["file_id"])
    date = int(media.get("date") or 0)
    size = int(media.get("size") or 0)
    if kind == "photo":
        return (
            encode_uint32(MESSAGE_MEDIA_PHOTO_CONSTRUCTOR)
            + encode_uint32(1)
            + encode_photo(
                photo_id=file_id,
                file_reference=f"intelligram-file:{file_id}".encode("ascii"),
                date=date,
                size=size,
            )
        )
    if kind == "document":
        return (
            encode_uint32(MESSAGE_MEDIA_DOCUMENT_CONSTRUCTOR)
            + encode_uint32(1)
            + encode_document(media=media)
        )
    return None


def encode_message(
    *,
    message: dict[str, Any],
    recipient_peer: bytes,
    outgoing: bool,
    sender_peer: bytes | None = None,
) -> bytes:
    reply_to_message_id = message.get("reply_to_message_id")
    edited_at = message.get("edited_at")
    encoded_media = encode_message_media(message.get("media") if isinstance(message.get("media"), dict) else None)
    flags = (
        (1 << 8)
        | ((1 << 1) if outgoing else 0)
        | ((1 << 3) if reply_to_message_id is not None else 0)
        | ((1 << 9) if encoded_media is not None else 0)
        | ((1 << 15) if edited_at is not None else 0)
    )
    return (
        encode_uint32(MESSAGE_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_uint32(0)  # flags2
        + encode_int32(int(message["id"]))
        + (sender_peer if sender_peer is not None else encode_peer_user(user_id=int(message["sender_user_id"])))
        + recipient_peer
        + (encode_message_reply_header(reply_to_message_id=int(reply_to_message_id)) if reply_to_message_id is not None else b"")
        + encode_int32(int(message["sent_at"]))
        + encode_tl_string(str(message["body"]))
        + (encoded_media or b"")
        + (encode_int32(int(edited_at)) if edited_at is not None else b"")
    )


def encode_update_new_channel_message(*, message: bytes, pts: int, pts_count: int) -> bytes:
    return (
        encode_uint32(UPDATE_NEW_CHANNEL_MESSAGE_CONSTRUCTOR)
        + message
        + encode_int32(pts)
        + encode_int32(pts_count)
    )


def encode_messages_emoji_groups_not_modified() -> bytes:
    return encode_uint32(MESSAGES_EMOJI_GROUPS_NOT_MODIFIED_CONSTRUCTOR)


def encode_messages_all_stickers_not_modified() -> bytes:
    return encode_uint32(MESSAGES_ALL_STICKERS_NOT_MODIFIED_CONSTRUCTOR)


def encode_messages_sticker_set_not_modified() -> bytes:
    return encode_uint32(MESSAGES_STICKER_SET_NOT_MODIFIED_CONSTRUCTOR)


def encode_emoji_keywords_difference(*, lang_code: str, from_version: int, version: int) -> bytes:
    return (
        encode_uint32(EMOJI_KEYWORDS_DIFFERENCE_CONSTRUCTOR)
        + encode_tl_string(lang_code)
        + encode_int32(from_version)
        + encode_int32(version)
        + encode_vector([])
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


def encode_messages_dialogs_slice(
    *,
    count: int,
    dialogs: Iterable[bytes],
    messages: Iterable[bytes],
    chats: Iterable[bytes],
    users: Iterable[bytes],
) -> bytes:
    """Encode the count-bearing first page Web K expects for its virtual dialog list."""

    return (
        encode_uint32(MESSAGES_DIALOGS_SLICE_CONSTRUCTOR)
        + encode_int32(count)
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


def encode_messages_messages_slice(
    *, count: int, messages: Iterable[bytes], chats: Iterable[bytes], users: Iterable[bytes],
) -> bytes:
    """Encode a counted history result for messages.getHistory-style calls."""
    return (
        encode_uint32(MESSAGES_MESSAGES_SLICE_CONSTRUCTOR)
        + encode_uint32(0)  # flags: exact count, no next-rate or offset correction
        + encode_int32(count)
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


def encode_update_channel(*, channel_id: int) -> bytes:
    return encode_uint32(UPDATE_CHANNEL_CONSTRUCTOR) + encode_int64(channel_id)


def encode_update_chat_default_banned_rights(*, peer: bytes, flags: int, version: int = 1) -> bytes:
    return (
        encode_uint32(UPDATE_CHAT_DEFAULT_BANNED_RIGHTS_CONSTRUCTOR)
        + peer
        + encode_chat_banned_rights(flags=flags)
        + encode_int32(version)
    )


def encode_update_chat_participants(*, participants: bytes) -> bytes:
    return encode_uint32(UPDATE_CHAT_PARTICIPANTS_CONSTRUCTOR) + participants


def encode_update_edit_message(*, message: bytes, pts: int, pts_count: int) -> bytes:
    return encode_uint32(UPDATE_EDIT_MESSAGE_CONSTRUCTOR) + message + encode_int32(pts) + encode_int32(pts_count)


def encode_update_delete_messages(*, message_ids: Iterable[int], pts: int, pts_count: int) -> bytes:
    return encode_uint32(UPDATE_DELETE_MESSAGES_CONSTRUCTOR) + encode_vector_ints(message_ids) + encode_int32(pts) + encode_int32(pts_count)


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


def encode_updates_too_long() -> bytes:
    return encode_uint32(UPDATES_TOO_LONG_CONSTRUCTOR)


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


def encode_update_edit_channel_message(*, message: bytes, pts: int, pts_count: int) -> bytes:
    return (
        encode_uint32(UPDATE_EDIT_CHANNEL_MESSAGE_CONSTRUCTOR)
        + message
        + encode_int32(pts)
        + encode_int32(pts_count)
    )


def encode_chat_admin_rights(*, flags: int = 0x7FFFF) -> bytes:
    return encode_uint32(CHAT_ADMIN_RIGHTS_CONSTRUCTOR) + encode_uint32(flags)


def encode_channel_participant(*, user_id: int, date: int, role: str = "member") -> bytes:
    if role == "owner":
        return (
            encode_uint32(CHANNEL_PARTICIPANT_CREATOR_CONSTRUCTOR)
            + encode_uint32(0)
            + encode_int64(user_id)
            + encode_chat_admin_rights()
        )
    return (
        encode_uint32(CHANNEL_PARTICIPANT_CONSTRUCTOR)
        + encode_uint32(0)
        + encode_int64(user_id)
        + encode_int32(date)
    )


def encode_channels_channel_participants(
    *, count: int, participants: Iterable[bytes], chats: Iterable[bytes], users: Iterable[bytes]
) -> bytes:
    return (
        encode_uint32(CHANNELS_CHANNEL_PARTICIPANTS_CONSTRUCTOR)
        + encode_int32(count)
        + encode_vector(participants)
        + encode_vector(chats)
        + encode_vector(users)
    )


def encode_channels_channel_participant(
    *, participant: bytes, chats: Iterable[bytes], users: Iterable[bytes]
) -> bytes:
    return (
        encode_uint32(CHANNELS_CHANNEL_PARTICIPANT_CONSTRUCTOR)
        + participant
        + encode_vector(chats)
        + encode_vector(users)
    )


def encode_updates_channel_difference_empty(*, pts: int) -> bytes:
    return (
        encode_uint32(UPDATES_CHANNEL_DIFFERENCE_EMPTY_CONSTRUCTOR)
        + encode_uint32(1)
        + encode_int32(pts)
    )


def encode_chat_invite(
    *,
    title: str,
    participants_count: int,
    broadcast: bool,
    about: str = "",
) -> bytes:
    flags = 1
    if broadcast:
        flags |= 1 << 1
    else:
        flags |= 1 << 3
    if about:
        flags |= 1 << 5
    return (
        encode_uint32(CHAT_INVITE_CONSTRUCTOR)
        + encode_uint32(flags)
        + encode_tl_string(title)
        + (encode_tl_string(about) if about else b"")
        + encode_photo_empty()
        + encode_int32(participants_count)
        + encode_int32(0)
    )


def encode_messages_chat_invite_join_result_ok(*, updates: bytes) -> bytes:
    return encode_uint32(MESSAGES_CHAT_INVITE_JOIN_RESULT_OK_CONSTRUCTOR) + updates


def encode_messages_chat_admins_with_invites() -> bytes:
    return (
        encode_uint32(MESSAGES_CHAT_ADMINS_WITH_INVITES_CONSTRUCTOR)
        + encode_vector([])
        + encode_vector([])
    )


def encode_messages_chat_invite_importers() -> bytes:
    return (
        encode_uint32(MESSAGES_CHAT_INVITE_IMPORTERS_CONSTRUCTOR)
        + encode_int32(0)
        + encode_vector([])
        + encode_vector([])
    )
