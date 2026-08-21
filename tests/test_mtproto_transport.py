from __future__ import annotations

import pytest

from intelligram.mtproto.transport import AbridgedFrameBuffer, TransportError, encode_abridged_packet


def test_abridged_frame_round_trip_with_connection_tag_and_fragmentation() -> None:
    first = b"\x01\x00\x00\x00"
    second = b"\x02\x00\x00\x00"
    stream = b"\xef" + encode_abridged_packet(first) + encode_abridged_packet(second)
    decoder = AbridgedFrameBuffer(require_tag=True)
    assert decoder.feed(stream[:3]) == []
    assert decoder.feed(stream[3:8]) == [first]
    assert decoder.feed(stream[8:]) == [second]


def test_abridged_frame_uses_long_header_after_126_words() -> None:
    payload = b"a" * (127 * 4)
    encoded = encode_abridged_packet(payload)
    assert encoded[:1] == b"\x7f"
    decoder = AbridgedFrameBuffer()
    assert decoder.feed(encoded) == [payload]


def test_abridged_frame_rejects_invalid_tag_and_alignment() -> None:
    with pytest.raises(TransportError):
        encode_abridged_packet(b"abc")
    decoder = AbridgedFrameBuffer(require_tag=True)
    with pytest.raises(TransportError):
        decoder.feed(b"\x00")
