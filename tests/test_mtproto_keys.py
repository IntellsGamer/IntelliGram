from __future__ import annotations

from pathlib import Path

from intelligram.mtproto.keys import load_or_create_server_keypair, mtproto_public_key_fingerprint


def test_server_keypair_is_persistent_and_has_stable_fingerprint(tmp_path: Path) -> None:
    private_path = tmp_path / "server_private.pem"
    public_path = tmp_path / "server_public.pem"
    first = load_or_create_server_keypair(private_path, public_path)
    second = load_or_create_server_keypair(private_path, public_path)
    assert private_path.exists()
    assert public_path.exists()
    assert first.private_key.key_size == 2048
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == mtproto_public_key_fingerprint(second.public_key)
