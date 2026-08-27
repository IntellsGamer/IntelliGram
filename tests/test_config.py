from __future__ import annotations

from pathlib import Path

import pytest

from intelligram.config import Settings


def test_admin_owner_phone_loads_and_normalizes_from_local_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("INTELLIGRAM_ADMIN_PHONE", raising=False)
    monkeypatch.delenv("INTELLIGRAM_PUBLIC_LINK_BASE_URL", raising=False)
    (tmp_path / ".env").write_text(
        "INTELLIGRAM_ADMIN_PHONE=1 (555) 000-0901\n"
        "INTELLIGRAM_PUBLIC_LINK_BASE_URL=https://links.example.intelligram.test/tenant\n",
        encoding="utf-8",
    )

    settings = Settings.from_environment()

    assert settings.admin_owner_phone == "+15550000901"
    assert settings.public_link_base_url == "https://links.example.intelligram.test/tenant"


def test_public_link_base_url_is_normalized_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTELLIGRAM_PUBLIC_LINK_BASE_URL", "https://links.example.intelligram.test/tenant/")

    settings = Settings.from_environment()

    assert settings.public_link_base_url == "https://links.example.intelligram.test/tenant"


@pytest.mark.parametrize(
    "value",
    [
        "links.example.intelligram.test",
        "ftp://links.example.intelligram.test",
        "https://links.example.intelligram.test/?unexpected=value",
        "https://links.example.intelligram.test/#fragment",
    ],
)
def test_public_link_base_url_requires_absolute_clean_http_url(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("INTELLIGRAM_PUBLIC_LINK_BASE_URL", value)

    with pytest.raises(ValueError, match="INTELLIGRAM_PUBLIC_LINK_BASE_URL"):
        Settings.from_environment()
