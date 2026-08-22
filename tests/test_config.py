from __future__ import annotations

import pytest

from intelligram.config import Settings


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
