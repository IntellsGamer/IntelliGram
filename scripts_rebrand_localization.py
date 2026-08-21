from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT.parent / "reference-sources" / "telegram-web-k" / "src"
TARGET = ROOT / "client" / "src"

TYPE_SCRIPT_VALUE = re.compile(
    r"(?P<prefix>'(?:\\.|[^'\\])*'\s*:\s*)'(?P<value>(?:\\.|[^'\\])*)'"
)
STRINGS_VALUE = re.compile(
    r'(?P<prefix>"(?:\\.|[^"\\])*"\s*=\s*)"(?P<value>(?:\\.|[^"\\])*)"'
)

TARGETS = (
    (REFERENCE / "lang.ts", TARGET / "lang.ts", TYPE_SCRIPT_VALUE),
    (REFERENCE / "langSign.ts", TARGET / "langSign.ts", TYPE_SCRIPT_VALUE),
    (
        REFERENCE / "scripts" / "out" / "langPack.strings",
        TARGET / "scripts" / "out" / "langPack.strings",
        STRINGS_VALUE,
    ),
)


def rebrand_values(text: str, pattern: re.Pattern[str]) -> tuple[str, int]:
    replacements = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal replacements
        value = match.group("value")
        replacements += value.count("Telegram")
        return f"{match.group('prefix')}'{value.replace('Telegram', 'IntelliGram')}'" if pattern is TYPE_SCRIPT_VALUE else \
            f'{match.group("prefix")}"{value.replace("Telegram", "IntelliGram")}"'

    return pattern.sub(replace, text), replacements


def main() -> None:
    replacements = 0
    for source, destination, pattern in TARGETS:
        original = source.read_text(encoding="utf-8")
        rebranded, count = rebrand_values(original, pattern)
        destination.write_text(rebranded, encoding="utf-8")
        replacements += count
    if not replacements:
        raise SystemExit("No inherited product-name strings found")
    print(f"Rebranded {replacements} user-visible product-name occurrences while preserving localization keys")


if __name__ == "__main__":
    main()
