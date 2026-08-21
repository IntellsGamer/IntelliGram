from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

ROOTS = {
    "Telegram Web A": Path("/home/ubuntu/reference-sources/telegram-web-a"),
    "Teamgram Server": Path("/home/ubuntu/reference-sources/teamgram-server"),
}
OUTPUT = Path("/home/ubuntu/IntelliGram/REFERENCE_SOURCE_INVENTORY.md")
EXCLUDED_PARTS = {".git", "node_modules", "dist", "coverage", ".cache"}
TEXT_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".go", ".py", ".md", ".json", ".yaml", ".yml", ".sql", ".proto", ".tl", ".css", ".scss", ".html", ".sh", ".toml"}
KEYWORDS = {
    "auth": ("auth", "authorization", "login"),
    "updates": ("update", "difference", "pts"),
    "history": ("history", "pagination", "slice"),
    "secret_chats": ("secret", "encrypted chat", "e2e"),
    "groups_channels": ("channel", "group", "chat participant"),
    "media": ("upload", "download", "media", "document"),
    "transport": ("mtproto", "transport", "websocket", "abridged"),
}


def is_excluded(path: Path) -> bool:
    return any(part in EXCLUDED_PARTS for part in path.parts)


def walk_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file() and not is_excluded(path.relative_to(root))]


def safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def build_section(name: str, root: Path) -> str:
    files = walk_files(root)
    extensions = Counter((path.suffix.lower() or "[no extension]") for path in files)
    source_files = [path for path in files if path.suffix.lower() in TEXT_EXTENSIONS]
    directories = Counter()
    for path in files:
        rel = path.relative_to(root)
        if len(rel.parts) > 1:
            directories[rel.parts[0]] += 1
    keyword_hits: dict[str, list[str]] = defaultdict(list)
    for path in source_files:
        text = safe_read(path).lower()
        if not text:
            continue
        rel = str(path.relative_to(root))
        for category, terms in KEYWORDS.items():
            if any(term in text for term in terms):
                keyword_hits[category].append(rel)
    largest = sorted(source_files, key=lambda p: p.stat().st_size, reverse=True)[:25]
    lines = [
        f"## {name}",
        "",
        f"**Root:** `{root}`  ",
        f"**Files audited:** {len(files):,} total; {len(source_files):,} textual/code/configuration files.",
        "",
        "### Top-level layout",
        "",
        "| Directory | File count |",
        "|---|---:|",
    ]
    lines.extend(f"| `{directory}` | {count:,} |" for directory, count in directories.most_common())
    lines.extend([
        "",
        "### Dominant file types",
        "",
        "| Extension | Files |",
        "|---|---:|",
    ])
    lines.extend(f"| `{extension}` | {count:,} |" for extension, count in extensions.most_common(20))
    lines.extend([
        "",
        "### Largest textual files reviewed as high-complexity candidates",
        "",
        "| Path | KiB |",
        "|---|---:|",
    ])
    lines.extend(
        f"| `{path.relative_to(root)}` | {path.stat().st_size / 1024:.1f} |"
        for path in largest
    )
    lines.extend([
        "",
        "### Functional keyword coverage",
        "",
        "| Concern | Matching source files | Representative paths |",
        "|---|---:|---|",
    ])
    for category in KEYWORDS:
        matches = keyword_hits[category]
        samples = "<br>".join(f"`{path}`" for path in matches[:8]) or "—"
        lines.append(f"| {category.replace('_', ' ')} | {len(matches):,} | {samples} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    sections = [
        "# Reference Source Inventory",
        "",
        "This is a static source-tree inventory generated from local, read-only copies of Telegram Web A and Teamgram Server. It is a map for systematic protocol and feature-contract analysis; it does not execute third-party code.",
        "",
    ]
    for name, root in ROOTS.items():
        sections.append(build_section(name, root))
    OUTPUT.write_text("\n".join(sections), encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
