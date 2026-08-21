from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

CLIENT_ROOT = Path("/home/ubuntu/reference-sources/telegram-web-a/src")
SCHEMA_PATH = CLIENT_ROOT / "lib/gramjs/tl/static/api.tl"
SERVER_ROOT = Path("/home/ubuntu/reference-sources/teamgram-server")
OUTPUT = Path("/home/ubuntu/IntelliGram/ACTUAL_CLIENT_RPC_COVERAGE.md")

FUNCTION_MARKER = "---functions---"
FUNCTION_PATTERN = re.compile(r"^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)#")
REFERENCE_PATTERN = re.compile(r"GramJs\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)")
HANDLER_FILE_PATTERN = re.compile(r"(?:^|/)([a-z]+)\.([A-Za-z0-9_]+)_handler\.go$")


def pascal_case(value: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in value.split("_"))


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def main() -> None:
    schema_lines = read(SCHEMA_PATH).splitlines()
    try:
        function_lines = schema_lines[schema_lines.index(FUNCTION_MARKER) + 1:]
    except ValueError as exc:
        raise RuntimeError("Unable to locate the functions section in api.tl") from exc

    schema_methods: dict[tuple[str, str], str] = {}
    for line in function_lines:
        match = FUNCTION_PATTERN.match(line.strip())
        if not match:
            continue
        namespace, method = match.groups()
        schema_methods[(namespace, pascal_case(method))] = method

    usage: dict[tuple[str, str], set[str]] = defaultdict(set)
    for path in CLIENT_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        text = read(path)
        rel = str(path.relative_to(CLIENT_ROOT))
        for namespace, method_class in REFERENCE_PATTERN.findall(text):
            if (namespace, method_class) in schema_methods:
                usage[(namespace, method_class)].add(rel)

    handlers: dict[str, set[str]] = defaultdict(set)
    for path in SERVER_ROOT.rglob("*_handler.go"):
        rel = str(path.relative_to(SERVER_ROOT))
        match = HANDLER_FILE_PATTERN.search(rel)
        if match:
            namespace, method = match.groups()
            handlers[f"{namespace}.{method[:1].lower()}{method[1:]}"] .add(rel)

    exact, missing = [], []
    per_namespace = defaultdict(lambda: [0, 0])
    for (namespace, method_class), paths in sorted(usage.items()):
        method = schema_methods[(namespace, method_class)]
        key = f"{namespace}.{method}"
        handler_paths = sorted(handlers.get(key, set()))
        per_namespace[namespace][0] += 1
        if handler_paths:
            per_namespace[namespace][1] += 1
            exact.append((key, len(paths), sorted(paths), handler_paths))
        else:
            missing.append((key, len(paths), sorted(paths)))

    core_lazy = {"messages.getDialogs", "messages.getHistory", "messages.getMessages", "updates.getDifference", "updates.getChannelDifference", "messages.search", "messages.searchGlobal", "channels.getParticipants", "messages.getPeerDialogs"}
    core_security = {"auth.sendCode", "auth.signIn", "auth.signUp", "auth.checkPassword", "account.getPassword", "account.updatePasswordSettings", "account.getAuthorizations", "account.resetAuthorization", "auth.logOut"}
    core_groups = {"messages.createChat", "messages.addChatUser", "messages.deleteChatUser", "channels.createChannel", "channels.editTitle", "channels.editAbout", "channels.inviteToChannel", "channels.getParticipants", "channels.getFullChannel"}

    lines = [
        "# Actual Telegram Web A RPC Coverage",
        "",
        "This report reads every JavaScript/TypeScript source file in Telegram Web A’s `src/` tree. It filters `GramJs.Namespace.Class` references through the project’s own `api.tl` `---functions---` section, excluding API result/data classes from the request inventory. A ‘missing’ row means no Teamgram handler filename matched by name; it remains subject to manual source confirmation.",
        "",
        f"**Unique schema-defined RPCs referenced by Web A:** {len(usage):,}  ",
        f"**Direct Teamgram handler-name matches:** {len(exact):,}  ",
        f"**No direct Teamgram handler-name match:** {len(missing):,}",
        "",
        "## Namespace coverage",
        "",
        "| Namespace | Client RPCs | Direct Teamgram handlers | Filename-unmatched |",
        "|---|---:|---:|---:|",
    ]
    for namespace, (total, matched) in sorted(per_namespace.items()):
        lines.append(f"| `{namespace}` | {total} | {matched} | {total - matched} |")

    def obligation_section(title: str, keys: set[str]) -> None:
        lines.extend(["", f"## {title}", "", "| RPC | Used by Web A | Teamgram handler match |", "|---|---|---|"])
        seen = {f"{namespace}.{schema_methods[(namespace, method_class)]}": (namespace, method_class) for namespace, method_class in usage}
        for key in sorted(keys):
            item = seen.get(key)
            if not item:
                lines.append(f"| `{key}` | No static reference | — |")
                continue
            namespace, method_class = item
            handlers_found = handlers.get(key, set())
            lines.append(f"| `{key}` | Yes ({len(usage[item])} source file(s)) | {'Yes' if handlers_found else 'No static filename match'} |")

    obligation_section("Lazy-loading and synchronization obligations", core_lazy)
    obligation_section("Authentication and session-security obligations", core_security)
    obligation_section("Group and channel obligations", core_groups)

    lines.extend(["", "## Direct Teamgram handler matches", "", "| RPC | Web A source files | Teamgram handler files |", "|---|---:|---|"])
    for key, count, _, handler_paths in exact:
        handlers_preview = "<br>".join(f"`{p}`" for p in handler_paths[:2])
        lines.append(f"| `{key}` | {count} | {handlers_preview} |")

    lines.extend(["", "## Filename-unmatched client RPCs", "", "| RPC | Web A source files | Representative Web A paths |", "|---|---:|---|"])
    for key, count, paths in missing:
        preview = "<br>".join(f"`{p}`" for p in paths[:3])
        lines.append(f"| `{key}` | {count} | {preview} |")

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
