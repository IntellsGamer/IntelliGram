# IntelliGram

**IntelliGram** is a self-hosted messaging-system implementation track. It combines a Python server port inspired by Teamgram’s public Apache-2.0 MTProto server architecture with a planned GPL-3.0-compliant fork of Telegram Web A for the browser client. It is an independent system: it does not connect to Telegram’s production network, does not use Telegram application credentials, and is not affiliated with Telegram.

> The current repository contains a **tested server foundation** and the complete source-contract analysis that drives the remaining client and MTProto work. It is not yet a drop-in replacement for Telegram’s unpublished production backend.

## Current implementation

| Area | Delivered now | Next compatibility work |
|---|---|---|
| Persistent state | SQLite schema for users, sessions, auth-key records, peers, memberships, dialogs, messages, updates, and outbox events | PostgreSQL adapter, migrations, media metadata, and scalable services |
| Development authentication | Signed, revocable local sessions; production-safe configuration rejects development-login settings | MTProto authorization-key handshake, self-hosted phone/QR/passkey flows |
| Messaging core | Transactional group creation, role membership checks, idempotent sends, dialog paging, history paging, unread state, and durable update records | Full TL RPC dispatch, direct chats, edits/deletions/replies/reactions/forwards, permissions |
| Real time | WebSocket update fan-out and durable `/difference` recovery | MTProto update envelopes, `pts`/`seq`/channel-state compatibility |
| MTProto security | Python MTProto 2.0 AES-key derivation, AES-IGE, encrypted-envelope validation, self-owned RSA fingerprints, RSA_PAD, Diffie-Hellman auth-key generation, and initial TL service messages | Encrypted-session persistence, full TCP/WSS transport suite, API TL constructors, service messages, and RPC dispatch |
| Client | Complete Telegram Web A source-tree and RPC-contract inventory | GPL-3.0 source fork, endpoint/DC configuration port, IntelliGram branding, browser integration |

The test suite currently validates the cryptographic envelope primitives plus account/session, group, idempotent-message, lazy-history, and durable-update behavior.

## Source provenance and licensing

| Component | Repository | Use in IntelliGram | License |
|---|---|---|---|
| Telegram Web A | [Ajaxy/telegram-tt][1] | Browser UI/UX and client behavior reference; future fork base | GPL-3.0 |
| Teamgram Server | [teamgram/teamgram-server][2] | Python server-port reference for protocol and service behavior | Apache-2.0 |
| MTProto specification | [Telegram MTProto 2.0 documentation][3] | Public transport, authorization, encryption, framing, and TL semantics | Public specification |

The provenance and compatibility analysis is recorded in [`RESEARCH_NOTES.md`](RESEARCH_NOTES.md), [`REFERENCE_SOURCE_INVENTORY.md`](REFERENCE_SOURCE_INVENTORY.md), [`ACTUAL_CLIENT_RPC_COVERAGE.md`](ACTUAL_CLIENT_RPC_COVERAGE.md), and [`COMPATIBILITY_CONTRACT.md`](COMPATIBILITY_CONTRACT.md). When Telegram Web A source is brought into this repository, its GPL-3.0 license text, copyright notices, and corresponding source obligations will be preserved.

## Local run

Create an isolated environment, install the package in editable mode with its development dependencies, and start the local server. The default configuration listens only on `127.0.0.1:8080` and creates its local state under `./data/`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
INTELLIGRAM_DEVELOPMENT_MODE=true python -m intelligram
# Separate terminal: initial abridged MTProto TCP gateway on 127.0.0.1:10443
INTELLIGRAM_DEVELOPMENT_MODE=true python -m intelligram.mtproto.gateway
```

The operational health and bootstrap endpoints are then available at `GET /health` and `GET /v1/bootstrap`. The separate MTProto gateway validates Telegram Web A’s abridged transport tag and implements the public `req_pq_multi` → RSA_PAD → Diffie-Hellman → `dh_gen_ok` authorization-key exchange. Application RPCs are still being added above that key-exchange layer. Development-only endpoints under `/v1/development/` create test identities and sessions. They return `404` when `INTELLIGRAM_DEVELOPMENT_MODE=false`; do not expose a development-mode deployment to the Internet.

Run the complete test suite with:

```bash
PYTHONPATH=src python3 -m pytest -q
```

## Compatibility method

The browser client’s contract is not inferred from UI screenshots. A complete static scan of the Telegram Web A `src/` tree identified **438 schema-defined RPCs** actually referenced by the client. The implementation plan starts with secure bootstrap, authorization, dialog/history lazy loading, messages, updates/differences, membership and groups, then media. A server feature is only considered compatible when the forked client invokes the original-style TL method, receives the required constructor, restores state after reconnect, and passes an authorization and update-recovery integration test.

## Security boundary

MTProto 2.0 is documented as a client-server encrypted transport with a server RSA key, an authorization-key exchange, message IDs, server salts, AES-256-IGE, and strict replay/integrity checks. [3] IntelliGram implements these layers incrementally and will not substitute an invented crypto protocol. The current HTTP/WebSocket control interface is a local verification surface, not a replacement for the MTProto client interface.

Telegram Web A itself does not implement a functional Secret Chat UI flow; its encrypted-chat references are authorization/session flags. IntelliGram will therefore first deliver correctly encrypted MTProto cloud-chat transport. A true end-to-end Secret Chat extension requires separately designed and audited key management and will not be represented as complete until it is actually implemented.

## References

[1]: https://github.com/Ajaxy/telegram-tt "Telegram Web A source"
[2]: https://github.com/teamgram/teamgram-server "Teamgram Server source"
[3]: https://core.telegram.org/mtproto/description "MTProto 2.0 detailed description"
