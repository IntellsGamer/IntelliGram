# IntelliGram Research Notes

## Repository audit — 2026-08-21

The requested repository is `IntellsGamer/IntelliGram`, a public GitHub repository on the `main` branch. Its current initial commit is `ac2c72b0014e6d1e02cc0a9f82443b85361e12e6`. The only tracked project file is a one-line `README.md` containing the title `IntelliGram`; there is no existing client, server, build system, license, or configuration.

## Verified Telegram Web source candidate

The official source candidate for an authentic Telegram Web UI/UX reference is **Telegram Web A** at `https://github.com/Ajaxy/telegram-tt`. The repository itself states that it won Telegram’s Lightweight Client Contest and is available at `https://web.telegram.org/a`. It describes a TypeScript client built on Teact and a custom GramJS MTProto implementation, and labels the repository **GPL v3**.

### Porting implications

Telegram Web A is client code written for Telegram’s proprietary backend and MTProto ecosystem. It cannot provide a self-hosted Telegram server. Reusing or adapting its source requires GPL-3.0-compatible distribution, preservation of copyright and license notices, disclosure of corresponding source for distributed modified versions, and clear non-affiliation branding. A Python IntelliGram backend must be an independently implemented server rather than a literal port of Telegram’s proprietary server, which is not distributed as open source.

## Initial project boundary

The target should become an independently networked IntelliGram product: a Python server with its own protocol and data model, plus a web client whose visual/interaction behavior is studied from Telegram Web A source and adapted under GPL-3.0 compliance. It must not claim Telegram compatibility, use Telegram API credentials, or connect to Telegram’s production network.

## Sources

1. IntelliGram repository: https://github.com/IntellsGamer/IntelliGram
2. Telegram Web A source: https://github.com/Ajaxy/telegram-tt
3. Telegram Web A deployment: https://web.telegram.org/a
4. Telegram apps index: https://telegram.org/apps


## Official source-publication confirmation

Telegram’s official applications page states that its published apps are open source and identifies both **Telegram Web A** and **Telegram Web K** as GPL-3.0 web clients. It identifies the Web A source as `Ajaxy/telegram-tt`. The official FAQ’s table of contents separately includes the questions “Can I get Telegram’s server-side code?” and “Can I use my own server?”, while its linked public-source section refers to client applications and APIs. The frontend source is therefore suitable as a GPL-3.0 reference and adaptation base, but it is not evidence of an open-source production backend.

Source: https://telegram.org/apps and https://telegram.org/faq#q-can-i-get-telegrams-server-side-code

## Teamgram server assessment

**Teamgram Server** (`https://github.com/teamgram/teamgram-server`) is an active, unofficial, self-hosted MTProto 2.0 server written in Go and released under the **Apache License 2.0**. Its repository describes support for abridged, intermediate, padded-intermediate, and full MTProto transports; Telegram API layer 228; private chats; basic groups; contacts; and web functionality. It lists patched Android, iOS, and TDesktop clients rather than stock Telegram Web A.

Its deployed architecture is not a small standalone daemon. It depends on MySQL, Redis, etcd, Kafka, MinIO, FFmpeg, and multiple Go services, and its current default verification code is documented as `12345` (which must never be retained in a production deployment). The repository reports a current commit dated 2026-08-04 and exposes architecture, protocol, and security specifications.

### Python-port suitability

Teamgram is a strong **behavioral and protocol reference** for a Python implementation because its Apache-2.0 licensing permits reuse with preservation of notices. However, a literal line-by-line translation would produce a Python service mesh with a significant operational footprint and would not automatically make Telegram Web A compatible. A Python port should therefore keep the public MTProto/TL contract, state updates, authorization and data semantics, while initially consolidating the service topology behind explicit interfaces that can be split into services later. Compatibility must be tested against the actual target client build rather than inferred from Teamgram’s claim.

Source: https://github.com/teamgram/teamgram-server

## Complete client/source-contract inventory

A static audit read the entire Telegram Web A `src/` tree: **3,045 files total**, including **925 TSX**, **856 TypeScript**, and **515 SCSS** files. Telegram Web A is not a REST application. Its API worker creates a GramJS `TelegramClient` using a callback-backed session, connects via secure WebSocket by default, completes authorization through the MTProto flow, invokes TL RPC constructors, persists local entities, and processes asynchronous updates through a difference-recovery manager.

The client’s configuration encodes concrete lazy-loading contracts: 40/60 message history rows per first slice depending on viewport, 25/30 chat rows per UI slice, 100 dialogs per chat-list fetch, 42 items for shared/chat media and message search, and a 30-member initial participant slice with a 200-member subsequent load. The server must return the corresponding TL `messages.*`, `channels.*`, and `updates.*` result forms and advance `pts`, `qts`, `seq`, and per-channel update state correctly. `messages.getDialogs`, `messages.getHistory`, `messages.getMessages`, `messages.getPeerDialogs`, `messages.search`, `messages.searchGlobal`, `updates.getDifference`, and `updates.getChannelDifference` all have direct Teamgram handler matches.

A schema-aware scan read every JavaScript/TypeScript source file and found **438 distinct schema-defined RPCs** used by Web A. Teamgram contains directly named handlers for **146**; many remaining RPCs are current Telegram commercial/platform features (payments, stories, premium, AI compose, stats, phone/calls, and bot ecosystems) that require separate implementation rather than being present in the server reference. The detailed generated reports are `ACTUAL_CLIENT_RPC_COVERAGE.md`, `CLIENT_SERVER_RPC_CONTRACT.md`, and `REFERENCE_SOURCE_INVENTORY.md`.

### Secret-chat boundary

Web A contains only a small number of incidental `EncryptedChat` / `SecretChat` references outside its embedded GramJS library. The reviewed references expose the *authorization setting* for allowing encrypted chats, not an end-to-end secret-chat UI or workflow. Consequently, an exact port of **Telegram Web A** does not require a functional Secret Chat UI in its initial compatibility contract; adding one would be a separate product/client capability requiring an end-to-end key-management design. This is distinct from the MTProto client-server encryption required for ordinary cloud-chat transport.

### Deployment and client reconfiguration

Web A currently reads production Telegram API credentials and data-center settings from environment variables and GramJS configuration. An IntelliGram build must replace that provisioning with its own application identity, self-hosted data-center descriptors, RSA fingerprints, server URLs, branding, asset metadata, and link domains. Teamgram similarly expects patched client network configuration. Neither source base will transparently point an unmodified public Telegram client at a new server without this controlled reconfiguration.

## Authorization-key handshake implementation evidence

Telegram Web A’s `Authenticator.ts` implements the public MTProto authorization sequence as `req_pq_multi` → client factorization of a bounded 63-bit `pq` → RSA_PAD-encrypted `p_q_inner_data_dc` → `server_DH_params_ok` → AES-IGE-protected `server_DH_inner_data` → `set_client_DH_params` → `dh_gen_ok`. It validates client/server nonces, a public DH value, a server-provided safe 2048-bit prime, SHA-1 integrity values, and the derived `new_nonce_hash1`. Its nonce AES derivation is `SHA1(new_nonce || server_nonce) || SHA1(server_nonce || new_nonce)[:12]` for the key and `SHA1(server_nonce || new_nonce)[12:20] || SHA1(new_nonce || new_nonce) || new_nonce[:4]` for the IV.

Teamgram’s `app/interface/gnetway/internal/server/gnet/handshake.go` implements the same public state progression and establishes a server salt by XORing the first eight bytes of `new_nonce` and `server_nonce`. It confirms the server architecture’s responsibility for persisting the resulting authorization key after DH completion. Teamgram’s file header identifies the reference implementation as Apache-2.0.

The Python port now has a fully tested local simulation of this public handshake, including the proper MTProto bare-RSA-public-key fingerprint. The fingerprint serialization was checked against Telegram Web A’s built-in key: TL-encode the modulus and exponent as bare `bytes` fields, SHA-1 hash, and interpret the final eight digest bytes little-endian; the expected embedded fingerprint `-3414540481677951611` was reproduced.

Sources: https://core.telegram.org/mtproto/auth_key ; local source snapshot of https://github.com/Ajaxy/telegram-tt (`src/lib/gramjs/network/Authenticator.ts`, `src/lib/gramjs/Helpers.ts`, `src/lib/gramjs/crypto/AuthKey.ts`, `src/lib/gramjs/crypto/Factorizator.ts`) ; local source snapshot of https://github.com/teamgram/teamgram-server (`app/interface/gnetway/internal/server/gnet/handshake.go`).
