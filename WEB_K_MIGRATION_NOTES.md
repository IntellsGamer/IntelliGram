# IntelliGram Telegram Web K Migration Notes

## Purpose

**Telegram Web K is now the primary IntelliGram web client.** The existing Telegram Web A import remains useful only as a protocol reference until the Web K port is verified. The product remains a completely self-hosted messaging system: the Web K client must use only the IntelliGram Python MTProto gateway and must not retain Telegram production endpoints or public keys.

## Authoritative Source Baseline

| Item | Value |
|---|---|
| Source repository | [`TelegramOrg/Telegram-web-k`](https://github.com/TelegramOrg/Telegram-web-k) |
| Upstream lineage | `morethanwords/tweb` |
| Checked-out revision | `b21491cfdec248127cfb6a1e6617e26826021ff4` |
| License | GPL-3.0-only, retained in the derived client distribution |
| Client framework | TypeScript, Solid, Vite, Shared Worker architecture |
| Package manager | pnpm 11.16.0 |

Telegram Web K is an official GPL-3.0 browser client source with a Vite development server and production build pipeline.[1]

## Relevant MTProto Implementation Surface

| Concern | Web K source location | IntelliGram change |
|---|---|---|
| Data-center URL construction | `src/lib/mtproto/dcConfigurator.ts` | Replace `wss://…web.telegram.org/apiws` construction with the configured IntelliGram `/apiws` WebSocket URL; restrict routing to self-hosted DC 1. |
| Transport selection | `src/lib/mtproto/dcConfigurator.ts`, `src/lib/mtproto/transports/controller.ts` | Use native WebSocket plus abridged framing; remove production HTTP and obfuscated fallback routing from the self-hosted path. |
| Abridged codec | `src/lib/mtproto/transports/abridged.ts` | Keep the existing client codec; it already matches IntelliGram’s abridged WebSocket gateway framing. |
| Socket implementation | `src/lib/mtproto/transports/websocket.ts` | Retain binary WebSocket behavior and target the Python gateway’s binary `/apiws` endpoint. |
| RSA key registry | `src/lib/mtproto/rsaKeysManager.ts` | Replace embedded Telegram public keys with the RSA modulus/exponent fetched from IntelliGram’s `/v1/bootstrap`; verify the exposed fingerprint before registration. |
| Authorization exchange | `src/lib/mtproto/authorizer.ts` | Preserve Web K’s native RSA_PAD and DH authorization-key exchange; validate it against the Python gateway. |
| API/bootstrap worker | `src/lib/mainWorker/index.worker.ts`, `src/lib/appManagers/apiManager.ts` | Register the IntelliGram server key before the first MTProto connection from the shared worker. |

The existing Python gateway already supports binary WebSocket connection setup, abridged framing, `req_pq_multi`, `req_DH_params`, and `set_client_DH_params`. During this audit the server DH prime was byte-compared to Web K/Web A’s canonical embedded prime and corrected to an exact 512-hex-character match.

## Initial Compatibility Consequences

After the canonical DH prime correction, the live client completed the authorization-key exchange and emitted encrypted requests. The server now needs the next encrypted API coverage in priority order: `updates.getState`, exact `help.getConfig`, `auth.exportLoginToken`, phone authorization, and initial dialog/history/user RPCs. Web K’s more current schema will likely expand the compatibility surface beyond Web A; the required RPC coverage will be regenerated from the imported source after the port.

## Migration Rules

The import must retain Web K’s visible interaction model, layouts, state architecture, and GPL license notices. Product-facing strings, manifests, metadata, icons, and direct references to Telegram must be renamed to **IntelliGram**. Protocol identities must never cause a connection to Telegram-owned domains, TLS endpoints, or embedded public keys.

## References

[1]: https://github.com/TelegramOrg/Telegram-web-k "Telegram Web K official source repository"
