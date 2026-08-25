# IntelliGram Visual Verification Matrix

This matrix defines the active visual QA scope for IntelliGram’s **currently implemented** Layer 228 / Web K compatibility surface. A passing encrypted regression only establishes a protocol baseline. A row is visually verified only after a normal SharedWorker Web K interaction shows the expected screen state, gateway behavior is free of protocol failures, storage reflects the outcome, and the relevant reload or reopen behavior holds.

> **Scope boundary:** this is not a claim of complete Telegram parity. Secret chats, calls, bots, payments, stories, premium features, cloud search, full multi-device synchronization, full permissions, and any server API not represented by IntelliGram’s current handlers remain separately unverified or unimplemented.

| Domain | Existing encrypted baseline | Required normal Web K visual scenarios | Current visual status |
|---|---|---|---|
| Bootstrap and startup | Config, language/country calls, startup entities, QR token | Fresh load, hard reload, startup without white screen, country selector opens and selects, no unresolved gateway error | **Fresh root dialog hydration/reopen verified for Saved Messages, channel, and owner-only group; white-screen and country-selector checks remain unverified in this pass** |
| Registration and password | No-SMS registration, password-backed account | Create controlled account, verify shell, reload persistence, profile name visible | **Previously exercised; repeat after bootstrap pass** |
| In-app login code | Durable app-code challenge and five-attempt lockout | Existing session receives a visible in-app notification/message; independent login enters code; reload after sign-in | **Unverified after visible-delivery changes** |
| Password fallback | `account.getPassword`, SRP check, encrypted authorization | Code card exposes **Can’t sign in?**, invalid password visibly rejects, valid password enters shell and survives reload | **Authenticated password-state response now visibly drives Two-Step Verification `On`; fallback sign-in card remains unverified** |
| Direct dialogs and ordinary sends | Send, replies, edits/deletes, forwards, read/typing, difference replay | Open dialogs; send text, retry behavior, reply; check finalization; open context menus; verify reload | **Saved Messages root/sidebar/historical reopen verified; edit/delete remain unverified visually** |
| Attachments and voice | Uploaded photo, document retrieval, voice metadata and history | Photo upload/display/download; voice record or client media pipeline; native voice bubble; reload; no `GET_FAILED` | **Voice verified through client media pipeline; photo visual path pending** |
| Profile and settings | Profile update, photo upload/download, full user | Edit name/about, upload profile photo, settings name/photo reload, self profile visible | **Self profile/settings, name edit, and reload persistence verified; bio, username, and photo remain unverified** |
| Contacts and private chats | Import, search, resolve username, create chat | Import controlled contact, search, open private chat, reload dialog and profile | **Unverified visually** |
| One-member groups | Owner-only create chat, participants, title/about, membership updates | Create a one-person group, send message, open group info, rename/about, reload | **Creation, send, title/about edit, Group Info, and reload verified; permission toggles/member-management controls remain unverified** |
| Channels | Creation, author identity, invites, username, slow mode, join request, protection | Create broadcast channel, post/reload identity, channel info, invite/public/private settings, slow mode and protection controls | **Post/reload, private IntelliGram invite-link display, owner title/about edits, and reload persistence verified; public/private changes and other settings remain unverified** |
| Message management | Durable edit/delete/forward | Context menu actions show correct availability, edit badge after reload, deletion/revoke and forward state | **Unverified visually; do not claim** |
| Devices and logout | Authorizations list/revoke, logout | Devices screen lists active session, revoke controlled remote session, logout returns to auth entry | **Unverified visually** |
| Updates and recovery | Difference and read-history replays | Refresh/hard reload after changes; no stuck pending transport; no duplicated durable messages | **Partly verified; repeat after each affected feature** |

## Execution Rules

Each scenario is performed on controlled local data only. The normal SharedWorker path is authoritative; `?noWorker=1` is never used as final evidence. Each defect record must distinguish the visible symptom, the exact gateway request or error, the durable database state, and reload behavior. Repairs require an encrypted regression where practicable, a complete test run, and a separate browser retest of the affected visual path.

## Evidence Log

The chronological evidence from the recent send/channel/voice pass is recorded in [`current_regression_verification.md`](current_regression_verification.md). New observations should be appended there without rewriting prior evidence.
