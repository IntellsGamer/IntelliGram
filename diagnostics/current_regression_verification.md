# Current Regression Verification

## 2026-08-25 — Native ordinary send reconciliation

A controlled normal SharedWorker Web K account sent `Web K duplicate-finalization probe 20260825A` to Saved Messages through the visible composer. The browser’s text extraction and a first visual frame appeared to contain the text twice. However, gateway evidence recorded **one** `messages_send_message` request, SQLite contained **one** durable message row (ID `2`, one client random ID), and the Web K SharedWorker message cache contained **one** real message with ID/MID `2` and final flags `{out: true, unread: true}`. The visible second occurrence is therefore not evidence of a server double insert; it requires separate DOM/render interpretation before claiming a duplication defect. The composer’s two overlapping contenteditables were also empty after finalization.

## 2026-08-25 — Native attachment UI attempt

The normal SharedWorker Saved Messages UI exposed its attach control and has one hidden multiple-file input. The browser upload bridge could not locate that hidden input by an interactive index, so the repository-owned `voice.ogg` fixture was **not** injected through the UI in this session. No media message was created by this attempt. The server-side encrypted voice regression independently exercised the same Layer 228 uploaded-document, document retrieval, and persisted-history paths; a separate browser-accessible native upload route is still required for visual voice-bubble confirmation.

## 2026-08-25 — Native broadcast channel setup

Using the normal SharedWorker Web K UI, a controlled account created `Web K Channel Identity Probe` with description `Controlled native channel author verification`. Web K opened the real broadcast channel at `#-2`, showed `1 subscriber`, rendered the native creation event, and exposed the standard Broadcast composer. The Add Subscribers panel remained open on the left after the one-member creation flow; no post has been sent yet in this entry.

## 2026-08-25 — Native broadcast post

A controlled post, `Native channel author probe 20260825B`, was sent through the normal Web K Broadcast composer. The visible channel timeline rendered the post without a personal **You** label, and the sidebar preview attributed it to `Web K Channel Identity Probe`. Gateway evidence recorded one `messages_send_message` request; SQLite has one durable row (`message_id=4`, `peer_id=2`, `sender_user_id=1`, peer kind `channel`). A direct `getMessageByPeer(-2, …)` cache probe resolved the self-peer cache rather than the channel cache, so it is not used as an author-identity assertion. The visible UI, gateway, and durable state support the repair; reload verification remains pending.

## 2026-08-25 — Native Web K voice rendering via client media pipeline

Because the browser upload bridge cannot target Web K’s hidden attachment input, a repository-owned OGG fixture was passed to Web K’s own `appMessagesManager.sendFile` media pipeline with `isVoiceMessage=true`, `duration=2`, and a controlled waveform. This is not a direct MTProto call. The normal SharedWorker UI then rendered the Saved Messages entry as **Voice message** with a visible **0:02** duration and native voice iconography; it did not render as a generic `audio.ogg` file. Gateway, durable metadata, download, and clean-reload checks remain pending in the next observation.

## 2026-08-25 — Native voice clean reload

A cache-busting full document reload into Saved Messages cleared the normal Web K in-memory view and rehydrated history from IntelliGram. The same media entry remained a native voice bubble with its play control and **0:02** duration. This confirms the persisted `documentAttributeAudio` metadata is usable after reload. A failed keyboard reload shortcut inserted a single `R` into the controlled composer; it was removed through the active composer’s ordinary input event, and no message was sent by that cleanup.

## 2026-08-25 — Fresh-load dialog-list anomaly

After the browser session reset to `about:blank`, reopening the normal Web K origin produced a clean shell without a white screen. However, the sidebar listed the persisted broadcast channel while **Saved Messages was absent**, despite the controlled account having durable Saved Messages text and voice rows earlier in the session. This is a reproducible-looking dialog hydration/listing anomaly and is under investigation; it must not be treated as a successful fresh-load result.

### Confirmation

A second cache-busting root load was allowed to settle and still showed only the broadcast channel. A cache-busting direct load to `#1` immediately restored Saved Messages, its text history, and native 0:02 voice bubble. The defect is therefore **root dialog-list hydration** rather than data loss or message-history failure.

### Root dialog-list diagnosis

A live raw `messages.getDialogs` request with Web K’s normal `folder_id=0`, empty offsets, and `limit=20` returned `messages.dialogsSlice` with `count=2`, two dialogs (`peerUser(user_id=1)` and `peerChannel(channel_id=2)`), two top messages, one user, and one chat. The server response is structurally complete. The live client dialog store also reports entries for peer IDs `1` and `-2`, while the root visual list renders only the channel. This narrows the defect to Web K’s folder/index classification or UI projection of the stored self dialog; it is not data loss, getDialogs response truncation, or history hydration failure.

### Client-storage inspection note

The page-to-worker bridge exposes `dialogsStorage.getFolderDialogs(...)` as a `Promise`, even though the imported source returns an array in-worker. Two un-awaited probes therefore failed with `map is not a function`; this is a bridge-shape limitation, not new client evidence. The raw server response and visual root omission remain the relevant facts.

### Root folder projection diagnosis

Awaited client inspection shows `getFolderDialogs(0)` contains only the channel. `getDialogOnly(1)` and `getDialogOnly(-2)` both exist and each reports `folder_id=0`; the self top message is finalized (`{out: true, unread: true}`), so temporary-send state is not the cause. The client’s `canSaveDialog` predicate accepts the self user. The page-to-worker bridge does not expose the internal root index values, so no additional conclusion is drawn from that inspection. The visible root omission is confirmed and requires a compatibility repair or a narrowly documented client-side projection adjustment.

### Final root-list diagnostic

Clearing only the controlled client’s local dialog cache and reloading the normal 20-item dialog page still returned one visible channel despite a server count of two. Calling Web K’s own `processDialogForFilter(selfDialog, filter0)` reported `changed=true` but left `getFolderDialogs(0)` with only the channel. This establishes a root self-dialog index/projection quirk in the current client behavior. A narrow Web K source repair is required to assign a visible root index to the self dialog when normal filtering fails.

### Root-list guard retest

After the client guard was built, a fresh root load created a second sidebar row where Saved Messages was previously absent. However, after settling it remained an unlabeled skeleton rather than a usable Saved Messages item. The guard changes the projection state but does not complete entity/title hydration, so this is **not** a verified fix and further diagnosis continues.

### Root dialog-list repair verified

A fresh cache-busting root load in normal SharedWorker mode now visibly renders **both** durable sidebar dialogs: `Saved Messages` (with the expected `Voice message` preview) and `Web K Channel Identity Probe`. Selecting the actual `#1` Saved Messages sidebar row navigated normally and opened its three-message history, including the persisted `0:02` native voice bubble. The repair is a narrow imported-Web-K storage reconciliation: it obtains the canonical self dialog from Web K's own account/dialog stores and inserts it into the real root folder array with a valid normal dialog index, including when a pre-existing root entry lacks an index. This is not a substitute UI or server-data rewrite.

A second independent cache-busting root load after reopening Saved Messages remained visually correct. Its live SharedWorker root folder contained exactly peer `1` (Saved Messages, top message `5`) and peer `-2` (the broadcast channel, top message `4294967300`), both with `folder_id=0`.

### Post-repair ordinary-send visual probe

Through the visible Saved Messages composer, a controlled `SharedWorker post-root repair text probe 20260825C` was sent after the root-list repair. The UI immediately showed one latest message bubble and one sidebar preview, while the composer returned to its empty `Message` state. The gateway recorded one new `messages_send_message` request with no observed protocol failure. Read-only SQLite inspection found exactly one corresponding durable row: `id=6`, `peer_id=1`, `sender_user_id=1`, and one client random ID. A cache-busting normal SharedWorker reload at `#1` retained that text exactly once and preserved the native `0:02` voice bubble. The header initially remained at `3 messages` despite four persisted/rendered message bubbles (anchor, prior text, voice, and the new probe). A direct normal Web K `messages.getHistory` call decoded all four records, so the stale label was traced to the uncounted `messages.messages` response. IntelliGram now returns the standard exact-count `messages.messagesSlice` result. After gateway restart and a further cache-busting normal SharedWorker reload, the header visibly corrected to **`4 messages`** while retaining all four bubbles and the native voice rendering.
