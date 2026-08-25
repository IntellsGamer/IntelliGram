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
