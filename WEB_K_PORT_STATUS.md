# IntelliGram Web K Port Status

## 2026-08-21 — Initial Web K client import and routing work

The official `TelegramOrg/Telegram-web-k` source at commit `b21491cfdec248127cfb6a1e6617e26826021ff4` is now the primary `client/` directory. The former IntelliGram Web A worktree is preserved outside the repository under `/home/ubuntu/reference-sources/intelligram-web-a-intelligram-worktree` as a protocol reference.

The Web K client has been rebranded with the IntelliGram Vite title/metadata, PWA manifests, the IntelliGram application icon set, localized product strings, and a package identity of `intelligram-web-k`. Its development server is running on port 1234; the Python MTProto gateway remains on port 8080.

The client transport work replaces Web K’s production data-center lists, HTTP routes, WebSocket hostname construction, and embedded Telegram RSA keys with a single DC 1 route to the configured IntelliGram `/apiws` endpoint. The client fetches `/v1/bootstrap` and validates the signed MTProto RSA fingerprint before the authorization exchange. A native non-obfuscated abridged WebSocket transport now sends the `0xEF` tag required by the Python gateway.

TypeScript validation passes after these changes. During the first browser check, the document title is `IntelliGram`, but the Web K page is still blank during its cold Vite module load. There is no browser console exception and no new request in the Python gateway log yet. The next verification step is to wait for module completion or move to the production bundle if Vite’s unbundled cold-load behavior prevents the login screen from rendering.

## 2026-08-21 — End-to-end QR initialization verified

The bundled IntelliGram Web K client now completes a fresh self-hosted MTProto authorization-key handshake against the Python gateway. The verified sequence is `req_pq_multi`, `req_DH_params`, `set_client_DH_params`, first encrypted initialization, `help.getConfig`, `updates.getState`, and `auth.exportLoginToken`.

The server-side fixes required for this milestone were the canonical Telegram DH prime, unsigned 64-bit server-salt representation, a bootstrap RSA-key field mapping from `modulus_hex`/`exponent_hex`, WebSocket-only transport selection, and the `updates.State` response. The QR login token is now visibly rendered in the imported Telegram Web K interface. The public asset copy step is enabled for production builds, and the QR centre mark uses the IntelliGram application icon.

The next protocol work is authorization completion: a scanned token must become `auth.loginTokenSuccess` carrying `auth.Authorization`; the phone flow must support no-SMS account creation and an existing-session in-app approval path for later device login.

## 2026-08-21 — SMS-free native Web K registration verified

The actual bundled IntelliGram Web K phone-login path was verified against the Python MTProto gateway. Entering a fresh syntactically valid phone identifier immediately transitioned from the preserved Web K phone card to the preserved sign-up card without SMS. The sign-up card now collects first name, optional last name, and an IntelliGram password. Submitting the form created the account through encrypted `auth.sendCode` and `auth.signUp` calls and entered the Web K messaging shell successfully.

The password is stored server-side using scrypt. The separate REST/self-hosted account service now supports password login and a durable, five-minute six-digit device-login code delivered as `updateIntelliGramLoginCode` to active existing sessions, with five-attempt invalidation. The corresponding API and MTProto adapter tests pass.

## 2026-08-21 — Production preview icon assets repaired

The missing interface icons were not a Web K component regression. The production build had previously omitted `public/` assets, then the preview service worker cached the HTML fallback response for the missing `tgico` font files. Public asset copying is now enabled in Vite, the bundled preview contains the Web K font and SVG assets, and the stale localhost service-worker caches were cleared. Chromium confirms `tgico` as loaded, and the preview visibly renders the icon font and chat-background assets again.

## 2026-08-21 — Clean-session checkpoint and persisted MTProto key restoration

A browser session that retained a pre-persistence authorization key continued to receive `AUTH_KEY_UNREGISTERED` after the gateway was restarted. This did not invalidate the restart design: that legacy key was created before the database held its raw MTProto key material. Schema v3 now persists `auth_keys.key_material` and `auth_keys.server_salt`, and FastAPI startup restores valid persisted entries into the shared encrypted-session registry. Automated coverage confirms the restoration behavior.

The browser’s local storage, session storage, service-worker registrations, caches, and IndexedDB have been cleared. A fresh session at `http://127.0.0.1:1235/?build=fresh-1787328650146` now reaches the branded IntelliGram QR / phone-login page with a rendered QR canvas. The next sign-in will establish a clean persistent authorization key against the restarted gateway.

The active implementation batch is now the first signed-in binary TL API surface required by Telegram Web K: real `user` objects, contacts, dialogs, message history, and outgoing text messages.

## 2026-08-21 — Core signed-in TL implementation staged for live verification

The local gateway now exposes native layer-228 binary TL handlers for `users.getUsers`, `users.getFullUser`, `contacts.getContacts`, `messages.getDialogs`, `messages.getPeerDialogs`, `messages.getHistory`, `messages.sendMessage`, `account.updateStatus`, and `account.getPrivacy`. The implementation includes full modern `user` records, direct-peer persistence (including Saved Messages), dialogs, text messages, update containers, contact data, and a minimal full-user profile response. The resulting encrypted adapter coverage passes together with all prior protocol tests.

Because the browser had produced another unauthorised, in-memory handshake key immediately before the gateway restart, its state was cleared once more. The current local browser session at `?build=core-rpcs-1787329417463` presents the branded QR / phone login screen with a freshly generated QR code, ready to establish and persist a key against the live implementation.

## 2026-08-21 — Live phone-flow checkpoint

The clean live browser session successfully transitioned from the QR card to the preserved Web K phone-login card. The visible form separates country selection from the phone-number field. The next verification operation inspects the concrete client-side inputs so the no-SMS registration test can be completed against the current signed-in RPC gateway.

The imported Web K phone card uses custom `contenteditable` controls rather than native `<input>` elements. The first contenteditable element is the country selector/text field and the second, with `inputmode="decimal"`, is the phone field. The previous coordinate-only input did not persist because country and phone must be supplied separately through these controls.

The country selector opened correctly, but programmatic entry into its custom contenteditable search field closed the list without retaining a selection. This is a client-control targeting detail rather than a server protocol failure; the next check will use the rendered element metadata to select the intended country explicitly.

The Web K country-list selection flow was examined in the browser. The client exposes `contenteditable` controls with dial-code formatting, and a direct DOM-driven selection/insertion populated the phone control. The current display format is `+55 50 00011 1`; this confirms the page is applying its phone formatter, but the selected country/prefix did not match the intended USA test entry. Subsequent live testing should submit this syntactically valid formatted identifier or reset the field through the normal control path.

The active Next submission was successful: the Python MTProto gateway routed the unregistered formatted identifier directly into the imported Web K sign-up card, proving the live no-SMS `auth.sendCode` branch. First and last name fields accepted normal form entry. The password is a third custom contenteditable control immediately above the `START MESSAGING` button; the generic multi-field filler mistook the button’s index for that control, so the final registration operation must target the password field explicitly.

## 2026-08-21 — Live no-SMS registration and signed-in shell verified

The clean browser completed the normal imported Web K interaction sequence: phone card, no-SMS sign-up card, password entry, encrypted `auth.signUp`, and transition into the IntelliGram messaging shell. The visible post-login shell contains the preserved Web K sidebar, search box, action controls, and empty-chat canvas. This confirms that `auth.Authorization` now carries a usable full `user` entity rather than the previous `userEmpty` placeholder.

The next validation step is to inspect the live gateway’s request log for the authenticated Web K bootstrap methods and use it to prioritize the next compatibility handlers.

The authenticated browser console shows no post-login TL parsing or runtime exception after the initial storage-reset messages, and the live Web K view remains stably mounted in the IntelliGram messaging shell. Gateway telemetry confirms the live client invoked `users.getFullUser`, `messages.getDialogs`, and `updates.getState`; the newly implemented handlers served those requests without a `METHOD_INVALID` response. The blank dialog list is expected for the just-created account.

## Fresh environment regression check

With the ignored client `.env` temporarily removed, the updated Web K client completed state loading and logged `Will mount auth page: authStateSignQr` rather than throwing `compareVersion(...).split` on an undefined version. The browser view was captured immediately after navigation while still visually white; a follow-up render check is required before declaring the fresh-start fix complete.

## 2026-08-21 — Live Saved Messages verification

After restarting the local IntelliGram gateway with the Saved Messages dialog repair, the Web K main menu’s **Saved Messages** entry opened successfully. The client rendered its native cloud-storage informational state and no longer stalled on the self `inputPeerSelf` / peer-dialog route. This confirms that materializing the durable self-dialog resolves the previously reported navigation failure.
