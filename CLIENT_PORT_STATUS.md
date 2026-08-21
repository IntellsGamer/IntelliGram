# IntelliGram Client-Port Status

## Browser verification

The imported Telegram Web A source fork is running locally through Vite at `http://127.0.0.1:1234`. The browser document title is **IntelliGram**. The visible initial QR authorization screen retains the original Telegram Web A layout and interaction structure while now presents the expected IntelliGram copy:

> **Log in to IntelliGram by QR Code**
>
> 1. Open IntelliGram on your phone.
> 2. Go to **Settings** > **Devices** > **Add Device**.
> 3. Point your phone at this screen to confirm login.

The client startup path fetches the self-hosted Python server bootstrap descriptor and registers only a fingerprint-verified IntelliGram MTProto RSA key. The client no longer includes Telegram production RSA server keys and its DC resolver targets a configurable single IntelliGram endpoint.

## Current transport boundary

The Python server now exposes binary WebSocket route `/apiws`, matching the imported client’s WebSocket URL pattern. It accepts the `binary` subprotocol and its abridged framing tag, then supports the public `req_pq_multi` → RSA_PAD → DH → `dh_gen_ok` authorization-key exchange. The full browser UI renders successfully. The next server work is application-layer TL constructor support after authorization so the client can complete its post-auth initialization and present a real IntelliGram account rather than only the unchanged login shell.

## Browser retry after endpoint separation

After separating the client public URL (`http://127.0.0.1:1234`) from the Python server URL (`http://127.0.0.1:8080`) and enabling public bootstrap CORS, the browser continues to render the authentic IntelliGram-branded Telegram Web A QR-login layout. At this point the layout still shows its loading indicator rather than a generated QR matrix, so the next diagnostic step is browser-console/MTProto handshake analysis rather than presentation-layer work. The visible title and all initial user-facing copy remain correctly branded as IntelliGram.

## Bootstrap correction

The browser console now completes IntelliGram transport bootstrap with **no RSA fingerprint error**. The correction was to expose the signed 64-bit MTProto RSA fingerprint as a JSON string rather than a JavaScript-unsafe numeric value. The Python server confirms a successful `GET /v1/bootstrap` request. No `/apiws` WebSocket handshake appears in the server log yet, so the remaining login-shell spinner is now isolated to the client’s connection-start or worker scheduling path rather than branding, CORS, bootstrap, or RSA-key registration.

## Worker-start diagnostic

After successful server bootstrap, the imported client still reaches `>>> START LOAD WORKER` but does not visibly progress to QR generation. Browser resource timing exposed no observed `/apiws` request, and waiting for asynchronous startup did not change the spinner state. This locates the next compatibility/debugging boundary before the browser connection layer: the application worker’s connection initialization or inter-client startup logic.

## Browser WebSocket transport enabled

The direct browser probe now opens `ws://127.0.0.1:8080/apiws` successfully and negotiates the expected `binary` subprotocol. The prior failure was environmental: Uvicorn had no WebSocket runtime installed, so it rejected upgrade requests. Installing the runtime and restarting the Python server resolved this transport-level blocker. The next live refresh will test the imported client’s complete connection and authorization-key handshake against the now-reachable endpoint.

## Automatic client transport progress

The authentic imported Web A worker now automatically opens the Python server’s `/apiws` route after the page refresh. The server log confirms a successful WebSocket acceptance and an open connection. The UI remains in its QR loading state, so the current remaining boundary is inside the encrypted MTProto authorization-key handshake or its immediately following session request—not browser origin, bootstrap, WebSocket upgrade, or client worker startup.

## Connection retry observation

After a server restart, a fresh browser reload completed the public bootstrap request but did not reopen `/apiws` during the observed interval. Browser local storage contains no persisted account, session, or DC configuration keys, so a stale stored Telegram endpoint is not the cause. The diagnostic focus remains the imported worker’s in-memory connection scheduling and session initialization sequence.
