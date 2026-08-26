/*
 * Originally from:
 * https://github.com/zhukov/webogram
 * Copyright (C) 2014 Igor Zhukov <igor.beatle@gmail.com>
 * https://github.com/zhukov/webogram/blob/master/LICENSE
 */

import type {TransportType} from '@lib/mtproto/dcConfigurator';

// The HTTP compatibility bootstrap is intentionally protocol-based, not merely
// `isSecureContext`-based. Loopback HTTP is technically secure enough for some
// browser APIs, but it must exercise the same deterministic no-Service-Worker
// startup path as any other HTTP deployment. HTTPS retains the normal worker
// architecture unchanged.
const httpCompatibility = location.protocol !== 'https:';

const Modes = {
  test: location.search.indexOf('test=1') > 0/*  || true */,
  debug: location.search.indexOf('debug=1') > 0,
  http: false,
  ssl: true, // location.search.indexOf('ssl=1') > 0 || location.protocol === 'https:' && location.search.indexOf('ssl=0') === -1,
  asServiceWorker: !!import.meta.env.VITE_MTPROTO_SW,
  transport: 'websocket' as TransportType,
  noSharedWorker: location.search.indexOf('noSharedWorker=1') > 0,
  // HTTPS uses the normal Service Worker. Every HTTP origin uses the in-process
  // compatibility bootstrap instead of attempting registration and getting stuck
  // between worker states.
  noServiceWorker: location.search.indexOf('noServiceWorker=1') > 0 || httpCompatibility,
  noOffscreenCanvas: location.search.indexOf('noOffscreenCanvas=1') > 0,
  // Kill switch for the SHARED object-URL lifecycle: with it on, worker-minted
  // blob URLs are never evicted from the caches, never revoked, and pins are
  // not reported — the old leak-forever behaviour for shared media.
  // Tab-local one-off URLs (ObjectURLScope: editor previews, upload previews,
  // decoded voice) are NOT covered: disposing those is self-contained and was
  // a plain leak fix, so it stays active even here. Neither are the handful of
  // pre-existing raw URL.revokeObjectURL call sites (recording, rtmp, download).
  // * OFF everywhere by default — the lifecycle is live in production too.
  // * ?noObjectUrlRevoke=1 forces it on to fall back to the old behaviour
  //   (it reaches the worker too — makeWorkerURL forwards query params).
  noObjectUrlRevoke: location.search.indexOf('noObjectUrlRevoke=1') > 0,
  // Run MTProto + crypto entirely in the main thread (debug only). Loops the
  // worker entries back through a MessageChannel in the same realm so
  // breakpoints / call stacks span the whole pipeline. Multi-tab features
  // (SharedWorker dedup, auto-lock cross-tab) silently degrade.
  // Triggers: ?noWorker=1 in the URL, VITE_NO_WORKER injected at build time,
  // or the HTTP compatibility bootstrap. HTTPS still uses the normal SharedWorker
  // implementation; HTTP runs the same imported worker modules in-process.
  noWorker: location.search.indexOf('noWorker=1') > 0 || !!import.meta.env.VITE_NO_WORKER || httpCompatibility,
  multipleTransports: !!(import.meta.env.VITE_MTPROTO_AUTO && import.meta.env.VITE_MTPROTO_HAS_HTTP && import.meta.env.VITE_MTPROTO_HAS_WS) && location.search.indexOf('noMultipleTransports=1') === -1,
  noPfs: true || location.search.indexOf('noPfs=1') > 0
};

if(import.meta.env.VITE_MTPROTO_HAS_HTTP) {
  const httpOnly = Modes.http = location.search.indexOf('http=1') > 0;
  if(httpOnly) {
    Modes.multipleTransports = false;
  }
}

// * start with HTTP first
if(Modes.multipleTransports) {
  Modes.http = true;
}

if(Modes.http) {
  Modes.transport = 'https';
}

export default Modes;
