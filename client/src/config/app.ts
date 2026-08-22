/*
 * Derived from Telegram Web K, originally based on Webogram.
 * IntelliGram uses this configuration only with its self-hosted MTProto server.
 */

import type {TrueDcId} from '@types';
import langPackLocalVersion from '@/langPackLocalVersion';

export const DEFAULT_BACKGROUND_SLUG = 'pattern';

const threads = Math.min(4, navigator.hardwareConcurrency ?? 4);
const configuredApiId = Number(import.meta.env.VITE_INTELLIGRAM_API_ID ?? 1);
const configuredBuild = Number(import.meta.env.VITE_BUILD ?? 1);
const configuredLangPackVersion = Number(import.meta.env.VITE_LANG_PACK_VERSION ?? 1);
const publicLinkBaseUrl = (import.meta.env.VITE_INTELLIGRAM_PUBLIC_LINK_BASE_URL ?? 'https://intelligram.local')
  .trim()
  .replace(/\/+$/, '') || 'https://intelligram.local';
const publicLinkDisplayPrefix = `${publicLinkBaseUrl.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')}/`;

const App = {
  id: Number.isSafeInteger(configuredApiId) && configuredApiId > 0 ? configuredApiId : 1,
  hash: import.meta.env.VITE_INTELLIGRAM_API_HASH ?? 'intelligram-self-hosted',
  pushServerKey: import.meta.env.VITE_INTELLIGRAM_PUSH_SERVER_KEY,
  // Local Vite checkouts do not include the ignored `.env` file. These defaults
  // keep persisted-state migration valid while explicit deployment values still win.
  version: import.meta.env.VITE_VERSION ?? '0.1.0',
  versionFull: import.meta.env.VITE_VERSION_FULL ?? '0.1.0 IntelliGram Web K',
  build: Number.isFinite(configuredBuild) && configuredBuild > 0 ? configuredBuild : 1,
  langPackVersion: Number.isFinite(configuredLangPackVersion) && configuredLangPackVersion > 0 ? configuredLangPackVersion : 1,
  langPackLocalVersion: langPackLocalVersion,
  // Retain Web K's local language-pack format; this is not a Telegram endpoint identity.
  langPack: 'webk',
  langPackCode: 'en',
  domains: [] as string[],
  baseDcId: 1 as TrueDcId,
  isMainDomain: false,
  suffix: '',
  threads,
  lottieWorkers: threads,
  cryptoWorkers: threads,
  interclientBroadcastChannel: 'intelligram',
  // The server remains authoritative for invite URLs. This is the branded
  // public-channel prefix rendered by Web K beside username-only input.
  publicLinkBaseUrl,
  publicLinkDisplayPrefix
};

export default App;
