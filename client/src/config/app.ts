/*
 * Derived from Telegram Web K, originally based on Webogram.
 * IntelliGram uses this configuration only with its self-hosted MTProto server.
 */

import type {TrueDcId} from '@types';
import langPackLocalVersion from '@/langPackLocalVersion';

export const DEFAULT_BACKGROUND_SLUG = 'pattern';

const threads = Math.min(4, navigator.hardwareConcurrency ?? 4);
const configuredApiId = Number(import.meta.env.VITE_INTELLIGRAM_API_ID ?? 1);

const App = {
  id: Number.isSafeInteger(configuredApiId) && configuredApiId > 0 ? configuredApiId : 1,
  hash: import.meta.env.VITE_INTELLIGRAM_API_HASH ?? 'intelligram-self-hosted',
  pushServerKey: import.meta.env.VITE_INTELLIGRAM_PUSH_SERVER_KEY,
  version: import.meta.env.VITE_VERSION,
  versionFull: import.meta.env.VITE_VERSION_FULL,
  build: +import.meta.env.VITE_BUILD,
  langPackVersion: +import.meta.env.VITE_LANG_PACK_VERSION,
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
  interclientBroadcastChannel: 'intelligram'
};

export default App;
