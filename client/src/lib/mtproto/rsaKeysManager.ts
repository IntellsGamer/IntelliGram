/*
 * Derived from Telegram Web K, originally based on Webogram.
 * IntelliGram intentionally trusts only the public key advertised by its
 * configured self-hosted server after a local MTProto fingerprint check.
 */

import {TLSerialization} from '@lib/mtproto/tl_utils';
import cryptoWorker from '@lib/crypto/cryptoMessagePort';
import bytesFromHex from '@helpers/bytes/bytesFromHex';
import bytesToHex from '@helpers/bytes/bytesToHex';
import bigInt from 'big-integer';

export type RSAPublicKeyHex = {
  modulus: string,
  exponent: string
};

type IntelliGramBootstrap = {
  product: string,
  network: string,
  mtproto: {
    dc_id: number,
    server_public_key_fingerprint: string,
    server_public_key: {
      modulus_hex: string,
      exponent_hex: string
    }
  }
};

function normalizedFingerprint(value: string) {
  const fingerprint = BigInt(value);
  return BigInt.asUintN(64, fingerprint).toString(16).padStart(16, '0');
}

function serverBaseUrl() {
  const configured = import.meta.env.VITE_INTELLIGRAM_SERVER_URL;
  if(configured) {
    return configured.replace(/\/$/, '');
  }
  return `${location.protocol}//${location.hostname}:8080`;
}

function validatePublicKey(key: RSAPublicKeyHex) {
  if(!/^[0-9a-f]{512}$/i.test(key.modulus) || !/^[0-9a-f]{2,16}$/i.test(key.exponent)) {
    throw new Error('[IntelliGram MT] bootstrap returned an invalid RSA public key');
  }
}

export class RSAKeysManager {
  private publicKeysParsed: Record<string, RSAPublicKeyHex> = {};
  private prepared = false;
  private preparePromise: Promise<void> = null;

  private async fetchBootstrapKey(): Promise<{key: RSAPublicKeyHex, fingerprint: string}> {
    const response = await fetch(`${serverBaseUrl()}/v1/bootstrap`, {cache: 'no-store'});
    if(!response.ok) {
      throw new Error(`[IntelliGram MT] bootstrap failed with HTTP ${response.status}`);
    }

    const bootstrap = await response.json() as IntelliGramBootstrap;
    if(bootstrap?.product !== 'IntelliGram' || bootstrap?.network !== 'self-hosted' || !bootstrap.mtproto) {
      throw new Error('[IntelliGram MT] bootstrap did not identify a self-hosted IntelliGram server');
    }

    const {server_public_key: rawKey, server_public_key_fingerprint: fingerprint} = bootstrap.mtproto;
    const key: RSAPublicKeyHex = {
      modulus: rawKey?.modulus_hex,
      exponent: rawKey?.exponent_hex
    };
    if(typeof fingerprint !== 'string' || !rawKey) {
      throw new Error('[IntelliGram MT] bootstrap omitted its MTProto public-key data');
    }
    validatePublicKey(key);
    return {key, fingerprint};
  }

  private async registerBootstrapKey(key: RSAPublicKeyHex, claimedFingerprint: string) {
    const serialized = new TLSerialization();
    serialized.storeBytes(bytesFromHex(key.modulus), 'n');
    serialized.storeBytes(bytesFromHex(key.exponent), 'e');
    const digest = await cryptoWorker.invokeCrypto('sha1', serialized.getBuffer());
    const fingerprintBytes = digest.slice(-8).reverse();
    const actualFingerprint = bytesToHex(fingerprintBytes).toLowerCase();

    if(actualFingerprint !== normalizedFingerprint(claimedFingerprint)) {
      throw new Error('[IntelliGram MT] bootstrap RSA fingerprint verification failed');
    }
    this.publicKeysParsed = {[actualFingerprint]: key};
  }

  public prepare(): Promise<void> {
    if(this.preparePromise) return this.preparePromise;
    if(this.prepared) return Promise.resolve();

    this.preparePromise = this.fetchBootstrapKey()
    .then(({key, fingerprint}) => this.registerBootstrapKey(key, fingerprint))
    .then(() => {
      this.prepared = true;
      this.preparePromise = null;
    })
    .catch((error) => {
      this.preparePromise = null;
      throw error;
    });
    return this.preparePromise;
  }

  public async select(fingerprints: Array<string>) {
    await this.prepare();
    for(const fingerprint of fingerprints) {
      const fingerprintHex = normalizedFingerprint(fingerprint);
      const foundKey = this.publicKeysParsed[fingerprintHex];
      if(foundKey) {
        return Object.assign({fingerprint: bigInt(fingerprint).toString(10)}, foundKey);
      }
    }
  }
}

export default new RSAKeysManager();
