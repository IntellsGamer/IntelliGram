/**
 * Insecure HTTP (LAN IPs, hostnames other than localhost) is not a secure
 * context. Chromium then leaves `caches` undefined and refuses Service Workers.
 * Detect that environment once and install an in-memory Cache Storage so the
 * rest of Web K can boot without throwing `Cache is not defined`.
 */

export function isInsecureHttpContext(): boolean {
  try {
    if(typeof location === 'undefined') {
      return false;
    }
    if(location.protocol !== 'http:') {
      return false;
    }
    const host = (location.hostname || '').toLowerCase();
    return host !== 'localhost' && host !== '127.0.0.1' && host !== '[::1]';
  } catch(_err) {
    return false;
  }
}

class MemoryCache {
  private readonly entries = new Map<string, Response>();

  private key(request: RequestInfo | URL): string {
    if(typeof request === 'string') return request;
    if(request instanceof URL) return request.href;
    return request.url;
  }

  match(request: RequestInfo | URL): Promise<Response | undefined> {
    const stored = this.entries.get(this.key(request));
    return Promise.resolve(stored ? stored.clone() : undefined);
  }

  matchAll(request?: RequestInfo | URL): Promise<Response[]> {
    if(request === undefined) {
      return Promise.resolve([...this.entries.values()].map((response) => response.clone()));
    }
    const stored = this.entries.get(this.key(request));
    return Promise.resolve(stored ? [stored.clone()] : []);
  }

  put(request: RequestInfo | URL, response: Response): Promise<void> {
    this.entries.set(this.key(request), response);
    return Promise.resolve();
  }

  delete(request: RequestInfo | URL): Promise<boolean> {
    return Promise.resolve(this.entries.delete(this.key(request)));
  }

  keys(): Promise<Request[]> {
    return Promise.resolve([...this.entries.keys()].map((url) => new Request(url)));
  }

  add(): Promise<void> {
    return Promise.reject(new Error('Cache.add is not available in HTTP compatibility mode'));
  }

  addAll(): Promise<void> {
    return Promise.reject(new Error('Cache.addAll is not available in HTTP compatibility mode'));
  }
}

class MemoryCacheStorage {
  private readonly named = new Map<string, MemoryCache>();

  open(cacheName: string): Promise<MemoryCache> {
    let cache = this.named.get(cacheName);
    if(!cache) {
      cache = new MemoryCache();
      this.named.set(cacheName, cache);
    }
    return Promise.resolve(cache);
  }

  has(cacheName: string): Promise<boolean> {
    return Promise.resolve(this.named.has(cacheName));
  }

  delete(cacheName: string): Promise<boolean> {
    return Promise.resolve(this.named.delete(cacheName));
  }

  keys(): Promise<string[]> {
    return Promise.resolve([...this.named.keys()]);
  }

  async match(request: RequestInfo | URL): Promise<Response | undefined> {
    for(const cache of this.named.values()) {
      const hit = await cache.match(request);
      if(hit) return hit;
    }
    return undefined;
  }
}

export function installHttpCompatibility(): boolean {
  const insecure = isInsecureHttpContext();
  const cacheMissing = typeof (globalThis as {caches?: CacheStorage}).caches === 'undefined';
  if(cacheMissing) {
    (globalThis as any).caches = new MemoryCacheStorage();
  }
  if(insecure) {
    (globalThis as any).__INTELLIGRAM_HTTP_COMPAT__ = true;
  }
  return insecure;
}

installHttpCompatibility();
