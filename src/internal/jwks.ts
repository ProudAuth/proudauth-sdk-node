/**
 * A key cache for one trusted JWKS URL with bounded, coalesced refreshes (§14.4,
 * TEST-005). The URL always comes from configuration (or the configured issuer's
 * discovery document), never from a token header such as jku or x5u.
 *
 * Refresh semantics mirror the Go SDK:
 *  - the first lookup loads the key set;
 *  - an unknown kid triggers at most one refresh, and refreshes are spaced by at
 *    least `minRefreshIntervalMs`, so floods of random kids cannot cause a request
 *    storm;
 *  - concurrent callers share one in-flight fetch;
 *  - a failed fetch keeps the previously known keys; a successful fetch replaces
 *    the set (retired keys disappear).
 *
 * @internal
 */

import { isPlainObject, parseStrictJSON } from './json.js';
import { importJWK, type VerificationKey } from './jws.js';
import { discardBody, readBodyLimited, utf8Strict, waitFor, type FetchLike } from './http.js';

export type JwksFailure = 'unavailable' | 'unknown_key';

export class JwksError extends Error {
  override readonly name = 'JwksError';
  constructor(
    readonly reason: JwksFailure,
    options?: { cause?: unknown },
  ) {
    super(reason === 'unavailable' ? 'key set unavailable' : 'unknown signing key', options);
  }
}

export interface JwksCacheOptions {
  url: string;
  fetch: FetchLike;
  timeoutMs: number;
  minRefreshIntervalMs: number;
  now: () => number;
  maxBytes?: number;
}

export class JwksCache {
  readonly #opts: JwksCacheOptions;
  #keys = new Map<string, VerificationKey>();
  #lastFetch: number | undefined;
  #inflight: Promise<void> | undefined;
  #fetchCount = 0;
  #everLoaded = false;
  #lastFailed = false;

  constructor(opts: JwksCacheOptions) {
    this.#opts = opts;
  }

  /** Number of key-set fetches started (diagnostics and tests). */
  get fetchCount(): number {
    return this.#fetchCount;
  }

  async getKey(kid: string, signal?: AbortSignal): Promise<VerificationKey> {
    await this.#refresh(false, signal);
    let k = this.#keys.get(kid);
    if (k) return k;
    // One bounded refresh for an unknown kid.
    await this.#refresh(true, signal);
    k = this.#keys.get(kid);
    if (k) return k;
    if (!this.#everLoaded && this.#lastFailed) throw new JwksError('unavailable');
    throw new JwksError('unknown_key');
  }

  async #refresh(force: boolean, signal: AbortSignal | undefined): Promise<void> {
    const unavailable = (): Error => new JwksError('unavailable');
    if (this.#inflight) {
      // Coalesce: wait for the in-flight fetch; its outcome is observed via the key map.
      await waitFor(
        this.#inflight.catch(() => undefined),
        signal,
        unavailable,
      );
      return;
    }
    if (!force && this.#keys.size > 0) return;
    const now = this.#opts.now();
    if (this.#lastFetch !== undefined && now - this.#lastFetch < this.#opts.minRefreshIntervalMs) return;
    this.#lastFetch = now;
    this.#fetchCount++;
    const p = this.#load();
    this.#inflight = p;
    const clear = (): void => {
      if (this.#inflight === p) this.#inflight = undefined;
    };
    p.then(clear, clear);
    await waitFor(p, signal, unavailable);
  }

  async #load(): Promise<void> {
    try {
      // The shared fetch is bounded by its own timeout, not by one caller's signal.
      const res = await this.#opts.fetch(this.#opts.url, {
        method: 'GET',
        headers: { accept: 'application/jwk-set+json, application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(this.#opts.timeoutMs),
      });
      if (res.status !== 200) {
        await discardBody(res);
        throw new Error(`key set endpoint returned HTTP ${res.status}`);
      }
      const body = await readBodyLimited(res, this.#opts.maxBytes ?? 1 << 20);
      const set = parseStrictJSON(utf8Strict.decode(body));
      if (!isPlainObject(set) || !Array.isArray(set.keys)) throw new Error('key set has no keys array');
      const keys = new Map<string, VerificationKey>();
      const ambiguous = new Set<string>();
      for (const jwk of set.keys) {
        const k = importJWK(jwk);
        if (!k) continue;
        if (keys.has(k.kid)) ambiguous.add(k.kid);
        else keys.set(k.kid, k);
      }
      // Two usable keys under one kid make key selection ambiguous (TEST-004): trust neither.
      for (const kid of ambiguous) keys.delete(kid);
      this.#keys = keys;
      this.#everLoaded = true;
      this.#lastFailed = false;
    } catch (cause) {
      this.#lastFailed = true;
      throw new JwksError('unavailable', { cause });
    }
  }
}
