/**
 * Small HTTP helpers shared by the SDK modules. Nothing here logs, and no helper
 * includes request or response bodies in errors (SDK-008).
 *
 * @internal
 */

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export class BodyTooLargeError extends Error {
  override readonly name = 'BodyTooLargeError';
  constructor() {
    super('response body exceeds the configured limit');
  }
}

/** Reads a response body, failing once it exceeds `limit` bytes. */
export async function readBodyLimited(res: Response, limit: number): Promise<Buffer> {
  const declared = res.headers.get('content-length');
  if (declared !== null && Number(declared) > limit) {
    await res.body?.cancel().catch(() => undefined);
    throw new BodyTooLargeError();
  }
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw new BodyTooLargeError();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/** Discards a response body so the connection can be reused. */
export async function discardBody(res: Response): Promise<void> {
  await res.body?.cancel().catch(() => undefined);
}

/** UTF-8 decoder that rejects invalid sequences and keeps a BOM (so JSON parsing rejects it). */
export const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * application/x-www-form-urlencoded encoding of one value, equivalent to Go's
 * url.QueryEscape (RFC 6749 §2.3.1 requires it for client credentials in Basic auth).
 */
export function formEncode(value: string): string {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
    .replace(/%20/g, '+');
}

/** Encodes a form body. */
export function formBody(fields: Record<string, string | undefined>): string {
  return Object.entries(fields)
    .filter((e): e is [string, string] => typeof e[1] === 'string')
    .map(([k, v]) => `${formEncode(k)}=${formEncode(v)}`)
    .join('&');
}

/** client_secret_basic Authorization header value (RFC 6749 §2.3.1). */
export function basicAuthorization(clientId: string, clientSecret: string): string {
  return 'Basic ' + Buffer.from(`${formEncode(clientId)}:${formEncode(clientSecret)}`, 'utf8').toString('base64');
}

/** Combines an optional caller signal with a timeout. */
export function withTimeout(timeoutMs: number, signal?: AbortSignal): AbortSignal {
  const t = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, t]) : t;
}

/**
 * Waits for a shared promise while letting one caller stop waiting via its own
 * signal, without cancelling the shared operation for the other waiters.
 */
export function waitFor<T>(p: Promise<T>, signal: AbortSignal | undefined, onAbort: () => Error): Promise<T> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(onAbort());
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(onAbort());
    signal.addEventListener('abort', abort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', abort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(e);
      },
    );
  });
}

export function requireHttpUrl(value: unknown, what: string, prefix: string): URL {
  if (typeof value !== 'string' || value === '') throw new TypeError(`${prefix}: ${what} is required`);
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new TypeError(`${prefix}: ${what} must be an absolute URL`);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new TypeError(`${prefix}: ${what} must be an http(s) URL`);
  if (u.username || u.password) throw new TypeError(`${prefix}: ${what} must not contain credentials`);
  return u;
}
