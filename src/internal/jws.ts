/**
 * Minimal, strict JWS compact-serialization support for the four asymmetric
 * algorithms ProudAuth issues (RS256, PS256, ES256, EdDSA/Ed25519), built only on
 * node:crypto. There is no "none", no HMAC and no algorithm fallback (TOK-005).
 *
 * @internal
 */

import { constants, createPublicKey, verify as cryptoVerify, type JsonWebKeyInput, type KeyObject } from 'node:crypto';
import { isPlainObject, parseStrictJSON, StrictJSONError } from './json.js';
import { utf8Strict } from './http.js';

export const SUPPORTED_ALGORITHMS = Object.freeze(['RS256', 'PS256', 'ES256', 'EdDSA'] as const);
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

/** Validates an algorithm allowlist; "none" and symmetric algorithms are always refused. */
export function resolveAlgorithms(algorithms: readonly string[] | undefined, prefix: string): ReadonlySet<string> {
  const list = algorithms && algorithms.length > 0 ? algorithms : SUPPORTED_ALGORITHMS;
  for (const a of list) {
    if (typeof a !== 'string' || a.toLowerCase() === 'none' || /^hs/i.test(a)) {
      throw new TypeError(`${prefix}: algorithm ${String(a)} is not allowed (no symmetric or unsigned tokens)`);
    }
    if (!(SUPPORTED_ALGORITHMS as readonly string[]).includes(a)) {
      throw new TypeError(`${prefix}: algorithm ${a} is not supported (supported: ${SUPPORTED_ALGORITHMS.join(', ')})`);
    }
  }
  return new Set(list);
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Strict, canonical base64url (no padding, no foreign characters, no non-zero pad bits). */
export function decodeBase64Url(s: string): Buffer {
  if (!BASE64URL.test(s) || s.length % 4 === 1) throw new Error('invalid base64url');
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s) throw new Error('non-canonical base64url');
  return b;
}

export function encodeBase64Url(b: Uint8Array | string): string {
  return Buffer.from(b).toString('base64url');
}

export type JWSFailure = 'malformed' | 'duplicate';

export class JWSParseError extends Error {
  override readonly name = 'JWSParseError';
  constructor(readonly reason: JWSFailure) {
    super(reason === 'duplicate' ? 'duplicate JSON member' : 'malformed JWS');
  }
}

export interface ParsedJWS {
  header: Readonly<Record<string, unknown>>;
  payload: Readonly<Record<string, unknown>>;
  signingInput: Buffer;
  signature: Buffer;
}

function parseSegment(bytes: Buffer): Record<string, unknown> {
  let text: string;
  try {
    text = utf8Strict.decode(bytes);
  } catch {
    throw new JWSParseError('malformed');
  }
  let value: unknown;
  try {
    value = parseStrictJSON(text);
  } catch (e) {
    throw new JWSParseError(e instanceof StrictJSONError && e.reason === 'duplicate' ? 'duplicate' : 'malformed');
  }
  if (!isPlainObject(value)) throw new JWSParseError('malformed');
  return value;
}

/**
 * Parses a compact JWS: exactly three canonical base64url segments, header and
 * payload must be JSON objects without duplicate members or trailing data.
 * Nothing here is trusted until the signature has been verified.
 */
export function parseCompactJWS(raw: string): ParsedJWS {
  const parts = raw.split('.');
  if (parts.length !== 3) throw new JWSParseError('malformed');
  const [h, p, s] = parts as [string, string, string];
  let hb: Buffer, pb: Buffer, sig: Buffer;
  try {
    hb = decodeBase64Url(h);
    pb = decodeBase64Url(p);
    sig = decodeBase64Url(s);
  } catch {
    throw new JWSParseError('malformed');
  }
  const header = parseSegment(hb);
  const payload = parseSegment(pb);
  return { header, payload, signingInput: Buffer.from(`${h}.${p}`, 'ascii'), signature: sig };
}

export interface VerificationKey {
  readonly kid: string;
  /** The JWK "alg" member, when the key set declares one. */
  readonly alg: string | undefined;
  readonly key: KeyObject;
}

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/**
 * Imports one public verification key. Keys without a kid, keys not meant for
 * signatures, private or symmetric keys, unsupported curves and RSA keys shorter
 * than 2048 bits are skipped rather than trusted.
 */
export function importJWK(jwk: unknown): VerificationKey | undefined {
  if (!isPlainObject(jwk)) return undefined;
  const { kid, kty, use, alg, key_ops: keyOps, crv } = jwk;
  if (typeof kid !== 'string' || kid === '') return undefined;
  if (use !== undefined && use !== 'sig') return undefined;
  if (keyOps !== undefined && !(Array.isArray(keyOps) && keyOps.includes('verify'))) return undefined;
  if (alg !== undefined && typeof alg !== 'string') return undefined;
  for (const m of PRIVATE_MEMBERS) if (m in jwk) return undefined;
  if (kty === 'EC') {
    if (crv !== 'P-256') return undefined;
  } else if (kty === 'OKP') {
    if (crv !== 'Ed25519') return undefined;
  } else if (kty !== 'RSA') {
    return undefined;
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: jwk, format: 'jwk' } as JsonWebKeyInput);
  } catch {
    return undefined;
  }
  if (kty === 'RSA' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return undefined;
  return Object.freeze({ kid, alg: alg as string | undefined, key });
}

/**
 * Verifies a JWS signature. The key type must match the algorithm, so an RSA key
 * can never verify an ES256 token and vice versa.
 */
export function verifySignature(alg: string, key: KeyObject, data: Buffer, signature: Buffer): boolean {
  try {
    switch (alg) {
      case 'RS256':
        if (key.asymmetricKeyType !== 'rsa') return false;
        return cryptoVerify('sha256', data, { key, padding: constants.RSA_PKCS1_PADDING }, signature);
      case 'PS256':
        if (key.asymmetricKeyType !== 'rsa') return false;
        return cryptoVerify(
          'sha256',
          data,
          { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
          signature,
        );
      case 'ES256':
        if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return false;
        if (signature.length !== 64) return false;
        return cryptoVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
      case 'EdDSA':
        if (key.asymmetricKeyType !== 'ed25519') return false;
        return cryptoVerify(null, data, key, signature);
      default:
        return false;
    }
  } catch {
    return false;
  }
}
