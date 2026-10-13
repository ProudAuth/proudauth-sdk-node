/**
 * Offline JWT access-token verification for resource servers (SDK-001), a port of
 * the Go SDK's verifier package.
 *
 * Offline mode verifies JWT access tokens with the §14.4 algorithm: a preconfigured
 * trusted issuer (checked before any key fetch), strict parsing with
 * duplicate-member rejection, explicit "at+jwt" typing, an asymmetric algorithm
 * allowlist, key IDs resolved only from that issuer's configured key set with
 * bounded, coalesced refreshes, exact issuer and audience checks, and fail-closed
 * errors.
 *
 * Offline verification cannot observe revocation before expiry (SES-023): a
 * revoked session's access token keeps working until `exp` plus the clock skew.
 * Use the strict-online Introspector (`@proudauth/sdk/introspection`) where that
 * exposure is unacceptable, and always for support (impersonation) tokens.
 */

import { Claims, type Actor } from './claims.js';
import { VerifierError } from './errors.js';
import type { FetchLike } from './internal/http.js';
import { requireHttpUrl } from './internal/http.js';
import { isPlainObject } from './internal/json.js';
import { JwksCache, JwksError } from './internal/jwks.js';
import { JWSParseError, parseCompactJWS, resolveAlgorithms, verifySignature } from './internal/jws.js';
import type { Authenticator } from './middleware.js';

export { Claims, type Actor, type ClaimsInit } from './claims.js';
export { MultiIssuerVerifier, type IssuerRegistration, type TenantClaims } from './multi-issuer.js';
export { VerifierError, isVerifierError, VERIFIER_ERROR_CODES, type VerifierErrorCode } from './errors.js';
export {
  attachClaims,
  authenticateRequest,
  bearerToken,
  challenge,
  fastifyHook,
  getClaims,
  middleware,
  protect,
  requireScopes,
  sendChallenge,
  type AuthChallenge,
  type Authenticator,
  type ChallengeOptions,
  type FastifyReplyLike,
  type MiddlewareOptions,
  type NextFunction,
  type RequestLike,
  type ResponseLike,
} from './middleware.js';
export { SUPPORTED_ALGORITHMS } from './internal/jws.js';

/** Token kinds accepted offline by default. */
export const DEFAULT_ACCEPTED_KINDS = Object.freeze(['user_access', 'service_access', 'exchange_access']);

/** Support tokens are opaque and strict-online only (IMP-010). */
export const SUPPORT_TOKEN_KIND = 'impersonation_access';

export const MAX_CLOCK_SKEW_MS = 60_000;

export interface VerifierConfig {
  /** The exact trusted issuer. Tokens from any other issuer are rejected without fetching anything (TEST-003). */
  issuer: string;
  /** This API's registered audience. */
  audience: string;
  /** Defaults to `${issuer}/jwks`. Never taken from a token (no jku/x5u). */
  jwksUrl?: string;
  /** Asymmetric allowlist; default RS256, PS256, ES256, EdDSA. "none" and HS* are refused. */
  algorithms?: string[];
  /** Permitted clock tolerance in milliseconds (default 30 000, at most 60 000). */
  clockSkewMs?: number;
  /**
   * Accepted token_kind values. Default: user_access, service_access and
   * exchange_access. impersonation_access is refused: support tokens are opaque
   * and must be validated online by the SupportGuard.
   */
  acceptedKinds?: string[];
  /** Minimum spacing of JWKS refreshes triggered by unknown key IDs (default 30 000 ms, minimum 1 000 ms). */
  minRefreshIntervalMs?: number;
  /** Maximum token size in bytes (default 8192). */
  maxTokenBytes?: number;
  /** JWKS request timeout (default 5 000 ms). */
  timeoutMs?: number;
  /** Custom fetch implementation (proxies, tests). Defaults to the global fetch. */
  fetch?: FetchLike;
  /** Clock in milliseconds since the epoch (tests). Defaults to Date.now. */
  now?: () => number;
}

export interface VerifyOptions {
  /** Lets this caller stop waiting for a key-set fetch; the shared fetch continues. */
  signal?: AbortSignal;
}

/** Verifies JWT access tokens offline. */
export class Verifier implements Authenticator {
  readonly #issuer: string;
  readonly #audience: string;
  readonly #algorithms: ReadonlySet<string>;
  readonly #skewMs: number;
  readonly #acceptedKinds: ReadonlySet<string>;
  readonly #maxTokenBytes: number;
  readonly #now: () => number;
  readonly #jwks: JwksCache;

  constructor(config: VerifierConfig) {
    const prefix = 'verifier';
    if (!config || typeof config.issuer !== 'string' || config.issuer === '' || typeof config.audience !== 'string' || config.audience === '') {
      throw new TypeError('verifier: issuer and audience are required');
    }
    this.#issuer = config.issuer;
    this.#audience = config.audience;
    const jwksUrl = config.jwksUrl ?? config.issuer.replace(/\/+$/, '') + '/jwks';
    requireHttpUrl(jwksUrl, 'jwksUrl', prefix);
    this.#algorithms = resolveAlgorithms(config.algorithms, prefix);
    const skew = config.clockSkewMs ?? 30_000;
    if (!Number.isFinite(skew) || skew < 0) throw new TypeError('verifier: clock skew must be a non-negative number of milliseconds');
    if (skew > MAX_CLOCK_SKEW_MS) throw new TypeError('verifier: clock skew must be at most 60s');
    this.#skewMs = skew;
    const kinds = config.acceptedKinds && config.acceptedKinds.length > 0 ? config.acceptedKinds : DEFAULT_ACCEPTED_KINDS;
    if (kinds.includes(SUPPORT_TOKEN_KIND)) {
      throw new TypeError('verifier: impersonation_access cannot be verified offline; use the SupportGuard (strict-online)');
    }
    this.#acceptedKinds = new Set(kinds);
    const minRefresh = config.minRefreshIntervalMs ?? 30_000;
    if (!Number.isFinite(minRefresh) || minRefresh < 1_000) throw new TypeError('verifier: minRefreshIntervalMs must be at least 1000');
    this.#maxTokenBytes = config.maxTokenBytes ?? 8192;
    if (!Number.isInteger(this.#maxTokenBytes) || this.#maxTokenBytes <= 0) throw new TypeError('verifier: maxTokenBytes must be a positive integer');
    const timeoutMs = config.timeoutMs ?? 5_000;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('verifier: timeoutMs must be positive');
    this.#now = config.now ?? Date.now;
    const fetchImpl = config.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') throw new TypeError('verifier: no fetch implementation available');
    this.#jwks = new JwksCache({ url: jwksUrl, fetch: fetchImpl, timeoutMs, minRefreshIntervalMs: minRefresh, now: this.#now });
  }

  /** How many JWKS fetches occurred (diagnostics and tests). */
  get fetchCount(): number {
    return this.#jwks.fetchCount;
  }

  /** The configured issuer. */
  get issuer(): string {
    return this.#issuer;
  }

  /** The configured audience. */
  get audience(): string {
    return this.#audience;
  }

  /** Verifies a JWT access token offline. Rejects with a VerifierError. */
  async verify(raw: string, options: VerifyOptions = {}): Promise<Claims> {
    if (typeof raw !== 'string' || raw === '') throw new VerifierError('missing_token');
    if (raw.length > this.#maxTokenBytes || Buffer.byteLength(raw, 'utf8') > this.#maxTokenBytes) {
      throw new VerifierError('too_large');
    }
    let jws;
    try {
      jws = parseCompactJWS(raw);
    } catch (e) {
      throw new VerifierError(e instanceof JWSParseError && e.reason === 'duplicate' ? 'duplicate_claim' : 'malformed');
    }
    const { header, payload } = jws;

    // Check the issuer before any key lookup so unrelated issuers never trigger fetches.
    if (payload.iss !== this.#issuer) throw new VerifierError('issuer');

    // No JOSE extensions are understood, so a critical one cannot be honoured.
    if (header.crit !== undefined) throw new VerifierError('malformed');
    const alg = header.alg;
    if (typeof alg !== 'string' || !this.#algorithms.has(alg)) throw new VerifierError('algorithm');
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
    if (typ !== 'at+jwt' && typ !== 'application/at+jwt') {
      throw new VerifierError('token_type'); // e.g. an ID token sent to an API (TEST-002)
    }
    const kid = header.kid;
    if (typeof kid !== 'string' || kid === '') throw new VerifierError('unknown_key');

    let key;
    try {
      key = await this.#jwks.getKey(kid, options.signal);
    } catch (e) {
      if (e instanceof JwksError && e.reason === 'unknown_key') throw new VerifierError('unknown_key');
      throw new VerifierError('unavailable', { cause: e });
    }
    if (key.alg !== undefined && key.alg !== alg) throw new VerifierError('algorithm');
    if (!verifySignature(alg, key.key, jws.signingInput, jws.signature)) throw new VerifierError('signature');

    return this.#claims(payload);
  }

  /** Implements Authenticator for offline verification. */
  authenticate(raw: string, options?: VerifyOptions): Promise<Claims> {
    return this.verify(raw, options);
  }

  #claims(p: Readonly<Record<string, unknown>>): Claims {
    const str = (k: string): string => {
      const v = p[k];
      if (v === undefined || v === null) return '';
      if (typeof v !== 'string') throw new VerifierError('malformed');
      return v;
    };
    const num = (k: string): number | undefined => {
      const v = p[k];
      if (v === undefined || v === null) return undefined;
      if (typeof v !== 'number' || !Number.isFinite(v)) throw new VerifierError('malformed');
      return v;
    };

    if (str('iss') !== this.#issuer) throw new VerifierError('issuer');

    const aud = p.aud;
    let audiences: string[];
    if (typeof aud === 'string') audiences = [aud];
    else if (aud === undefined || aud === null) audiences = [];
    else if (Array.isArray(aud) && aud.every((a) => typeof a === 'string')) audiences = aud as string[];
    else throw new VerifierError('malformed');
    // Exactly one audience, equal to this API's (narrow audiences, TOK-007, TEST-001).
    if (audiences.length !== 1 || audiences[0] !== this.#audience) throw new VerifierError('audience');

    const nowSec = this.#now() / 1000;
    const skewSec = this.#skewMs / 1000;
    const exp = num('exp');
    const nbf = num('nbf');
    const iat = num('iat');
    if (exp === undefined || nowSec > exp + skewSec) throw new VerifierError('expired');
    if (nbf !== undefined && nowSec + skewSec < nbf) throw new VerifierError('not_yet_valid');
    if (iat !== undefined && iat > nowSec + skewSec) throw new VerifierError('future_issued');

    const subject = str('sub');
    const clientId = str('client_id');
    const jti = str('jti');
    const tokenKind = str('token_kind');
    if (subject === '' || clientId === '' || jti === '' || !this.#acceptedKinds.has(tokenKind)) {
      throw new VerifierError('token_kind');
    }
    const scope = str('scope');
    const authTime = num('auth_time');
    const actor = p.act === undefined || p.act === null ? undefined : parseActorStrict(p.act, 0);
    // Token-only verification cannot validate the sender of this HTTP request.
    if (Object.hasOwn(p, 'cnf')) throw new VerifierError('sender_constraint');
    return new Claims({
      issuer: this.#issuer,
      subject,
      audience: this.#audience,
      clientId,
      scopes: scope.split(/\s+/).filter(Boolean),
      orgId: str('org_id'),
      sessionId: str('sid'),
      tokenKind,
      jti,
      issuedAt: iat !== undefined ? new Date(iat * 1000) : undefined,
      expiry: new Date(exp * 1000),
      authTime: authTime !== undefined && authTime > 0 ? new Date(authTime * 1000) : undefined,
      acr: str('acr'),
      authzVersion: num('authz_version') ?? 0,
      actor,
      online: false,
    });
  }
}

function parseActorStrict(v: unknown, depth: number): Actor {
  if (depth > 16 || !isPlainObject(v)) throw new VerifierError('malformed');
  const { sub, iss, act } = v;
  if (typeof sub !== 'string' || (iss !== undefined && typeof iss !== 'string')) throw new VerifierError('malformed');
  const out: { issuer?: string; subject: string; act?: Actor } = { subject: sub };
  if (typeof iss === 'string') out.issuer = iss;
  if (act !== undefined && act !== null) out.act = parseActorStrict(act, depth + 1);
  return out;
}
