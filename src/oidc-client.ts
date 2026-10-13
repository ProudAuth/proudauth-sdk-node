/**
 * Confidential-client helper for backends-for-frontends (SDK-004), a port of the
 * Go SDK's oidcclient package: authorization code + PKCE S256, state and nonce
 * handling, RFC 9207 issuer checks, strict ID-token validation (OIDC-016),
 * server-side token storage with single-flight refresh (SES-009), revocation and
 * RP-initiated logout.
 *
 * The issuer is trusted configuration. Discovery is fetched only from it, every
 * advertised endpoint must share the issuer's origin, and keys are resolved only
 * from the advertised jwks_uri (never from a token header).
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  basicAuthorization,
  discardBody,
  formBody,
  readBodyLimited,
  requireHttpUrl,
  utf8Strict,
  waitFor,
  withTimeout,
  type FetchLike,
} from './internal/http.js';
import { isPlainObject, parseStrictJSON } from './internal/json.js';
import { JwksCache, JwksError } from './internal/jwks.js';
import { JWSParseError, parseCompactJWS, resolveAlgorithms, verifySignature } from './internal/jws.js';

export type OIDCErrorCode = 'state' | 'id_token' | 'nonce' | 'reauthenticate' | 'provider' | 'configuration';

const MESSAGES: Record<OIDCErrorCode, string> = {
  state: 'state mismatch',
  id_token: 'invalid ID token',
  nonce: 'nonce mismatch',
  reauthenticate: 'refresh failed; the user must authenticate again',
  provider: 'provider error',
  configuration: 'invalid configuration',
};

/** Client errors. Messages carry categories only, never tokens, codes or secrets. */
export class OIDCError extends Error {
  override readonly name = 'OIDCError';
  readonly code: OIDCErrorCode;
  /** The failed check (e.g. "issuer", "audience", "at_hash") or provider detail. */
  readonly reason: string | undefined;
  /** OAuth error code returned by the provider, when there is one. */
  readonly providerError: string | undefined;
  /** HTTP status from the provider, when there is one. */
  readonly status: number | undefined;

  constructor(
    code: OIDCErrorCode,
    details: { reason?: string; providerError?: string; status?: number; cause?: unknown } = {},
  ) {
    const extra = [details.reason, details.providerError, details.status !== undefined ? `HTTP ${details.status}` : undefined]
      .filter(Boolean)
      .join(', ');
    super(`oidc-client: ${MESSAGES[code]}${extra ? ` (${extra})` : ''}`, details.cause !== undefined ? { cause: details.cause } : undefined);
    this.code = code;
    this.reason = details.reason;
    this.providerError = details.providerError;
    this.status = details.status;
  }
}

export function isOIDCError(err: unknown, code?: OIDCErrorCode): err is OIDCError {
  return err instanceof OIDCError && (code === undefined || err.code === code);
}

/** A URL-safe random value with 256 bits of entropy (state, nonce, PKCE verifier). */
export function randomValue(): string {
  return randomBytes(32).toString('base64url');
}

/** The S256 PKCE challenge for a verifier (RFC 7636). */
export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

export interface OIDCClientConfig {
  issuer: string;
  clientId: string;
  /** Omit for public clients (then client_id is sent in the request body). */
  clientSecret?: string;
  redirectUri: string;
  /** Default ["openid"]. */
  scopes?: string[];
  /** RFC 8707 resource indicator requested by default. */
  resource?: string;
  /** ID-token algorithm allowlist; default RS256, PS256, ES256, EdDSA. */
  algorithms?: string[];
  /** ID-token clock tolerance (default 30 000 ms, at most 60 000). */
  clockSkewMs?: number;
  /** Provider request timeout (default 10 000 ms). */
  timeoutMs?: number;
  /** Minimum spacing of JWKS refreshes for unknown key IDs (default 30 000 ms). */
  jwksMinRefreshIntervalMs?: number;
  fetch?: FetchLike;
  now?: () => number;
}

/**
 * The per-login state. Store it server-side (e.g. keyed by a random value in an
 * HttpOnly cookie), never only in a client-readable cookie, and use it once.
 */
export interface AuthRequest {
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly url: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly createdAt: number;
}

export interface TokenSet {
  readonly accessToken: string;
  readonly tokenType: string;
  readonly expiresIn: number;
  readonly refreshToken: string | undefined;
  readonly idToken: string | undefined;
  readonly scope: string | undefined;
  /** Absolute access-token expiry, milliseconds since the epoch. */
  readonly expiresAt: number;
}

export interface IDTokenClaims {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: readonly string[];
  readonly expiry: Date;
  readonly issuedAt: Date | undefined;
  readonly authTime: Date | undefined;
  readonly nonce: string | undefined;
  readonly acr: string | undefined;
  readonly amr: readonly string[];
  readonly azp: string | undefined;
  readonly sid: string | undefined;
  readonly atHash: string | undefined;
  readonly email: string | undefined;
  readonly name: string | undefined;
  /** Every verified claim, for application-specific fields. */
  readonly claims: Readonly<Record<string, unknown>>;
}

export interface ValidateIDTokenOptions {
  /** The nonce sent in the authorization request; required to match when given. */
  nonce?: string;
  /** The access token issued with the ID token; checked against at_hash when present. */
  accessToken?: string;
  /** Maximum authentication age in seconds (requires auth_time). */
  maxAgeSec?: number;
  signal?: AbortSignal;
}

const RESERVED_AUTH_PARAMS = new Set([
  'client_id',
  'redirect_uri',
  'response_type',
  'state',
  'nonce',
  'code_challenge',
  'code_challenge_method',
  'scope',
  'resource',
  'request',
  'request_uri',
]);

type Metadata = Readonly<Record<string, unknown>>;

// Module-private bridges so Session can use the client's token endpoint and clock.
let TOKEN_REQUEST: (client: OIDCClient, fields: Record<string, string>, signal?: AbortSignal) => Promise<TokenSet>;
let CLIENT_NOW: (client: OIDCClient) => number;
const SESSION_KEY = Symbol('session');

export class OIDCClient {
  readonly #issuer: string;
  readonly #issuerOrigin: string;
  readonly #clientId: string;
  readonly #clientSecret: string | undefined;
  readonly #redirectUri: string;
  readonly #scopes: readonly string[];
  readonly #resource: string | undefined;
  readonly #algorithms: ReadonlySet<string>;
  readonly #skewMs: number;
  readonly #timeoutMs: number;
  readonly #minRefreshMs: number;
  readonly #fetch: FetchLike;
  readonly #now: () => number;
  #meta: Promise<Metadata> | undefined;
  #jwks: JwksCache | undefined;

  constructor(config: OIDCClientConfig) {
    const prefix = 'oidc-client';
    if (!config || !config.issuer || !config.clientId || !config.redirectUri) {
      throw new TypeError('oidc-client: issuer, client ID and redirect URI are required');
    }
    this.#issuerOrigin = requireHttpUrl(config.issuer, 'issuer', prefix).origin;
    requireHttpUrl(config.redirectUri, 'redirectUri', prefix);
    this.#issuer = config.issuer;
    this.#clientId = config.clientId;
    this.#clientSecret = config.clientSecret || undefined;
    this.#redirectUri = config.redirectUri;
    this.#scopes = Object.freeze(config.scopes && config.scopes.length > 0 ? [...config.scopes] : ['openid']);
    this.#resource = config.resource || undefined;
    this.#algorithms = resolveAlgorithms(config.algorithms, prefix);
    this.#skewMs = config.clockSkewMs ?? 30_000;
    if (!Number.isFinite(this.#skewMs) || this.#skewMs < 0 || this.#skewMs > 60_000) {
      throw new TypeError('oidc-client: clock skew must be between 0 and 60s');
    }
    this.#timeoutMs = config.timeoutMs ?? 10_000;
    this.#minRefreshMs = config.jwksMinRefreshIntervalMs ?? 30_000;
    if (!Number.isFinite(this.#minRefreshMs) || this.#minRefreshMs < 1_000) {
      throw new TypeError('oidc-client: jwksMinRefreshIntervalMs must be at least 1000');
    }
    this.#fetch = config.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== 'function') throw new TypeError('oidc-client: no fetch implementation available');
    this.#now = config.now ?? Date.now;
  }

  get issuer(): string {
    return this.#issuer;
  }

  get clientId(): string {
    return this.#clientId;
  }

  /** JWKS fetches made for ID-token validation (diagnostics and tests). */
  get jwksFetchCount(): number {
    return this.#jwks?.fetchCount ?? 0;
  }

  /** Loads (once) and returns the issuer's discovery document. */
  discover(signal?: AbortSignal): Promise<Metadata> {
    if (!this.#meta) {
      const p = this.#loadDiscovery();
      this.#meta = p;
      p.catch(() => {
        if (this.#meta === p) this.#meta = undefined; // retry on the next call
      });
    }
    return waitFor(this.#meta, signal, () => new OIDCError('provider', { reason: 'aborted' }));
  }

  async #loadDiscovery(): Promise<Metadata> {
    const url = this.#issuer.replace(/\/+$/, '') + '/.well-known/openid-configuration';
    const m = await this.#getJSON(url);
    if (m.issuer !== this.#issuer) throw new OIDCError('provider', { reason: 'discovery issuer mismatch' });
    return Object.freeze(m);
  }

  async #getJSON(url: string): Promise<Record<string, unknown>> {
    let res: Response;
    try {
      res = await this.#fetch(url, {
        method: 'GET',
        headers: { accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (cause) {
      throw new OIDCError('provider', { reason: 'unreachable', cause });
    }
    if (res.status !== 200) {
      await discardBody(res);
      throw new OIDCError('provider', { reason: 'metadata request failed', status: res.status });
    }
    try {
      const v = parseStrictJSON(utf8Strict.decode(await readBodyLimited(res, 1 << 20)));
      if (!isPlainObject(v)) throw new Error('not an object');
      return v;
    } catch (cause) {
      throw new OIDCError('provider', { reason: 'invalid metadata', cause });
    }
  }

  async #endpoint(name: string, signal?: AbortSignal): Promise<string> {
    const m = await this.discover(signal);
    const s = m[name];
    if (typeof s !== 'string' || s === '') throw new OIDCError('provider', { reason: `missing endpoint ${name}` });
    let u: URL;
    try {
      u = new URL(s);
    } catch {
      throw new OIDCError('provider', { reason: `invalid endpoint ${name}` });
    }
    // Endpoints must live on the trusted issuer's origin.
    if (u.origin !== this.#issuerOrigin || u.username || u.password) {
      throw new OIDCError('provider', { reason: `endpoint ${name} is not on the issuer origin` });
    }
    return u.href;
  }

  /** Builds an authorization request with state, nonce, PKCE S256 and the resource indicator. */
  async authorizationUrl(
    options: { extraParams?: Record<string, string>; scopes?: string[]; resource?: string; signal?: AbortSignal } = {},
  ): Promise<AuthRequest> {
    const ep = await this.#endpoint('authorization_endpoint', options.signal);
    const scopes = options.scopes && options.scopes.length > 0 ? [...options.scopes] : [...this.#scopes];
    const state = randomValue();
    const nonce = randomValue();
    const codeVerifier = randomValue();
    const u = new URL(ep);
    const q = u.searchParams;
    q.set('client_id', this.#clientId);
    q.set('redirect_uri', this.#redirectUri);
    q.set('response_type', 'code');
    q.set('scope', scopes.join(' '));
    q.set('state', state);
    q.set('nonce', nonce);
    q.set('code_challenge', pkceChallenge(codeVerifier));
    q.set('code_challenge_method', 'S256');
    const resource = options.resource ?? this.#resource;
    if (resource) q.set('resource', resource);
    for (const [k, v] of Object.entries(options.extraParams ?? {})) {
      // Security parameters cannot be overridden through extra parameters.
      if (RESERVED_AUTH_PARAMS.has(k)) throw new TypeError(`oidc-client: ${k} cannot be set through extraParams`);
      q.set(k, v);
    }
    return Object.freeze({
      state,
      nonce,
      codeVerifier,
      url: u.href,
      redirectUri: this.#redirectUri,
      scopes: Object.freeze(scopes),
      createdAt: this.#now(),
    });
  }

  /**
   * Validates the callback (state, RFC 9207 issuer), redeems the code with the PKCE
   * verifier and validates the ID token (nonce, at_hash) before returning tokens.
   * `callback` is the callback URL, its query string, or its parameters.
   */
  async exchangeCode(
    authRequest: AuthRequest,
    callback: string | URL | URLSearchParams | Record<string, string>,
    options: { signal?: AbortSignal } = {},
  ): Promise<{ tokens: TokenSet; idClaims: IDTokenClaims | undefined }> {
    const params = toParams(callback);
    const one = (k: string): string | undefined => {
      const all = params.getAll(k);
      if (all.length > 1) throw new OIDCError('provider', { reason: `duplicate ${k} parameter` });
      return all[0];
    };
    const error = one('error');
    if (!authRequest || typeof authRequest.state !== 'string') throw new OIDCError('state');
    const state = one('state');
    if (!state || !safeEqual(state, authRequest.state)) throw new OIDCError('state');
    const meta = await this.discover(options.signal);
    const iss = one('iss');
    if (iss !== undefined && iss !== this.#issuer) {
      throw new OIDCError('provider', { reason: 'authorization response issuer mismatch (mix-up)' });
    }
    if (iss === undefined && meta.authorization_response_iss_parameter_supported === true) {
      throw new OIDCError('provider', { reason: 'authorization response is missing iss' });
    }
    if (error !== undefined) throw new OIDCError('provider', { providerError: safeCode(error) });
    const code = one('code');
    if (!code) throw new OIDCError('provider', { reason: 'missing authorization code' });

    const tokens = await this.#tokenRequest(
      {
        grant_type: 'authorization_code',
        code,
        code_verifier: authRequest.codeVerifier,
        redirect_uri: authRequest.redirectUri ?? this.#redirectUri,
      },
      options.signal,
    );
    let idClaims: IDTokenClaims | undefined;
    if (tokens.idToken) {
      idClaims = await this.validateIdToken(tokens.idToken, {
        nonce: authRequest.nonce,
        accessToken: tokens.accessToken,
        ...(options.signal ? { signal: options.signal } : {}),
      });
    } else if ((authRequest.scopes ?? this.#scopes).includes('openid')) {
      throw new OIDCError('id_token', { reason: 'missing ID token' });
    }
    return { tokens, idClaims };
  }

  /** Token endpoint call; reachable from Session through a module-private bridge. */
  async #tokenRequest(fields: Record<string, string>, signal?: AbortSignal): Promise<TokenSet> {
    const ep = await this.#endpoint('token_endpoint', signal);
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    };
    const form: Record<string, string> = { ...fields };
    if (this.#clientSecret !== undefined) headers.authorization = basicAuthorization(this.#clientId, this.#clientSecret);
    else form.client_id = this.#clientId;
    let res: Response;
    try {
      res = await this.#fetch(ep, {
        method: 'POST',
        headers,
        body: formBody(form),
        redirect: 'error',
        signal: withTimeout(this.#timeoutMs, signal),
      });
    } catch (cause) {
      throw new OIDCError('provider', { reason: 'token endpoint unreachable', cause });
    }
    let body: unknown;
    try {
      body = parseStrictJSON(utf8Strict.decode(await readBodyLimited(res, 1 << 20)));
    } catch (cause) {
      body = undefined;
      if (res.status === 200) throw new OIDCError('provider', { reason: 'invalid token response', status: 200, cause });
    }
    if (res.status !== 200) {
      const err = isPlainObject(body) && typeof body.error === 'string' ? body.error : undefined;
      if (err === 'invalid_grant') throw new OIDCError('reauthenticate', { providerError: err, status: res.status });
      throw new OIDCError('provider', { reason: 'token endpoint error', ...(err ? { providerError: safeCode(err) } : {}), status: res.status });
    }
    if (!isPlainObject(body)) throw new OIDCError('provider', { reason: 'invalid token response' });
    const { access_token: at, token_type: tt, expires_in: ei, refresh_token: rt, id_token: it, scope } = body;
    if (typeof at !== 'string' || at === '') throw new OIDCError('provider', { reason: 'missing access_token' });
    if (typeof tt !== 'string' || tt.toLowerCase() !== 'bearer') throw new OIDCError('provider', { reason: 'unsupported token_type' });
    if (ei !== undefined && (typeof ei !== 'number' || !Number.isFinite(ei) || ei < 0)) {
      throw new OIDCError('provider', { reason: 'invalid expires_in' });
    }
    const expiresIn = typeof ei === 'number' ? ei : 0;
    return Object.freeze({
      accessToken: at,
      tokenType: tt,
      expiresIn,
      refreshToken: typeof rt === 'string' && rt !== '' ? rt : undefined,
      idToken: typeof it === 'string' && it !== '' ? it : undefined,
      scope: typeof scope === 'string' ? scope : undefined,
      expiresAt: this.#now() + expiresIn * 1000,
    });
  }

  /**
   * Verifies the ID-token signature and then its claims: exact issuer, audience
   * containing this client, azp for multi-audience tokens, expiry, issued-at, nonce
   * and at_hash (OIDC-016). The payload is never trusted before the signature.
   */
  async validateIdToken(raw: string, options: ValidateIDTokenOptions = {}): Promise<IDTokenClaims> {
    const bad = (reason: string): OIDCError => new OIDCError('id_token', { reason });
    if (typeof raw !== 'string' || raw === '' || raw.length > 16384) throw bad('size');
    let jws;
    try {
      jws = parseCompactJWS(raw);
    } catch (e) {
      throw bad(e instanceof JWSParseError && e.reason === 'duplicate' ? 'duplicate member' : 'malformed');
    }
    const { header } = jws;
    if (header.crit !== undefined) throw bad('critical header');
    const alg = header.alg;
    if (typeof alg !== 'string' || !this.#algorithms.has(alg)) throw bad('algorithm');
    if (header.typ !== undefined && (typeof header.typ !== 'string' || header.typ.toLowerCase() !== 'jwt')) {
      throw bad('type'); // an access token (at+jwt) is not an ID token
    }
    const kid = header.kid;
    if (typeof kid !== 'string' || kid === '') throw bad('missing kid');
    const jwks = await this.#keySet(options.signal);
    let key;
    try {
      key = await jwks.getKey(kid, options.signal);
    } catch (e) {
      if (e instanceof JwksError && e.reason === 'unknown_key') throw bad('unknown key');
      throw new OIDCError('provider', { reason: 'key set unavailable', cause: e });
    }
    if (key.alg !== undefined && key.alg !== alg) throw bad('algorithm');
    if (!verifySignature(alg, key.key, jws.signingInput, jws.signature)) throw bad('signature');

    const p = jws.payload;
    const optStr = (k: string): string | undefined => {
      const v = p[k];
      if (v === undefined || v === null) return undefined;
      if (typeof v !== 'string') throw bad(`claim ${k}`);
      return v;
    };
    const optNum = (k: string): number | undefined => {
      const v = p[k];
      if (v === undefined || v === null) return undefined;
      if (typeof v !== 'number' || !Number.isFinite(v)) throw bad(`claim ${k}`);
      return v;
    };
    let audience: string[];
    if (typeof p.aud === 'string') audience = [p.aud];
    else if (Array.isArray(p.aud) && p.aud.every((a) => typeof a === 'string')) audience = p.aud as string[];
    else throw bad('audience');
    const iss = optStr('iss');
    const sub = optStr('sub');
    const azp = optStr('azp');
    const exp = optNum('exp');
    const iat = optNum('iat');
    const authTime = optNum('auth_time');
    const nonce = optStr('nonce');
    const atHash = optStr('at_hash');
    const nowSec = this.#now() / 1000;
    const skewSec = this.#skewMs / 1000;
    if (iss !== this.#issuer) throw bad('issuer');
    if (!sub) throw bad('subject');
    if (!audience.includes(this.#clientId)) throw bad('audience');
    if (audience.length > 1 && azp !== this.#clientId) throw bad('authorized party');
    if (azp !== undefined && azp !== this.#clientId) throw bad('authorized party');
    if (exp === undefined || nowSec > exp + skewSec) throw bad('expired');
    if (iat !== undefined && iat > nowSec + skewSec) throw bad('issued in the future');
    if (options.nonce !== undefined && options.nonce !== '' && (nonce === undefined || !safeEqual(nonce, options.nonce))) {
      throw new OIDCError('nonce');
    }
    if (options.accessToken && atHash !== undefined && !safeEqual(atHash, halfHash(alg, options.accessToken))) {
      throw bad('at_hash');
    }
    if (options.maxAgeSec !== undefined && (authTime === undefined || nowSec - authTime > options.maxAgeSec + skewSec)) {
      throw bad('max_age');
    }
    const amr = Array.isArray(p.amr) ? p.amr.filter((x): x is string => typeof x === 'string') : [];
    return Object.freeze({
      issuer: iss,
      subject: sub,
      audience: Object.freeze(audience),
      expiry: new Date(exp * 1000),
      issuedAt: iat !== undefined ? new Date(iat * 1000) : undefined,
      authTime: authTime !== undefined && authTime > 0 ? new Date(authTime * 1000) : undefined,
      nonce,
      acr: optStr('acr'),
      amr: Object.freeze(amr),
      azp,
      sid: optStr('sid'),
      atHash,
      email: typeof p.email === 'string' ? p.email : undefined,
      name: typeof p.name === 'string' ? p.name : undefined,
      claims: p,
    });
  }

  async #keySet(signal?: AbortSignal): Promise<JwksCache> {
    if (!this.#jwks) {
      const url = await this.#endpoint('jwks_uri', signal);
      this.#jwks ??= new JwksCache({
        url,
        fetch: this.#fetch,
        timeoutMs: this.#timeoutMs,
        minRefreshIntervalMs: this.#minRefreshMs,
        now: this.#now,
      });
    }
    return this.#jwks;
  }

  /**
   * Wraps tokens in a Session with single-flight refresh. Keep exactly one Session
   * per browser session in this process.
   */
  session(tokens: TokenSet, options: SessionOptions = {}): Session {
    return new Session(this, tokens, options, SESSION_KEY);
  }

  /** Revokes a token at the provider (RFC 7009); used at logout. */
  async revoke(token: string, options: { tokenTypeHint?: 'refresh_token' | 'access_token'; signal?: AbortSignal } = {}): Promise<void> {
    if (typeof token !== 'string' || token === '') return;
    const ep = await this.#endpoint('revocation_endpoint', options.signal);
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
    const form: Record<string, string> = { token, token_type_hint: options.tokenTypeHint ?? 'refresh_token' };
    if (this.#clientSecret !== undefined) headers.authorization = basicAuthorization(this.#clientId, this.#clientSecret);
    else form.client_id = this.#clientId;
    let res: Response;
    try {
      res = await this.#fetch(ep, {
        method: 'POST',
        headers,
        body: formBody(form),
        redirect: 'error',
        signal: withTimeout(this.#timeoutMs, options.signal),
      });
    } catch (cause) {
      throw new OIDCError('provider', { reason: 'revocation endpoint unreachable', cause });
    }
    await discardBody(res);
    if (res.status !== 200) throw new OIDCError('provider', { reason: 'revocation failed', status: res.status });
  }

  /** Builds an RP-initiated logout URL. */
  async logoutUrl(
    options: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string; signal?: AbortSignal } = {},
  ): Promise<string> {
    const ep = await this.#endpoint('end_session_endpoint', options.signal);
    const u = new URL(ep);
    if (options.idTokenHint) u.searchParams.set('id_token_hint', options.idTokenHint);
    u.searchParams.set('client_id', this.#clientId);
    if (options.postLogoutRedirectUri) u.searchParams.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
    if (options.state) u.searchParams.set('state', options.state);
    return u.href;
  }

  /**
   * Ends a session: clears it locally, revokes its refresh token and returns the
   * RP-initiated logout URL. The local session is cleared even when revocation fails
   * (the error is then rethrown after clearing).
   */
  async logout(
    session: Session,
    options: { postLogoutRedirectUri?: string; state?: string; signal?: AbortSignal } = {},
  ): Promise<string> {
    const tokens = session.tokens;
    session.clear();
    const url = await this.logoutUrl({
      ...(tokens?.idToken ? { idTokenHint: tokens.idToken } : {}),
      ...options,
    });
    if (tokens?.refreshToken) {
      await this.revoke(tokens.refreshToken, { tokenTypeHint: 'refresh_token', ...(options.signal ? { signal: options.signal } : {}) });
    }
    return url;
  }

  static {
    TOKEN_REQUEST = (client, fields, signal) => client.#tokenRequest(fields, signal);
    CLIENT_NOW = (client) => client.#now();
  }
}

export interface SessionOptions {
  /** Claims of the ID token from login; refreshed ID tokens must keep the same subject. */
  idClaims?: IDTokenClaims;
  /**
   * Called after every successful refresh so the new (rotated) tokens can be
   * persisted server-side. Refresh tokens rotate; persisting the old one and using
   * it again is reuse and revokes the whole family.
   */
  onRefresh?: (tokens: TokenSet) => void | Promise<void>;
  /** Refresh when the access token expires within this window (default 15 000 ms). */
  refreshWindowMs?: number;
}

/**
 * Server-side tokens for one browser session. Refresh is single-flight: concurrent
 * callers share one refresh request, so the same refresh token is never presented
 * twice (SES-009, TEST-030). A failed refresh clears the session (a lost refresh
 * response cannot be retried safely, §24.3): the user must authenticate again.
 *
 * Single-flight is per process. With several BFF instances, route a session to
 * one instance or serialize refresh with a distributed lock.
 */
export class Session {
  readonly #client: OIDCClient;
  #tokens: TokenSet | undefined;
  #idClaims: IDTokenClaims | undefined;
  #inflight: Promise<string> | undefined;
  readonly #onRefresh: SessionOptions['onRefresh'];
  readonly #windowMs: number;
  #refreshCount = 0;

  /** Use `OIDCClient.session()`. */
  constructor(client: OIDCClient, tokens: TokenSet, options: SessionOptions, key: symbol) {
    if (key !== SESSION_KEY) throw new TypeError('oidc-client: use OIDCClient.session() to create sessions');
    this.#client = client;
    this.#tokens = tokens;
    this.#idClaims = options.idClaims;
    this.#onRefresh = options.onRefresh;
    this.#windowMs = options.refreshWindowMs ?? 15_000;
  }

  /** Current tokens, or undefined after logout or a failed refresh. */
  get tokens(): TokenSet | undefined {
    return this.#tokens;
  }

  get idClaims(): IDTokenClaims | undefined {
    return this.#idClaims;
  }

  /** Refresh requests made by this session (diagnostics and tests). */
  get refreshCount(): number {
    return this.#refreshCount;
  }

  /** Forgets the tokens locally (does not revoke; see OIDCClient.logout). */
  clear(): void {
    this.#tokens = undefined;
  }

  /**
   * Returns a valid access token, refreshing once when it is about to expire.
   * Pass `rejectedToken` when an API rejected the current access token to force one
   * refresh; concurrent callers that saw the same token share it.
   */
  accessToken(options: { rejectedToken?: string; signal?: AbortSignal } = {}): Promise<string> {
    const aborted = (): Error => new OIDCError('provider', { reason: 'aborted' });
    if (this.#inflight) return waitFor(this.#inflight, options.signal, aborted);
    const t = this.#tokens;
    if (!t) return Promise.reject(new OIDCError('reauthenticate'));
    const forced = options.rejectedToken !== undefined && options.rejectedToken === t.accessToken;
    if (!forced && CLIENT_NOW(this.#client) + this.#windowMs < t.expiresAt) return Promise.resolve(t.accessToken);
    if (!t.refreshToken) return Promise.reject(new OIDCError('reauthenticate'));
    const p = this.#refresh(t);
    this.#inflight = p;
    const clear = (): void => {
      if (this.#inflight === p) this.#inflight = undefined;
    };
    p.then(clear, clear);
    return waitFor(p, options.signal, aborted);
  }

  async #refresh(current: TokenSet): Promise<string> {
    let next: TokenSet;
    try {
      this.#refreshCount++;
      // The shared refresh is bounded by the client timeout only: one caller giving
      // up must not abandon a rotation whose response the others still need.
      const nt = await TOKEN_REQUEST(this.#client, { grant_type: 'refresh_token', refresh_token: current.refreshToken! });
      let idClaims = this.#idClaims;
      if (nt.idToken) {
        const c = await this.#client.validateIdToken(nt.idToken, { accessToken: nt.accessToken });
        if (this.#idClaims && c.subject !== this.#idClaims.subject) {
          throw new OIDCError('id_token', { reason: 'refreshed ID token subject changed' });
        }
        idClaims = c;
      }
      next = Object.freeze({
        ...nt,
        refreshToken: nt.refreshToken ?? current.refreshToken,
        idToken: nt.idToken ?? current.idToken,
      });
      this.#idClaims = idClaims;
    } catch (err) {
      this.#tokens = undefined;
      if (isOIDCError(err, 'reauthenticate')) throw err;
      throw new OIDCError('reauthenticate', { reason: isOIDCError(err) ? err.code : 'refresh failed', cause: err });
    }
    this.#tokens = next;
    if (this.#onRefresh) await this.#onRefresh(next);
    return next.accessToken;
  }
}

function toParams(callback: string | URL | URLSearchParams | Record<string, string>): URLSearchParams {
  if (callback instanceof URLSearchParams) return callback;
  if (callback instanceof URL) return callback.searchParams;
  if (typeof callback === 'string') {
    if (/^https?:\/\//i.test(callback)) return new URL(callback).searchParams;
    const q = callback.indexOf('?');
    return new URLSearchParams(q >= 0 ? callback.slice(q + 1) : callback);
  }
  return new URLSearchParams(callback);
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Provider error codes are echoed only when they look like OAuth error codes. */
function safeCode(s: string): string {
  return /^[a-z0-9_.-]{1,64}$/i.test(s) ? s : 'unrecognized_error';
}

/** at_hash / c_hash: left half of the hash matching the signing algorithm (OIDC Core §3.1.3.6). */
export function halfHash(alg: string, value: string): string {
  const h = alg === 'EdDSA' ? 'sha512' : 'sha256';
  const d = createHash(h).update(value, 'utf8').digest();
  return d.subarray(0, d.length / 2).toString('base64url');
}
