/**
 * Strict-online token validation (§13.2, SDK-002) and the downstream support-access
 * contract (§16.2), a port of the Go SDK's Introspector and SupportGuard.
 *
 * Every call consults the identity provider's authoritative state through RFC 7662
 * introspection. There is no positive cache, and any failure (network error,
 * timeout, non-200, unparsable response) denies with an `unavailable` error rather
 * than downgrading to offline checks (TEST-035).
 */

import { Claims, type Actor } from './claims.js';
import { VerifierError } from './errors.js';
import {
  basicAuthorization,
  discardBody,
  formBody,
  readBodyLimited,
  requireHttpUrl,
  utf8Strict,
  withTimeout,
  type FetchLike,
} from './internal/http.js';
import { isPlainObject, parseStrictJSON } from './internal/json.js';
import {
  attachClaims,
  bearerToken,
  challenge,
  reportError,
  sendChallenge,
  type Authenticator,
  type MiddlewareOptions,
  type NextFunction,
  type RequestLike,
  type ResponseLike,
} from './middleware.js';

export { Claims, type Actor, type ClaimsInit } from './claims.js';
export { VerifierError, isVerifierError, VERIFIER_ERROR_CODES, type VerifierErrorCode } from './errors.js';
export {
  authenticateRequest,
  bearerToken,
  challenge,
  getClaims,
  middleware,
  protect,
  requireScopes,
  sendChallenge,
  type AuthChallenge,
  type Authenticator,
  type ChallengeOptions,
  type MiddlewareOptions,
  type NextFunction,
  type RequestLike,
  type ResponseLike,
} from './middleware.js';

/** Token kinds the Introspector accepts by default (support tokens only via SupportGuard). */
export const DEFAULT_ONLINE_KINDS = Object.freeze(['user_access', 'service_access', 'exchange_access', 'api_key', 'personal_access']);

export const SUPPORT_TOKEN_KIND = 'impersonation_access';

export interface IntrospectorConfig {
  /** The issuer's introspection endpoint, e.g. `${issuer}/oauth/introspect`. */
  endpoint: string;
  /** This resource server's confidential client credentials (client_secret_basic). */
  clientId: string;
  clientSecret: string;
  /** Exact expected issuer of introspected tokens. */
  issuer: string;
  /** This API's audience; tokens for any other audience are rejected. */
  audience: string;
  /** Per-request deadline (default 3 000 ms). Timeouts deny. */
  timeoutMs?: number;
  /**
   * Accepted token_kind values for `authenticate` (default: user_access,
   * service_access, exchange_access, api_key, personal_access).
   * impersonation_access is refused here: support tokens go through SupportGuard.
   */
  acceptedKinds?: string[];
  /** Tokens longer than this are rejected without a network call (default 8192). */
  maxTokenBytes?: number;
  fetch?: FetchLike;
}

interface IntrospectorInternals {
  introspect(raw: string, signal: AbortSignal | undefined): Promise<Claims>;
  acceptsKind(kind: string): boolean;
}

// Module-private capabilities shared with SupportGuard; not reachable from outside.
const INTERNALS = new WeakMap<Introspector, IntrospectorInternals>();

function internals(i: Introspector): IntrospectorInternals {
  const x = INTERNALS.get(i);
  if (!x) throw new VerifierError('contract');
  return x;
}

/** Strict-online authenticator. Implements Authenticator for the HTTP adapters. */
export class Introspector implements Authenticator {
  readonly #endpoint: string;
  readonly #authorization: string;
  readonly #issuer: string;
  readonly #audience: string;
  readonly #timeoutMs: number;
  readonly #kinds: ReadonlySet<string>;
  readonly #maxTokenBytes: number;
  readonly #fetch: FetchLike;

  constructor(config: IntrospectorConfig) {
    const prefix = 'introspection';
    if (!config) throw new TypeError('introspection: configuration is required');
    this.#endpoint = requireHttpUrl(config.endpoint, 'endpoint', prefix).href;
    for (const k of ['clientId', 'clientSecret', 'issuer', 'audience'] as const) {
      if (typeof config[k] !== 'string' || config[k] === '') throw new TypeError(`introspection: ${k} is required`);
    }
    this.#authorization = basicAuthorization(config.clientId, config.clientSecret);
    this.#issuer = config.issuer;
    this.#audience = config.audience;
    this.#timeoutMs = config.timeoutMs ?? 3_000;
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) throw new TypeError('introspection: timeoutMs must be positive');
    const kinds = config.acceptedKinds && config.acceptedKinds.length > 0 ? config.acceptedKinds : DEFAULT_ONLINE_KINDS;
    if (kinds.includes(SUPPORT_TOKEN_KIND)) {
      throw new TypeError('introspection: impersonation_access must be handled by a SupportGuard, not accepted as an ordinary kind');
    }
    this.#kinds = new Set(kinds);
    this.#maxTokenBytes = config.maxTokenBytes ?? 8192;
    this.#fetch = config.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== 'function') throw new TypeError('introspection: no fetch implementation available');
    INTERNALS.set(this, {
      introspect: (raw, signal) => this.#introspect(raw, signal),
      acceptsKind: (kind) => this.#kinds.has(kind),
    });
  }

  get issuer(): string {
    return this.#issuer;
  }

  get audience(): string {
    return this.#audience;
  }

  /** Introspects and checks issuer and audience; no token-kind policy. */
  async #introspect(raw: string, signal: AbortSignal | undefined): Promise<Claims> {
    if (typeof raw !== 'string' || raw === '') throw new VerifierError('missing_token');
    if (Buffer.byteLength(raw, 'utf8') > this.#maxTokenBytes) throw new VerifierError('too_large');
    let res: Response;
    try {
      res = await this.#fetch(this.#endpoint, {
        method: 'POST',
        headers: {
          authorization: this.#authorization,
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: formBody({ token: raw }),
        redirect: 'error',
        signal: withTimeout(this.#timeoutMs, signal),
      });
    } catch (cause) {
      throw new VerifierError('unavailable', { cause });
    }
    let m: unknown;
    try {
      if (res.status !== 200) {
        await discardBody(res);
        throw new Error(`introspection endpoint returned HTTP ${res.status}`);
      }
      const body = await readBodyLimited(res, 64 << 10);
      m = parseStrictJSON(utf8Strict.decode(body));
    } catch (cause) {
      throw new VerifierError('unavailable', { cause });
    }
    if (!isPlainObject(m)) throw new VerifierError('unavailable');
    if (m.active !== true) throw new VerifierError('inactive');
    const c = toClaims(m);
    if (c.issuer !== this.#issuer) throw new VerifierError('issuer');
    if (c.audience !== this.#audience) throw new VerifierError('audience');
    return c;
  }

  /** Verifies a non-support token online. */
  async authenticate(raw: string, options: { signal?: AbortSignal } = {}): Promise<Claims> {
    const c = await this.#introspect(raw, options.signal);
    if (!this.#kinds.has(c.tokenKind)) {
      // A support token presented to an API path that has not implemented the
      // support contract is rejected (IMP-001, TEST-045).
      throw new VerifierError('token_kind');
    }
    return c;
  }
}

function toClaims(m: Record<string, unknown>): Claims {
  if (Object.hasOwn(m, 'cnf')) throw new VerifierError('sender_constraint');
  const str = (k: string): string => (typeof m[k] === 'string' ? (m[k] as string) : '');
  const num = (k: string): number => {
    const v = m[k];
    return typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0;
  };
  const date = (k: string): Date | undefined => {
    const v = num(k);
    return v > 0 ? new Date(v * 1000) : undefined;
  };
  let audience = '';
  if (typeof m.aud === 'string') audience = m.aud;
  else if (Array.isArray(m.aud) && m.aud.length === 1 && typeof m.aud[0] === 'string') audience = m.aud[0];
  return new Claims({
    issuer: str('iss'),
    subject: str('sub'),
    audience,
    clientId: str('client_id'),
    scopes: str('scope').split(/\s+/).filter(Boolean),
    orgId: str('org_id'),
    sessionId: str('sid'),
    tokenKind: str('token_kind'),
    jti: str('jti'),
    acr: str('acr'),
    authzVersion: num('authz_version'),
    supportMode: str('support_mode'),
    impersonationGrantId: str('impersonation_grant_id'),
    expiry: date('exp'),
    issuedAt: date('iat'),
    authTime: date('auth_time'),
    actor: parseActorLenient(m.act, 0),
    online: true,
  });
}

function parseActorLenient(v: unknown, depth: number): Actor | undefined {
  if (depth > 16 || !isPlainObject(v)) return undefined;
  const out: { issuer?: string; subject: string; act?: Actor } = { subject: typeof v.sub === 'string' ? v.sub : '' };
  if (typeof v.iss === 'string') out.issuer = v.iss;
  const nested = parseActorLenient(v.act, depth + 1);
  if (nested) out.act = nested;
  return out;
}

// ---------------------------------------------------------------------------
// Support-access contract
// ---------------------------------------------------------------------------

/**
 * Operations that can never be performed with support access (IMP-012, IMP-013).
 * Each entry is one or more operation-name segments; see `isProtectedOperation`
 * for how they match (the same rule as the Go SDK's IsProtectedOperation).
 */
export const PROTECTED_OPERATIONS = Object.freeze([
  'password.change',
  'password.reset',
  'mfa.change',
  'identifier.change',
  'account.link',
  'credential.export',
  'api_key.create',
  'personal_token.create',
  'consent.modify',
  'idp.admin',
  'payment',
  'refund',
  'ownership.transfer',
  'secret.read',
  'secret',
  'delete',
  'purge',
]);

/**
 * Verbs that make an operation a write wherever they appear as a segment of its
 * name, even when the caller declared it a read ("orders.read.update" is a
 * write). Matching is exact per segment. Same list as the Go SDK's WriteSegments.
 */
export const WRITE_SEGMENTS = Object.freeze([
  'create', 'add', 'insert', 'update', 'edit', 'modify', 'change', 'set', 'put', 'patch', 'write',
  'upsert', 'replace', 'delete', 'remove', 'destroy', 'erase', 'purge', 'archive', 'unarchive', 'restore', 'reset', 'rotate',
  'revoke', 'grant', 'assign', 'unassign', 'link', 'unlink', 'transfer', 'issue', 'approve', 'reject', 'cancel', 'enable',
  'disable', 'suspend', 'reactivate', 'activate', 'deactivate', 'lock', 'unlock', 'invite', 'send', 'submit', 'publish',
  'unpublish', 'import', 'merge', 'move', 'rename', 'refund', 'pay', 'execute',
]);

const WRITE_SEGMENT_SET: ReadonlySet<string> = new Set(WRITE_SEGMENTS);

/**
 * Normalizes an operation name for classification: trimmed, lowercased, '-' read
 * as '_', split into segments on '.', ':' and '/', empty segments dropped.
 */
function operationSegments(operation: string): string[] {
  if (typeof operation !== 'string') return [];
  return operation
    .trim()
    .toLowerCase()
    .replace(/-/g, '_')
    .split(/[.:/]/)
    .filter((s) => s !== '');
}

/** One operation segment matches one entry segment, tolerating a simple plural on either side. */
function segmentMatches(seg: string, entry: string): boolean {
  return seg === entry || seg === entry + 's' || seg + 's' === entry;
}

/** Whether `entry`'s segments occur as a contiguous run in `segs`. */
function containsRun(segs: readonly string[], entry: readonly string[]): boolean {
  if (entry.length === 0 || entry.length > segs.length) return false;
  for (let start = 0; start + entry.length <= segs.length; start++) {
    if (entry.every((e, k) => segmentMatches(segs[start + k]!, e))) return true;
  }
  return false;
}

/**
 * Reports whether `operation` touches a protected identity, money or secret
 * operation anywhere in its name under the given list (default
 * PROTECTED_OPERATIONS): the segments of an entry occur as a contiguous run of
 * the operation's segments, case-insensitively and tolerating simple plurals
 * ("orders.refund", "refunds.issue", "payments.create", "secrets.read",
 * "orders.purge", "users.password.change", "Account.Delete"). An empty operation
 * is treated as protected (deny by default).
 */
export function isProtectedOperation(operation: string, protectedOps: readonly string[] = PROTECTED_OPERATIONS): boolean {
  const segs = operationSegments(operation);
  if (segs.length === 0) return true;
  return protectedOps.some((p) => containsRun(segs, operationSegments(p)));
}

/**
 * Reports whether any segment of `operation` is a write-like verb
 * (WRITE_SEGMENTS). Such operations are writes even when declared reads.
 */
export function isWriteOperation(operation: string): boolean {
  return operationSegments(operation).some((s) => WRITE_SEGMENT_SET.has(s));
}

/** The actor-aware record a resource must persist for every support request (IMP-006). */
export interface SupportEvent {
  grantId: string;
  /** The real administrator (act.sub). */
  actor: string;
  actorIssuer: string | undefined;
  /** The effective customer subject. */
  subject: string;
  orgId: string;
  clientId: string;
  tokenId: string;
  operation: string;
  /** Effective classification: false when declared a write or the name carries a write-like segment. */
  read: boolean;
  allowed: boolean;
  /** Why access was denied, when it was. */
  denyReason: 'protected_operation' | 'write_not_allowlisted' | undefined;
  at: Date;
}

/**
 * Persists support evidence. It is called BEFORE access is granted; if it throws
 * or rejects, access is denied. A resource that cannot record the actor must not
 * serve support requests.
 */
export interface SupportAuditor {
  recordSupportAccess(event: SupportEvent, options: { signal?: AbortSignal }): Promise<void> | void;
}

export interface SupportGuardConfig {
  introspector: Introspector;
  auditor: SupportAuditor | ((event: SupportEvent, options: { signal?: AbortSignal }) => Promise<void> | void);
  /**
   * Operations allowed for tokens in allowlisted_write mode (IMP-011), matched
   * case-insensitively against the whole operation name. Default: none.
   */
  writeOperations?: string[];
  /** Additional protected operations; the defaults cannot be removed. */
  protectedOperations?: string[];
}

export interface AuthorizeOptions {
  /**
   * True only for non-mutating operations. Anything else is treated as a write,
   * and so is an operation whose name carries a write-like segment.
   */
  read: boolean;
  signal?: AbortSignal;
}

/**
 * Implements the downstream support-access contract: strict-online validation per
 * request, preserved actor identity, read-only default, explicit write allowlist,
 * protected identity operations always denied, and an audit record before access
 * (§16.2, INT-010).
 */
export class SupportGuard {
  readonly #introspector: Introspector | undefined;
  readonly #record: ((event: SupportEvent, options: { signal?: AbortSignal }) => Promise<void> | void) | undefined;
  readonly #writeOps: ReadonlySet<string>;
  readonly #protected: readonly string[];

  constructor(config: SupportGuardConfig) {
    this.#introspector = config?.introspector instanceof Introspector ? config.introspector : undefined;
    const a = config?.auditor;
    if (typeof a === 'function') this.#record = a;
    else if (a && typeof a.recordSupportAccess === 'function') this.#record = (ev, o) => a.recordSupportAccess(ev, o);
    this.#writeOps = new Set((config?.writeOperations ?? []).map((o) => o.trim().toLowerCase()));
    this.#protected = Object.freeze([...PROTECTED_OPERATIONS, ...(config?.protectedOperations ?? [])]);
    this.validate();
  }

  /** Checks the guard configuration (contract validation); throws a `contract` VerifierError. */
  validate(): void {
    if (!this.#introspector || !this.#record) throw new VerifierError('contract');
  }

  /**
   * Validates a support token for one operation. The audit record is written before
   * access is granted; if it cannot be written, access is denied (`unavailable`).
   * Policy denials are audited too and reject with `support_policy`.
   */
  async authorize(raw: string, operation: string, options: AuthorizeOptions): Promise<Claims> {
    this.validate();
    const c = await internals(this.#introspector!).introspect(raw, options?.signal);
    return this.#decide(c, operation, options);
  }

  /**
   * Single-introspection entry point for APIs that serve both ordinary and support
   * requests: ordinary tokens are checked against the Introspector's accepted kinds,
   * support tokens against the full support contract. The decision is based on the
   * authoritative token_kind, never on the token's prefix.
   */
  async authorizeAny(raw: string, operation: string, options: AuthorizeOptions): Promise<Claims> {
    this.validate();
    const intro = internals(this.#introspector!);
    const c = await intro.introspect(raw, options?.signal);
    if (c.tokenKind === SUPPORT_TOKEN_KIND) return this.#decide(c, operation, options);
    if (!intro.acceptsKind(c.tokenKind)) throw new VerifierError('token_kind');
    return c;
  }

  /**
   * Express/Connect middleware for one route operation using `authorizeAny`.
   * 401 invalid token, 403 support policy, 503 unavailable or audit failure.
   */
  middleware(route: { operation: string; read: boolean }, options: MiddlewareOptions = {}) {
    if (!route || typeof route.operation !== 'string' || route.operation === '') {
      throw new TypeError('introspection: route operation is required');
    }
    return (req: RequestLike, res: ResponseLike, next: NextFunction): void => {
      const run = async (): Promise<void> => {
        let claims: Claims;
        try {
          claims = await this.authorizeAny(bearerToken(req), route.operation, { read: route.read === true });
        } catch (err) {
          reportError(err, req, options);
          sendChallenge(res, challenge(err, options));
          return;
        }
        attachClaims(req, claims, options);
        next();
      };
      run().catch(next);
    };
  }

  async #decide(c: Claims, operation: string, options: AuthorizeOptions): Promise<Claims> {
    if (c.tokenKind !== SUPPORT_TOKEN_KIND || !c.actor || c.actor.subject === '' || c.impersonationGrantId === '') {
      // Never grant authority just because an actor claim exists, and never serve a
      // support request whose actor cannot be attributed (IMP-006, TEST-045).
      throw new VerifierError('token_kind');
    }
    if (typeof operation !== 'string' || operation.trim() === '') throw new VerifierError('support_policy');
    const read = options?.read === true && !isWriteOperation(operation);
    let denyReason: SupportEvent['denyReason'];
    if (isProtectedOperation(operation, this.#protected)) denyReason = 'protected_operation';
    else if (!read && (c.supportMode !== 'allowlisted_write' || !this.#writeOps.has(operation.trim().toLowerCase()))) {
      denyReason = 'write_not_allowlisted';
    }
    const allowed = denyReason === undefined;
    const event: SupportEvent = {
      grantId: c.impersonationGrantId,
      actor: c.actor.subject,
      actorIssuer: c.actor.issuer,
      subject: c.subject,
      orgId: c.orgId,
      clientId: c.clientId,
      tokenId: c.jti,
      operation,
      read,
      allowed,
      denyReason,
      at: new Date(),
    };
    try {
      await this.#record!(event, options?.signal ? { signal: options.signal } : {});
    } catch (cause) {
      // Durable audit before access (IMP-020): no record, no access.
      throw new VerifierError('unavailable', { cause });
    }
    if (!allowed) throw new VerifierError('support_policy');
    return c;
  }
}
