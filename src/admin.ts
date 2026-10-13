/**
 * Typed client for the ProudAuth administration and self-service APIs (SDK-003,
 * SDK-007), a port of the Go SDK's admin package. It preserves RFC 9457 problem
 * details, iterates opaque-cursor pages, supports deadlines and cancellation via
 * AbortSignal, idempotency keys and If-Match preconditions, sends its version,
 * reports deprecated operations, wraps one-time secrets in Secret, and never
 * logs request bodies or tokens (SDK-008).
 */

import { randomBytes } from 'node:crypto';
import { STATUS_CODES } from 'node:http';
import { readBodyLimited, requireHttpUrl, withTimeout, type FetchLike } from './internal/http.js';
import { isPlainObject } from './internal/json.js';

/** This SDK's version, sent with every request. */
export const SDK_VERSION = '0.2.0';

const inspectCustom = Symbol.for('nodejs.util.inspect.custom');

/**
 * A one-time secret returned by the API: a client secret, API key, webhook
 * signing secret, setup or handoff code, download token or recovery code
 * (SDK-007, SDK-008). It never prints, logs or serializes its value;
 * reveal() returns it for the one place that must store it.
 */
export class Secret {
  readonly #value: string;
  constructor(value: string) {
    this.#value = value;
  }
  reveal(): string {
    return this.#value;
  }
  toString(): string {
    return this.#value ? '[REDACTED]' : '';
  }
  toJSON(): string {
    return this.toString();
  }
  [inspectCustom](): string {
    return `Secret(${this.toString()})`;
  }
}

/** Response members that carry one-time secrets (the server's list for its idempotency store). */
const SECRET_MEMBERS = new Set([
  'client_secret', 'client_secrets', 'api_key', 'signing_secret', 'setup_token', 'recovery_codes', 'invitation_secret',
  'access_token', 'refresh_token', 'id_token', 'handoff_code', 'download_token', 'token', 'secret', 'webhook_secrets',
]);

function seal(v: unknown): unknown {
  if (typeof v === 'string') return new Secret(v);
  if (Array.isArray(v)) return v.map(seal);
  if (isPlainObject(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, seal(x)]));
  return v;
}

/** Replaces secret-bearing values in a decoded response with Secret, recursively. */
function wrapSecrets(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(wrapSecrets);
  if (isPlainObject(v)) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, SECRET_MEMBERS.has(k) ? seal(x) : wrapSecrets(x)]));
  }
  return v;
}

/** An RFC 9457 problem returned by the API (API-007). */
export class ProblemError extends Error {
  override readonly name = 'ProblemError';
  readonly status: number;
  /** Stable machine-readable code. */
  readonly code: string;
  readonly title: string;
  readonly detail: string;
  readonly type: string | undefined;
  readonly instance: string | undefined;
  /** Field-level validation errors. */
  readonly errors: Readonly<Record<string, string>>;
  readonly requestId: string;
  /** Every member of the problem document, for extension members. */
  readonly extra: Readonly<Record<string, unknown>>;
  /** Response headers (e.g. Retry-After on 429). */
  readonly headers: Headers;

  constructor(status: number, body: Record<string, unknown>, headers: Headers) {
    const s = (k: string): string => (typeof body[k] === 'string' ? (body[k] as string) : '');
    const code = s('code') || STATUS_CODES[status] || `HTTP ${status}`;
    const title = s('title');
    const detail = s('detail');
    const errors: Record<string, string> = {};
    if (isPlainObject(body.errors)) {
      for (const [k, v] of Object.entries(body.errors)) if (typeof v === 'string') errors[k] = v;
    }
    let msg = `${status} ${code}: ${title}`;
    if (detail) msg += ` (${detail})`;
    for (const [k, v] of Object.entries(errors)) msg += ` [${k}: ${v}]`;
    super(msg);
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
    this.type = s('type') || undefined;
    this.instance = s('instance') || undefined;
    this.errors = Object.freeze(errors);
    this.requestId = s('request_id') || headers.get('x-request-id') || '';
    this.extra = Object.freeze({ ...body });
    this.headers = headers;
  }
}

export type AdminErrorCode = 'timeout' | 'aborted' | 'network' | 'invalid_response' | 'token_source';

/** Transport-level failures. Never contain request bodies or credentials. */
export class AdminRequestError extends Error {
  override readonly name = 'AdminRequestError';
  constructor(
    readonly code: AdminErrorCode,
    readonly method: string,
    readonly path: string,
    options?: { cause?: unknown },
  ) {
    super(`admin: ${method} ${path} failed (${code})`, options);
  }
}

/** Supplies bearer tokens; called once per request. */
export type TokenSource = string | ((signal: AbortSignal) => string | Promise<string>);

export interface AdminClientConfig {
  /** e.g. https://id.example.com */
  baseUrl: string;
  realm: string;
  token?: TokenSource;
  /** Default request deadline (default 30 000 ms). */
  timeoutMs?: number;
  userAgent?: string;
  fetch?: FetchLike;
  /** Maximum response size (default 32 MiB). */
  maxResponseBytes?: number;
  /** Called for responses of operations the server marks deprecated (Deprecation and Sunset headers, API-013). */
  onDeprecated?: (info: { method: string; path: string; deprecation: string; sunset: string | undefined }) => void;
}

export interface RequestOptions {
  /** Idempotency key for safe retries of creates (API-005). */
  idempotencyKey?: string;
  /** Optimistic-concurrency precondition (API-010). */
  ifMatch?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface AdminResponse<T> {
  status: number;
  headers: Headers;
  /** ETag of the returned representation, for If-Match. */
  etag: string | undefined;
  /** Set when the server marks the operation deprecated (API-013). */
  deprecation: string | undefined;
  sunset: string | undefined;
  data: T;
}

export interface Page<T> {
  items: T[];
  nextCursor: string;
}

export interface User {
  id: string;
  state: string;
  display_name: string;
  identifiers: Record<string, unknown>[];
  version: number;
  [k: string]: unknown;
}

export interface Organization {
  id: string;
  slug: string;
  display_name: string;
  state: string;
  version: number;
  [k: string]: unknown;
}

export interface Membership {
  id: string;
  user_id: string;
  state: string;
  roles: string[];
  [k: string]: unknown;
}

export interface Role {
  id: string;
  name: string;
  boundary_type: string;
  permissions: string[];
  [k: string]: unknown;
}

export interface OAuthClientSummary {
  id: string;
  client_id: string;
  name: string;
  client_type: string;
  state: string;
  [k: string]: unknown;
}

export interface SessionSummary {
  id: string;
  created_at: string;
  last_activity_at: string;
  amr: string[] | null;
  device_label?: string;
  network?: string;
  [k: string]: unknown;
}

export interface InvitationSummary {
  id: string;
  organization_id: string;
  purpose: string;
  target_email?: string;
  state: string;
  delivery_state: string;
  expires_at: string;
  [k: string]: unknown;
}

export interface SupportGrant {
  id: string;
  actor_user_id: string;
  target_user_id: string;
  organization_id: string;
  mode: string;
  state: string;
  expires_at: string;
  [k: string]: unknown;
}

export interface EffectivePermissions {
  permissions: string[];
  provenance: Record<string, string[]>;
  sources: Array<{ role_name: string; via: string; conditional: boolean; applies: boolean; permissions: string[]; redacted?: boolean }>;
  restricting_policies: number;
  [k: string]: unknown;
}

export type UserStateAction = 'suspend' | 'reactivate' | 'lock';

/** A random idempotency key. */
export function newIdempotencyKey(): string {
  return randomBytes(16).toString('hex');
}

const seg = (v: string): string => {
  if (typeof v !== 'string' || v === '') throw new TypeError('admin: path identifiers must be non-empty strings');
  return encodeURIComponent(v);
};

/** Calls one realm's custom APIs under /api/v1/realms/{realm}. */
export class AdminClient {
  readonly #base: string;
  readonly #token: TokenSource | undefined;
  readonly #timeoutMs: number;
  readonly #userAgent: string | undefined;
  readonly #fetch: FetchLike;
  readonly #maxBytes: number;
  readonly #onDeprecated: AdminClientConfig['onDeprecated'];

  constructor(config: AdminClientConfig) {
    if (!config || typeof config.realm !== 'string' || config.realm === '') throw new TypeError('admin: realm is required');
    const base = requireHttpUrl(config.baseUrl, 'baseUrl', 'admin');
    this.#base = base.href.replace(/\/+$/, '') + '/api/v1/realms/' + encodeURIComponent(config.realm);
    this.#token = config.token;
    this.#timeoutMs = config.timeoutMs ?? 30_000;
    this.#userAgent = config.userAgent;
    this.#fetch = config.fetch ?? globalThis.fetch;
    this.#maxBytes = config.maxResponseBytes ?? 32 << 20;
    this.#onDeprecated = config.onDeprecated;
  }

  /**
   * Performs a request against /api/v1/realms/{realm}{path} and decodes JSON.
   * Rejects with ProblemError for HTTP errors and AdminRequestError for transport
   * failures, timeouts and cancellation.
   */
  async request<T = unknown>(method: string, path: string, body?: unknown, options: RequestOptions = {}): Promise<AdminResponse<T>> {
    if (typeof path !== 'string' || !path.startsWith('/')) throw new TypeError('admin: path must start with "/"');
    const signal = withTimeout(options.timeoutMs ?? this.#timeoutMs, options.signal);
    const fail = (cause: unknown): AdminRequestError => {
      const reason: AdminErrorCode = options.signal?.aborted
        ? 'aborted'
        : signal.aborted || (cause instanceof Error && cause.name === 'TimeoutError')
          ? 'timeout'
          : 'network';
      return new AdminRequestError(reason, method, stripQuery(path), { cause });
    };
    const headers: Record<string, string> = { accept: 'application/json, application/problem+json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    headers['proudauth-sdk'] = `node/${SDK_VERSION}`;
    headers['user-agent'] = (this.#userAgent ? this.#userAgent + ' ' : '') + `proudauth-sdk-node/${SDK_VERSION}`;
    if (this.#token !== undefined) {
      let tok: string;
      try {
        tok = typeof this.#token === 'string' ? this.#token : await this.#token(signal);
      } catch (cause) {
        throw new AdminRequestError('token_source', method, stripQuery(path), { cause });
      }
      headers.authorization = `Bearer ${tok}`;
    }
    if (options.idempotencyKey) headers['idempotency-key'] = options.idempotencyKey;
    if (options.ifMatch) headers['if-match'] = options.ifMatch;
    let res: Response;
    let raw: Buffer;
    try {
      res = await this.#fetch(this.#base + path, {
        method,
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        redirect: 'error',
        signal,
      });
      raw = await readBodyLimited(res, this.#maxBytes);
    } catch (cause) {
      throw fail(cause);
    }
    let parsed: unknown;
    if (raw.length > 0) {
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch (cause) {
        if (res.status < 400) throw new AdminRequestError('invalid_response', method, stripQuery(path), { cause });
        parsed = undefined;
      }
    }
    const deprecation = res.headers.get('deprecation') ?? undefined;
    const sunset = res.headers.get('sunset') ?? undefined;
    if (deprecation && this.#onDeprecated) this.#onDeprecated({ method, path: stripQuery(path), deprecation, sunset });
    if (res.status >= 400) throw new ProblemError(res.status, isPlainObject(parsed) ? parsed : {}, res.headers);
    return {
      status: res.status,
      headers: res.headers,
      etag: res.headers.get('etag') ?? undefined,
      deprecation,
      sunset,
      data: wrapSecrets(parsed) as T,
    };
  }

  /** Iterates the pages of a cursor-paginated list endpoint (API-004). */
  async *pages<T>(path: string, options: RequestOptions = {}): AsyncGenerator<Page<T>, void, undefined> {
    let cursor = '';
    const seen = new Set<string>();
    for (;;) {
      let p = path;
      if (cursor) p += (p.includes('?') ? '&' : '?') + 'cursor=' + encodeURIComponent(cursor);
      const res = await this.request<{ items?: T[]; next_cursor?: string }>('GET', p, undefined, options);
      const items = Array.isArray(res.data?.items) ? res.data.items : [];
      const next = typeof res.data?.next_cursor === 'string' ? res.data.next_cursor : '';
      yield { items, nextCursor: next };
      if (!next) return;
      if (seen.has(next)) throw new AdminRequestError('invalid_response', 'GET', stripQuery(path)); // cursor loop
      seen.add(next);
      cursor = next;
    }
  }

  /** Iterates every item of a cursor-paginated list endpoint. */
  async *list<T>(path: string, options: RequestOptions = {}): AsyncGenerator<T, void, undefined> {
    for await (const page of this.pages<T>(path, options)) yield* page.items;
  }

  /** Lists users. */
  users(query = '', options?: RequestOptions): AsyncGenerator<User, void, undefined> {
    return this.list<User>('/users?q=' + encodeURIComponent(query), options);
  }

  /** Reads a user with its ETag. */
  getUser(userId: string, options?: RequestOptions): Promise<AdminResponse<User>> {
    return this.request<User>('GET', `/users/${seg(userId)}`, undefined, options);
  }

  /** Creates a user. A random idempotency key is used unless one is given (reuse it when retrying). */
  async createUser(input: Record<string, unknown>, options: RequestOptions = {}): Promise<Record<string, unknown>> {
    const res = await this.request<Record<string, unknown>>('POST', '/users', input, {
      ...options,
      idempotencyKey: options.idempotencyKey ?? newIdempotencyKey(),
    });
    return res.data;
  }

  /** Updates a user; pass the ETag from getUser as `ifMatch` to reject stale writes. */
  async updateUser(userId: string, patch: Record<string, unknown>, options: RequestOptions = {}): Promise<AdminResponse<User>> {
    return this.request<User>('PATCH', `/users/${seg(userId)}`, patch, options);
  }

  /** Suspends, reactivates or locks a user. */
  async setUserState(userId: string, action: UserStateAction, reason: string, options?: RequestOptions): Promise<void> {
    if (action !== 'suspend' && action !== 'reactivate' && action !== 'lock') throw new TypeError('admin: unknown user state action');
    await this.request('POST', `/users/${seg(userId)}/${action}`, { reason }, options);
  }

  /** Revokes all sessions of a user; returns the number revoked. */
  async revokeSessions(userId: string, options?: RequestOptions): Promise<number> {
    const res = await this.request<{ revoked_sessions?: number }>('POST', `/users/${seg(userId)}/revoke-sessions`, {}, options);
    return typeof res.data?.revoked_sessions === 'number' ? res.data.revoked_sessions : 0;
  }

  /** Lists organizations. */
  organizations(options?: RequestOptions): AsyncGenerator<Organization, void, undefined> {
    return this.list<Organization>('/organizations', options);
  }

  /** Creates an organization. */
  async createOrganization(slug: string, displayName: string, options: RequestOptions = {}): Promise<Organization> {
    const res = await this.request<Organization>('POST', '/organizations', { slug, display_name: displayName }, {
      ...options,
      idempotencyKey: options.idempotencyKey ?? newIdempotencyKey(),
    });
    return res.data;
  }

  /** Lists organization members. */
  members(orgId: string, options?: RequestOptions): AsyncGenerator<Membership, void, undefined> {
    return this.list<Membership>(`/organizations/${seg(orgId)}/members`, options);
  }

  /** Adds an existing user to an organization. */
  async addMember(orgId: string, userId: string, roleIds: string[], options?: RequestOptions): Promise<Membership> {
    const res = await this.request<Membership>('POST', `/organizations/${seg(orgId)}/members`, { user_id: userId, role_ids: roleIds }, options);
    return res.data;
  }

  /** Creates an invitation. */
  async invite(orgId: string, email: string, roleIds: string[], options: RequestOptions = {}): Promise<Record<string, unknown>> {
    const res = await this.request<Record<string, unknown>>(
      'POST',
      `/organizations/${seg(orgId)}/invitations`,
      { email, role_ids: roleIds },
      { ...options, idempotencyKey: options.idempotencyKey ?? newIdempotencyKey() },
    );
    return res.data;
  }

  /** Lists roles for a boundary type. */
  async roles(boundary: string, options?: RequestOptions): Promise<Role[]> {
    const res = await this.request<{ items?: Role[] }>('GET', '/roles?boundary_type=' + encodeURIComponent(boundary), undefined, options);
    return Array.isArray(res.data?.items) ? res.data.items : [];
  }

  /** Assigns a role to a subject within a scope. */
  async assign(
    roleId: string,
    subject: { type: string; id: string },
    scope: { type: string; id: string },
    options?: RequestOptions,
  ): Promise<Record<string, unknown>> {
    const res = await this.request<Record<string, unknown>>('POST', '/role-assignments', { role_id: roleId, subject, scope }, options);
    return res.data;
  }

  /** Registers an OAuth client; the secret is returned once. */
  async createClient(input: Record<string, unknown>, options?: RequestOptions): Promise<Record<string, unknown>> {
    return (await this.request<Record<string, unknown>>('POST', '/clients', input, options)).data;
  }

  /** Issues an overlapping client secret. */
  async rotateClientSecret(clientRef: string, retireOthersAfterSec: number, options?: RequestOptions): Promise<Record<string, unknown>> {
    const res = await this.request<Record<string, unknown>>(
      'POST',
      `/clients/${seg(clientRef)}/credentials`,
      { retire_others_after_seconds: Math.trunc(retireOthersAfterSec) },
      options,
    );
    return res.data;
  }

  /** Requests support access (requires recent MFA and a reason). */
  async requestImpersonation(input: Record<string, unknown>, options?: RequestOptions): Promise<Record<string, unknown>> {
    return (await this.request<Record<string, unknown>>('POST', '/impersonation-requests', input, options)).data;
  }

  /** Issues an approved support grant. */
  async issueImpersonation(requestId: string, options?: RequestOptions): Promise<Record<string, unknown>> {
    return (await this.request<Record<string, unknown>>('POST', `/impersonation-requests/${seg(requestId)}/issue`, undefined, options)).data;
  }

  /** Ends a support grant. */
  async revokeImpersonation(grantId: string, reason: string, options?: RequestOptions): Promise<void> {
    await this.request('POST', `/impersonation-grants/${seg(grantId)}/revoke`, { reason }, options);
  }

  /** Lists OAuth clients. */
  clients(options?: RequestOptions): AsyncGenerator<OAuthClientSummary, void, undefined> {
    return this.list<OAuthClientSummary>('/clients', options);
  }

  /** Sets the scopes and subject types a client may request for a resource. */
  async setResourceGrant(clientRef: string, resourceId: string, scopes: string[], subjectTypes: string[], options?: RequestOptions): Promise<void> {
    await this.request('PUT', `/clients/${seg(clientRef)}/resource-grants/${seg(resourceId)}`, { allowed_scopes: scopes, subject_types: subjectTypes }, options);
  }

  /** Lists a user's active sessions. */
  async userSessions(userId: string, options?: RequestOptions): Promise<SessionSummary[]> {
    const res = await this.request<{ items?: SessionSummary[] }>('GET', `/users/${seg(userId)}/sessions`, undefined, options);
    return Array.isArray(res.data?.items) ? res.data.items : [];
  }

  /** Revokes one session of a user (SES-003). */
  async revokeSession(userId: string, sessionId: string, options?: RequestOptions): Promise<void> {
    await this.request('DELETE', `/users/${seg(userId)}/sessions/${seg(sessionId)}`, undefined, options);
  }

  /** Lists an organization's invitations, optionally by state. */
  invitations(orgId: string, state = '', options?: RequestOptions): AsyncGenerator<InvitationSummary, void, undefined> {
    return this.list<InvitationSummary>(`/organizations/${seg(orgId)}/invitations?state=${encodeURIComponent(state)}`, options);
  }

  /** Revokes a pending invitation. */
  async revokeInvitation(orgId: string, invitationId: string, options?: RequestOptions): Promise<void> {
    await this.request('POST', `/organizations/${seg(orgId)}/invitations/${seg(invitationId)}/revoke`, undefined, options);
  }

  /** Creates up to 100 invitations with per-item results (INV-011). */
  async inviteBatch(orgId: string, items: Record<string, unknown>[], options: RequestOptions = {}): Promise<Record<string, unknown>[]> {
    // An explicit `idempotencyKey: undefined` must not clobber the generated key.
    const res = await this.request<{ results?: Record<string, unknown>[] }>('POST', `/organizations/${seg(orgId)}/invitations/batch`, { items }, {
      ...options,
      idempotencyKey: options.idempotencyKey ?? newIdempotencyKey(),
    });
    return Array.isArray(res.data?.results) ? res.data.results : [];
  }

  /** Lists support grants (filters: actor_user_id, target_user_id, organization_id, state). */
  async impersonationGrants(filter: Record<string, string> = {}, options?: RequestOptions): Promise<SupportGrant[]> {
    const res = await this.request<{ items?: SupportGrant[] }>('GET', '/impersonation-grants?' + new URLSearchParams(filter).toString(), undefined, options);
    return Array.isArray(res.data?.items) ? res.data.items : [];
  }

  /** Explains a subject's effective permissions with provenance (AZ-009). */
  async subjectPermissions(subjectId: string, orgId = '', options?: RequestOptions): Promise<EffectivePermissions> {
    const q = orgId ? '?organization_id=' + encodeURIComponent(orgId) : '';
    return (await this.request<EffectivePermissions>('GET', `/subjects/${seg(subjectId)}/permissions${q}`, undefined, options)).data;
  }

  /** Queries audit evidence. */
  auditEvents(filter: Record<string, string> = {}, options?: RequestOptions): AsyncGenerator<Record<string, unknown>, void, undefined> {
    return this.list<Record<string, unknown>>('/audit-events?' + new URLSearchParams(filter).toString(), options);
  }
}

function stripQuery(path: string): string {
  const q = path.indexOf('?');
  return q >= 0 ? path.slice(0, q) : path;
}
