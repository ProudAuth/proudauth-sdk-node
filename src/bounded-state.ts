/**
 * Bounded-state verification (SDK-002): the consistency mode between offline
 * JWT verification and per-request introspection. Tokens are verified
 * locally, then checked against revocation state replayed from the identity
 * provider's session-event stream (SES-019). The state is trusted only while
 * it is fresher than `maxStalenessMs`; beyond that every check fails with
 * `stale_state` (HTTP 503). It never silently downgrades to offline acceptance.
 */
import type { Claims } from './claims.js';
import { VerifierError } from './errors.js';
import type { Authenticator } from './middleware.js';

export interface BoundedStateOptions {
  /** Identity provider origin, e.g. https://id.example.com */
  baseUrl: string;
  realm: string;
  /** Service access token (admin audience) carrying realm.session_events.read. */
  token: () => Promise<string>;
  maxStalenessMs: number;
  fetch?: typeof fetch;
  now?: () => number;
}

interface StreamPage {
  events?: Array<{ event_type: string; occurred_at: string; organization_id?: string; data?: Record<string, unknown> }>;
  next_cursor: string;
}

const SUBJECT_EVENTS = new Set([
  // user.recovery_restricted is not a revocation: the server keeps sessions valid.
  'user.suspended', 'user.locked', 'user.deleted', 'user.password_reset',
  'security.refresh_reuse_detected', 'security.credential_compromised',
]);
const ORG_EVENTS = new Set(['organization.suspended', 'organization.deleted', 'organization.archived']);
const MEMBER_EVENTS = new Set(['organization.membership.removed', 'organization.membership.suspended', 'authorization.role.unassigned']);
/**
 * Events naming the assignment's or grant's subject as `subject_id` rather
 * than `user_id`. The subject may also be a service principal (`svc_`) or a
 * group (`grp_`); the ID prefix tells them apart, and only users are tracked.
 */
const SUBJECT_ID_EVENTS = new Set(['authorization.role.unassigned', 'security.refresh_reuse_detected']);

/** Page size requested from the stream (its maximum). */
const PAGE_LIMIT = 500;
/** Pages one `sync()` call reads at most. */
const MAX_PAGES_PER_SYNC = 100;

/**
 * Thrown by `sync()` when the stream answers 410: the cursor is older than the
 * retained history. `sync()` has already rewound to the beginning of the
 * retained history (keeping every revocation it knows), so the next `sync()`
 * replays it; `run()` does so immediately. Its `code` is `unavailable`.
 */
export class CursorExpiredError extends VerifierError {
  constructor() {
    super('unavailable', { cause: new Error('session-event cursor is older than the retained history (HTTP 410)') });
  }
}

/** Keeps the latest revocation time for `key`, so a replay never weakens the state. */
function revokeAt(m: Map<string, number>, key: string, at: number): void {
  const prev = m.get(key);
  if (prev === undefined || Number.isNaN(prev) || at > prev) m.set(key, at);
}

export class BoundedState {
  readonly #o: Required<Omit<BoundedStateOptions, 'fetch' | 'now'>> & { fetch: typeof fetch; now: () => number };
  #cursor = '';
  #synced = 0;
  readonly #sessions = new Map<string, number>();
  readonly #subjects = new Map<string, number>();
  readonly #orgs = new Map<string, number>();
  readonly #members = new Map<string, number>();

  constructor(options: BoundedStateOptions) {
    if (!(options.maxStalenessMs > 0)) throw new TypeError('maxStalenessMs must be positive');
    this.#o = { ...options, fetch: options.fetch ?? fetch, now: options.now ?? Date.now };
  }

  async #get(query: Record<string, string>, signal?: AbortSignal): Promise<StreamPage> {
    const url = `${this.#o.baseUrl.replace(/\/+$/, '')}/api/v1/realms/${encodeURIComponent(this.#o.realm)}/session-events?${new URLSearchParams(query)}`;
    const res = await this.#o.fetch(url, { headers: { authorization: `Bearer ${await this.#o.token()}` }, signal });
    if (res.status === 410) throw new CursorExpiredError();
    if (res.status !== 200) throw new VerifierError('unavailable');
    return (await res.json()) as StreamPage;
  }

  /**
   * Positions the stream at "now"; call before accepting traffic. Calling it
   * again keeps every revocation already replayed: the stream has no snapshot
   * that could supersede them, so a restart only moves the position forward.
   */
  async start(): Promise<void> {
    const page = await this.#get({ from: 'now' });
    this.#cursor = page.next_cursor;
    this.#synced = this.#o.now();
  }

  /**
   * Reads all pending events (`waitSeconds` long-polls, 0..25). The state
   * counts as fresh only once a read reaches the end of the stream, so a
   * partly replayed backlog never passes for current state. A 410 rewinds to
   * the beginning of the retained history (keeping the known revocations) and
   * throws `CursorExpiredError`; the next `sync()` replays that history, which
   * includes the events after the expired cursor.
   */
  async sync(waitSeconds = 0, signal?: AbortSignal): Promise<void> {
    for (let i = 0; i < MAX_PAGES_PER_SYNC; i++) {
      const cursor = this.#cursor;
      const query: Record<string, string> = { cursor, limit: String(PAGE_LIMIT) };
      if (i === 0 && waitSeconds > 0) query.wait = String(Math.min(25, Math.floor(waitSeconds)));
      let page: StreamPage;
      try {
        page = await this.#get(query, signal);
      } catch (err) {
        // No snapshot exists, so the full resynchronization is a replay of the
        // retained history ('' is its beginning). #synced is left alone: the
        // state turns stale if the replay does not catch up in time.
        if (err instanceof CursorExpiredError && this.#cursor === cursor) this.#cursor = '';
        throw err;
      }
      const events = page.events ?? [];
      for (const ev of events) {
        const at = Date.parse(ev.occurred_at);
        const str = (k: string): string => (typeof ev.data?.[k] === 'string' ? (ev.data[k] as string) : '');
        let user = str('user_id');
        if (SUBJECT_ID_EVENTS.has(ev.event_type)) user = str('subject_id').startsWith('usr_') ? str('subject_id') : '';
        if (ev.event_type === 'session.revoked' && str('session_id')) revokeAt(this.#sessions, str('session_id'), at);
        else if (SUBJECT_EVENTS.has(ev.event_type) && user) revokeAt(this.#subjects, user, at);
        else if (ORG_EVENTS.has(ev.event_type)) {
          const org = str('organization_id') || ev.organization_id || '';
          if (org) revokeAt(this.#orgs, org, at);
        } else if (MEMBER_EVENTS.has(ev.event_type) && user && ev.organization_id) {
          revokeAt(this.#members, `${user}|${ev.organization_id}`, at);
        }
      }
      this.#cursor = page.next_cursor;
      if (events.length < PAGE_LIMIT) {
        this.#synced = this.#o.now();
        return;
      }
    }
  }

  /** Throws `stale_state` when the state is too old, `revoked` when the claims were revoked. */
  check(c: Claims): void {
    if (this.#synced === 0 || this.#o.now() - this.#synced > this.#o.maxStalenessMs) throw new VerifierError('stale_state');
    const issued = c.issuedAt?.getTime() ?? 0;
    const before = (m: Map<string, number>, k: string): boolean => {
      const at = m.get(k);
      return at !== undefined && issued <= at;
    };
    if (c.sessionId && this.#sessions.has(c.sessionId)) throw new VerifierError('revoked');
    if (before(this.#subjects, c.subject)) throw new VerifierError('revoked');
    if (c.orgId && (before(this.#orgs, c.orgId) || before(this.#members, `${c.subject}|${c.orgId}`))) throw new VerifierError('revoked');
  }

  /**
   * Keeps the state current until `signal` aborts; errors go to `onError`.
   * After a `CursorExpiredError` (reported too) it replays the retained
   * history at once instead of waiting, then keeps following the stream.
   */
  async run(signal: AbortSignal, onError?: (err: unknown) => void): Promise<void> {
    let backoff = 1000;
    let resyncing = false;
    while (!signal.aborted) {
      try {
        await this.sync(20, signal);
        backoff = 1000;
        resyncing = false;
      } catch (err) {
        if (signal.aborted) return; // stopping, not failing
        onError?.(err);
        if (err instanceof CursorExpiredError && !resyncing) {
          // sync() rewound to the retained history: replay it now. A second
          // 410 in a row waits like any other error.
          resyncing = true;
          continue;
        }
        // The backoff ends early when the caller stops.
        await new Promise<void>((resolve) => {
          const timer = setTimeout(done, backoff);
          function done(): void {
            clearTimeout(timer);
            signal.removeEventListener('abort', done);
            resolve();
          }
          signal.addEventListener('abort', done, { once: true });
        });
        backoff = Math.min(backoff * 2, 30_000);
      }
    }
  }
}

/** Offline verification followed by a bounded-state check. */
export class BoundedVerifier implements Authenticator {
  constructor(
    readonly verifier: Authenticator,
    readonly state: BoundedState,
  ) {}

  async authenticate(raw: string, options?: { signal?: AbortSignal }): Promise<Claims> {
    const claims = await this.verifier.authenticate(raw, options);
    this.state.check(claims);
    return claims;
  }
}
