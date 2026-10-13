import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BoundedState, BoundedVerifier, CursorExpiredError } from '../src/bounded-state.js';
import { Claims } from '../src/claims.js';
import { isVerifierError } from '../src/errors.js';
import type { Authenticator } from '../src/middleware.js';
import { challenge } from '../src/middleware.js';
import { json, startServer, type TestServer } from './helpers.js';

const claims = (subject: string, sessionId: string, issuedAt: number, orgId = 'org_1'): Claims =>
  new Claims({
    issuer: 'https://id.test/realms/main', subject, audience: 'https://api.test', clientId: 'web', scopes: [], orgId, sessionId,
    tokenKind: 'user_access', jti: 'j', issuedAt: new Date(issuedAt), acr: '', authzVersion: 0, online: false,
  });

describe('bounded-state verification (SDK-002)', () => {
  let idp: TestServer;
  let pending: unknown[] = [];
  let auth = '';
  let now = Date.parse('2026-10-10T10:00:00Z');

  before(async () => {
    idp = await startServer((req, res) => {
      auth = String(req.headers.authorization);
      const u = new URL(req.url ?? '', 'http://x');
      if (u.pathname !== '/api/v1/realms/main/session-events') return json(res, 404, {});
      if (u.searchParams.get('from') === 'now') return json(res, 200, { events: [], next_cursor: '10.0' });
      const events = pending;
      pending = [];
      return json(res, 200, { events, next_cursor: '11.0' });
    });
  });
  after(() => idp.close());

  it('rejects revoked sessions and subjects and fails closed when stale', async () => {
    const state = new BoundedState({ baseUrl: idp.url, realm: 'main', token: async () => 'svc-token', maxStalenessMs: 60_000, now: () => now });
    await state.start();
    assert.equal(auth, 'Bearer svc-token');
    const t0 = now - 1000;
    state.check(claims('usr_bob', 'ses_1', t0));
    pending = [
      { event_type: 'session.revoked', occurred_at: new Date(now).toISOString(), data: { user_id: 'usr_bob', session_id: 'ses_1' } },
      { event_type: 'user.suspended', occurred_at: new Date(now).toISOString(), data: { user_id: 'usr_carol' } },
    ];
    await state.sync();
    assert.throws(() => state.check(claims('usr_bob', 'ses_1', t0)), (e) => isVerifierError(e, 'revoked'));
    assert.throws(() => state.check(claims('usr_carol', 'ses_9', t0)), (e) => isVerifierError(e, 'revoked'));
    // A token issued after the subject revocation is unaffected.
    state.check(claims('usr_carol', 'ses_9', now + 1000));
    state.check(claims('usr_alice', 'ses_2', t0));
    now += 120_000;
    assert.throws(() => state.check(claims('usr_alice', 'ses_2', t0)), (e) => isVerifierError(e, 'stale_state'));
    assert.equal(challenge(new (await import('../src/errors.js')).VerifierError('stale_state')).status, 503);
  });

  it('wraps an authenticator', async () => {
    const state = new BoundedState({ baseUrl: idp.url, realm: 'main', token: async () => 't', maxStalenessMs: 60_000, now: () => now });
    await state.start();
    const inner: Authenticator = { authenticate: async () => claims('usr_x', 'ses_x', now - 10) };
    const v = new BoundedVerifier(inner, state);
    assert.equal((await v.authenticate('raw')).subject, 'usr_x');
    pending = [{ event_type: 'session.revoked', occurred_at: new Date(now).toISOString(), data: { session_id: 'ses_x' } }];
    await state.sync();
    await assert.rejects(v.authenticate('raw'), (e) => isVerifierError(e, 'revoked'));
  });

  it('reads subject_id for role unassignment and refresh reuse, for user subjects only', async () => {
    const state = new BoundedState({ baseUrl: idp.url, realm: 'main', token: async () => 't', maxStalenessMs: 60_000, now: () => now });
    await state.start();
    const at = new Date(now).toISOString();
    const t0 = now - 1000;
    pending = [
      { event_type: 'authorization.role.unassigned', occurred_at: at, organization_id: 'org_1', data: { subject_id: 'usr_dan', role_id: 'rol_1' } },
      { event_type: 'authorization.role.unassigned', occurred_at: at, organization_id: 'org_1', data: { subject_id: 'svc_batch', role_id: 'rol_1' } },
      { event_type: 'security.refresh_reuse_detected', occurred_at: at, data: { subject_id: 'usr_erin', family_id: 'rff_1' } },
      { event_type: 'security.refresh_reuse_detected', occurred_at: at, data: { subject_id: 'svc_batch', family_id: 'rff_2' } },
    ];
    await state.sync();
    assert.throws(() => state.check(claims('usr_dan', 'ses_d', t0, 'org_1')), (e) => isVerifierError(e, 'revoked'));
    state.check(claims('usr_dan', 'ses_d', t0, 'org_2'));
    assert.throws(() => state.check(claims('usr_erin', 'ses_e', t0, '')), (e) => isVerifierError(e, 'revoked'));
    // A service principal subject is not mistaken for a user.
    state.check(claims('svc_batch', 'ses_s', t0));
  });
});

/** A fake stream: handle(cursor) answers [status, body]; cursor is 'now' for from=now. */
function fakeStream(handle: (cursor: string) => [number, unknown]): { fetch: typeof fetch; cursors: string[] } {
  const cursors: string[] = [];
  const f = (async (input: string | URL | Request) => {
    const u = new URL(String(input));
    const cursor = u.searchParams.get('from') === 'now' ? 'now' : (u.searchParams.get('cursor') ?? '');
    cursors.push(cursor);
    // Yield to the event loop like a real request (run() would otherwise spin
    // on microtasks and starve the test's timers).
    await new Promise((r) => setImmediate(r));
    const [status, body] = handle(cursor);
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { fetch: f, cursors };
}

const revoked = (sessionId: string, at: number): unknown => ({
  event_type: 'session.revoked', occurred_at: new Date(at).toISOString(), data: { session_id: sessionId },
});

describe('bounded-state restarts and expired cursors', () => {
  const t0 = Date.parse('2026-10-10T10:00:00Z');

  it('keeps known revocations when start() is called again', async () => {
    const { fetch } = fakeStream((cursor) => {
      if (cursor === 'now') return [200, { events: [], next_cursor: '1.0' }];
      if (cursor === '1.0') {
        return [200, { next_cursor: '2.0', events: [revoked('ses_1', t0), { event_type: 'user.suspended', occurred_at: new Date(t0).toISOString(), data: { user_id: 'usr_2' } }] }];
      }
      return [200, { events: [], next_cursor: cursor }];
    });
    const state = new BoundedState({ baseUrl: 'https://id.test', realm: 'main', token: async () => 't', maxStalenessMs: 60_000, fetch, now: () => t0 });
    await state.start();
    await state.sync();
    await state.start();
    assert.throws(() => state.check(claims('usr_9', 'ses_1', t0 - 1000)), (e) => isVerifierError(e, 'revoked'));
    assert.throws(() => state.check(claims('usr_2', 'ses_9', t0 - 1000)), (e) => isVerifierError(e, 'revoked'));
  });

  it('rewinds to the retained history on 410 and is fresh only once caught up', async () => {
    let now = t0;
    let midReplayFails = true;
    const full = Array.from({ length: 500 }, (_, i) => revoked(`ses_old_${i}`, t0 - 3_600_000));
    const { fetch, cursors } = fakeStream((cursor) => {
      switch (cursor) {
        case 'now':
          return [200, { events: [], next_cursor: '5.0' }];
        case '5.0':
          return [200, { events: [revoked('ses_known', t0)], next_cursor: '6.0' }];
        case '6.0':
          return [410, { code: 'cursor_expired' }];
        case '':
          return [200, { events: full, next_cursor: 'p1' }];
        case 'p1':
          return midReplayFails ? [503, {}] : [200, { events: [revoked('ses_gap', t0)], next_cursor: '9.0' }];
        default:
          return [200, { events: [], next_cursor: cursor }];
      }
    });
    const state = new BoundedState({ baseUrl: 'https://id.test', realm: 'main', token: async () => 't', maxStalenessMs: 60_000, fetch, now: () => now });
    await state.start();
    await state.sync();
    await assert.rejects(state.sync(), (e) => e instanceof CursorExpiredError && isVerifierError(e, 'unavailable'));
    assert.throws(() => state.check(claims('usr_1', 'ses_known', t0)), (e) => isVerifierError(e, 'revoked'));
    // The replay applies a full page, then fails: not fresh, it has not caught up.
    now += 30_000;
    await assert.rejects(state.sync(), (e) => isVerifierError(e, 'unavailable'));
    now += 40_000;
    assert.throws(() => state.check(claims('usr_1', 'ses_other', t0)), (e) => isVerifierError(e, 'stale_state'));
    midReplayFails = false;
    await state.sync();
    for (const sid of ['ses_known', 'ses_gap', 'ses_old_0']) {
      assert.throws(() => state.check(claims('usr_1', sid, t0)), (e) => isVerifierError(e, 'revoked'), sid);
    }
    state.check(claims('usr_1', 'ses_other', t0));
    assert.deepEqual(cursors.slice(0, 4), ['now', '5.0', '6.0', '']);
  });

  it('run() reports the 410, replays the retained history and keeps following', async () => {
    let expired = 0;
    const { fetch } = fakeStream((cursor) => {
      switch (cursor) {
        case 'now':
          return [200, { events: [], next_cursor: '1.0' }];
        case '1.0':
          expired++;
          return [410, { code: 'cursor_expired' }];
        case '':
          return [200, { events: [revoked('ses_gap', t0)], next_cursor: '2.0' }];
        case '2.0':
          return [200, { events: [revoked('ses_next', t0)], next_cursor: '3.0' }];
        default:
          return [200, { events: [], next_cursor: cursor }];
      }
    });
    const state = new BoundedState({ baseUrl: 'https://id.test', realm: 'main', token: async () => 't', maxStalenessMs: 60_000, fetch, now: () => t0 });
    await state.start();
    const ac = new AbortController();
    const errors: unknown[] = [];
    const running = state.run(ac.signal, (e) => errors.push(e));
    const deadline = Date.now() + 5000;
    for (;;) {
      try {
        state.check(claims('usr_1', 'ses_next', t0));
      } catch (e) {
        if (isVerifierError(e, 'revoked')) break;
        throw e;
      }
      if (Date.now() > deadline) assert.fail('run() did not recover from the expired cursor');
      await new Promise((r) => setTimeout(r, 5));
    }
    ac.abort();
    await running;
    assert.throws(() => state.check(claims('usr_1', 'ses_gap', t0)), (e) => isVerifierError(e, 'revoked'));
    assert.equal(expired, 1);
    assert.equal(errors.length, 1);
    assert.ok(errors[0] instanceof CursorExpiredError);
  });

  it('never weakens a revocation when an older event is replayed', async () => {
    const t2 = t0;
    const t1 = t0 - 3_600_000;
    const suspended = (at: number): unknown => ({ event_type: 'user.suspended', occurred_at: new Date(at).toISOString(), data: { user_id: 'usr_1' } });
    const { fetch } = fakeStream((cursor) => {
      if (cursor === 'now') return [200, { events: [], next_cursor: '1.0' }];
      if (cursor === '1.0') return [200, { events: [suspended(t2), suspended(t1)], next_cursor: '2.0' }];
      return [200, { events: [], next_cursor: cursor }];
    });
    const state = new BoundedState({ baseUrl: 'https://id.test', realm: 'main', token: async () => 't', maxStalenessMs: 60_000, fetch, now: () => t0 });
    await state.start();
    await state.sync();
    assert.throws(() => state.check(claims('usr_1', 'ses_1', t2 - 60_000)), (e) => isVerifierError(e, 'revoked'));
    state.check(claims('usr_1', 'ses_1', t2 + 1000));
  });
});

describe('bounded-state run stops promptly', () => {
  it('aborts an in-flight long poll and a backoff at once', async () => {
    let calls = 0;
    const hanging: typeof fetch = (async (_url: unknown, init?: RequestInit) => {
      calls++;
      if (calls === 1) throw new Error('first poll fails'); // forces a backoff
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    }) as typeof fetch;
    const state = new BoundedState({ baseUrl: 'http://idp.test', realm: 'main', maxStalenessMs: 60_000, token: async () => 't', fetch: hanging });
    const ctl = new AbortController();
    const started = Date.now();
    const running = state.run(ctl.signal, () => {});
    await new Promise((r) => setTimeout(r, 50));
    ctl.abort();
    await running;
    assert.ok(Date.now() - started < 1000, `run took ${Date.now() - started} ms to stop`);
  });
});
