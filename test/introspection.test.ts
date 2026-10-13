import { after, before, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  Introspector,
  SupportGuard,
  isProtectedOperation,
  isVerifierError,
  type SupportEvent,
  type VerifierErrorCode,
} from '../src/introspection.js';
import { deadUrl, json, sleep, startServer, type TestServer } from './helpers.js';

const ISS = 'https://id.test/realms/main';
const AUD = 'https://api.test/orders';
const CLIENT_ID = 'orders-api:rs';
const CLIENT_SECRET = 'pa_cs_s3cr3t+/= &x';

type Entry = Record<string, unknown> | ((count: number) => unknown);

describe('strict-online introspection', () => {
  let idp: TestServer;
  const tokens = new Map<string, Entry>();
  let lastAuth = '';
  let lastBody = '';
  let lastType = '';
  let mode: 'ok' | 'error' | 'slow' | 'garbage' | 'dup' | 'array' = 'ok';
  let introspections = 0;

  before(async () => {
    idp = await startServer(async (req, res, body) => {
      if (req.method !== 'POST' || req.url !== '/oauth/introspect') return json(res, 404, {});
      introspections++;
      lastAuth = String(req.headers.authorization);
      lastType = String(req.headers['content-type']);
      lastBody = body;
      if (mode === 'error') return json(res, 500, { error: 'server_error' });
      if (mode === 'slow') await sleep(300);
      if (mode === 'garbage') return json(res, 200, '<html>');
      if (mode === 'dup') return json(res, 200, '{"active":false,"active":true,"iss":"' + ISS + '"}');
      if (mode === 'array') return json(res, 200, '[{"active":true}]');
      const tok = new URLSearchParams(body).get('token') ?? '';
      const entry = tokens.get(tok);
      const v = typeof entry === 'function' ? entry(introspections) : entry;
      json(res, 200, v ?? { active: false });
    });
  });
  after(() => idp.close());
  beforeEach(() => {
    mode = 'ok';
    tokens.clear();
  });

  const intro = (over: Partial<ConstructorParameters<typeof Introspector>[0]> = {}): Introspector =>
    new Introspector({
      endpoint: idp.url + '/oauth/introspect',
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      issuer: ISS,
      audience: AUD,
      timeoutMs: 150,
      ...over,
    });

  const active = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
    active: true,
    iss: ISS,
    sub: 'usr_1',
    aud: AUD,
    client_id: 'web',
    scope: 'orders:read',
    exp: 1_800_000_300,
    iat: 1_800_000_000,
    jti: 'tok_1',
    sid: 'ses_1',
    org_id: 'org_a',
    token_kind: 'user_access',
    token_type: 'Bearer',
    authz_version: 7,
    ...extra,
  });

  const rejects = (p: Promise<unknown>, code: VerifierErrorCode): Promise<void> =>
    assert.rejects(p, (e: unknown) => {
      assert.ok(isVerifierError(e), String(e));
      assert.equal(e.code, code);
      return true;
    });

  it('refuses sender-bound opaque tokens through token-only introspection', async () => {
    for (const cnf of [{ jkt: 'eA'.repeat(21) + 'A' }, { 'x5t#S256': 'eA'.repeat(21) + 'A' }, null, {}, { unknown: 'binding' }]) {
      tokens.set('bound', active({ cnf }));
      await rejects(intro().authenticate('bound'), 'sender_constraint');
    }
  });

  it('authenticates with client_secret_basic and form-encoded credentials', async () => {
    tokens.set('pa_at_abc', active());
    const c = await intro().authenticate('pa_at_abc');
    assert.equal(c.subject, 'usr_1');
    assert.equal(c.online, true);
    assert.equal(c.authzVersion, 7);
    assert.equal(c.expiry?.getTime(), 1_800_000_300_000);
    assert.equal(lastType, 'application/x-www-form-urlencoded');
    assert.equal(lastBody, 'token=pa_at_abc');
    const decoded = Buffer.from(lastAuth.replace(/^Basic /, ''), 'base64').toString();
    assert.equal(decoded, 'orders-api%3Ars:pa_cs_s3cr3t%2B%2F%3D+%26x');
    const [id, secret] = decoded.split(':').map((s) => decodeURIComponent(s.replace(/\+/g, ' ')));
    assert.equal(id, CLIENT_ID);
    assert.equal(secret, CLIENT_SECRET);
  });

  it('accepts JWT access tokens too (form-encodes the token)', async () => {
    tokens.set('a.b+c.d', active());
    await intro().authenticate('a.b+c.d');
    assert.equal(lastBody, 'token=a.b%2Bc.d');
  });

  it('denies inactive tokens', async () => {
    tokens.set('t', { active: false });
    await rejects(intro().authenticate('t'), 'inactive');
    tokens.set('t2', { active: 'true', iss: ISS, aud: AUD, token_kind: 'user_access' });
    await rejects(intro().authenticate('t2'), 'inactive');
  });

  it('never caches: a revocation is visible on the next request', async () => {
    let revoked = false;
    tokens.set('t', () => (revoked ? { active: false } : active()));
    const i = intro();
    const before = introspections;
    await i.authenticate('t');
    await i.authenticate('t');
    revoked = true;
    await rejects(i.authenticate('t'), 'inactive');
    assert.equal(introspections - before, 3);
  });

  it('fails closed on HTTP errors, bad JSON, timeouts and network errors (TEST-035)', async () => {
    tokens.set('t', active());
    mode = 'error';
    await rejects(intro().authenticate('t'), 'unavailable');
    mode = 'garbage';
    await rejects(intro().authenticate('t'), 'unavailable');
    mode = 'dup';
    await rejects(intro().authenticate('t'), 'unavailable');
    mode = 'array';
    await rejects(intro().authenticate('t'), 'unavailable');
    mode = 'slow';
    await rejects(intro().authenticate('t'), 'unavailable');
    mode = 'ok';
    await rejects(intro({ endpoint: (await deadUrl()) + '/oauth/introspect' }).authenticate('t'), 'unavailable');
    const ctl = new AbortController();
    ctl.abort();
    await rejects(intro().authenticate('t', { signal: ctl.signal }), 'unavailable');
  });

  it('does not follow redirects with client credentials', async () => {
    const redirector = await startServer((_q, res) => {
      res.writeHead(307, { location: idp.url + '/oauth/introspect' });
      res.end();
    });
    try {
      tokens.set('t', active());
      await rejects(intro({ endpoint: redirector.url + '/introspect' }).authenticate('t'), 'unavailable');
    } finally {
      await redirector.close();
    }
  });

  it('checks issuer and audience of the introspection result', async () => {
    tokens.set('t1', active({ iss: 'https://other.test' }));
    await rejects(intro().authenticate('t1'), 'issuer');
    tokens.set('t2', active({ aud: 'https://api.test/billing' }));
    await rejects(intro().authenticate('t2'), 'audience');
    tokens.set('t3', active({ aud: [AUD, 'https://api.test/billing'] }));
    await rejects(intro().authenticate('t3'), 'audience');
    tokens.set('t4', active({ aud: [AUD] }));
    await intro().authenticate('t4');
  });

  it('rejects support tokens on ordinary paths (IMP-001, TEST-045)', async () => {
    tokens.set('pa_it_1', active({ token_kind: 'impersonation_access', act: { sub: 'usr_agent' }, impersonation_grant_id: 'imp_1' }));
    await rejects(intro().authenticate('pa_it_1'), 'token_kind');
    tokens.set('x', active({ token_kind: 'refresh' }));
    await rejects(intro().authenticate('x'), 'token_kind');
  });

  it('rejects missing and oversized tokens without a network call', async () => {
    const before = introspections;
    await rejects(intro().authenticate(''), 'missing_token');
    await rejects(intro().authenticate('x'.repeat(9000)), 'too_large');
    assert.equal(introspections, before);
  });

  it('validates configuration', () => {
    assert.throws(() => intro({ audience: '' }), /audience is required/);
    assert.throws(() => intro({ issuer: '' }), /issuer is required/);
    assert.throws(() => intro({ clientSecret: '' }), /clientSecret is required/);
    assert.throws(() => intro({ endpoint: 'ftp://x' }), /http/);
    assert.throws(() => intro({ acceptedKinds: ['user_access', 'impersonation_access'] }), /SupportGuard/);
  });

  // The shared support-contract tests a service runs before it opts into
  // impersonation (INT-010): contract validation at startup, actor
  // propagation, read-only and protected-operation denials, audit failure,
  // revocation and introspection outages.
  describe('SupportGuard', () => {
    const support = (extra: Record<string, unknown> = {}): Record<string, unknown> =>
      active({
        sub: 'usr_customer',
        client_id: 'support-bff',
        jti: 'tok_support_1',
        token_kind: 'impersonation_access',
        act: { iss: ISS, sub: 'usr_agent' },
        impersonation_grant_id: 'imp_1',
        support_mode: 'read_only',
        ...extra,
      });

    const setup = (auditor?: (ev: SupportEvent) => void | Promise<void>, writeOperations: string[] = ['orders.annotate']) => {
      const events: SupportEvent[] = [];
      const order: string[] = [];
      const guard = new SupportGuard({
        introspector: intro(),
        auditor:
          auditor ??
          (async (ev) => {
            order.push('audit');
            await sleep(5);
            events.push(ev);
          }),
        writeOperations,
      });
      return { guard, events, order };
    };

    it('requires an auditor (contract validation)', () => {
      assert.throws(
        () => new SupportGuard({ introspector: intro(), auditor: undefined as never }),
        (e: unknown) => isVerifierError(e, 'contract'),
      );
      assert.throws(
        () => new SupportGuard({ introspector: undefined as never, auditor: () => undefined }),
        (e: unknown) => isVerifierError(e, 'contract'),
      );
    });

    it('allows a read with actor attribution, auditing before access', async () => {
      tokens.set('pa_it_1', support());
      const { guard, events, order } = setup();
      const c = await guard.authorize('pa_it_1', 'orders.list', { read: true });
      order.push('access');
      assert.deepEqual(order, ['audit', 'access']);
      assert.equal(c.isSupport(), true);
      assert.equal(c.actor?.subject, 'usr_agent');
      assert.equal(c.subject, 'usr_customer');
      assert.equal(events.length, 1);
      const ev = events[0]!;
      assert.equal(ev.allowed, true);
      assert.equal(ev.actor, 'usr_agent');
      assert.equal(ev.subject, 'usr_customer');
      assert.equal(ev.grantId, 'imp_1');
      assert.equal(ev.orgId, 'org_a');
      assert.equal(ev.operation, 'orders.list');
      assert.equal(ev.tokenId, 'tok_support_1');
    });

    it('denies writes in read_only mode and audits the denial (IMP-011)', async () => {
      tokens.set('pa_it_1', support());
      const { guard, events } = setup();
      await rejects(guard.authorize('pa_it_1', 'orders.annotate', { read: false }), 'support_policy');
      assert.equal(events.length, 1);
      assert.equal(events[0]!.allowed, false);
      assert.equal(events[0]!.denyReason, 'write_not_allowlisted');
    });

    it('treats an operation without read: true as a write', async () => {
      tokens.set('pa_it_1', support());
      const { guard } = setup();
      await rejects(guard.authorize('pa_it_1', 'orders.list', {} as never), 'support_policy');
    });

    it('allows only allowlisted writes in allowlisted_write mode', async () => {
      tokens.set('pa_it_w', support({ support_mode: 'allowlisted_write' }));
      const { guard } = setup();
      await guard.authorize('pa_it_w', 'orders.annotate', { read: false });
      await guard.authorize('pa_it_w', 'Orders.Annotate', { read: false });
      await rejects(guard.authorize('pa_it_w', 'orders.cancel', { read: false }), 'support_policy');
    });

    it('always denies protected operations, even allowlisted (IMP-012, IMP-013, TEST-042)', async () => {
      tokens.set('pa_it_w', support({ support_mode: 'allowlisted_write' }));
      const ops = ['password.change', 'password.reset', 'mfa.change.totp', 'api_key.create', 'payment', 'refund', 'orders.delete', 'users.password.change', 'DELETE'];
      const { guard, events } = setup(undefined, ops);
      for (const op of ops) {
        await rejects(guard.authorize('pa_it_w', op, { read: false }), 'support_policy');
        await rejects(guard.authorize('pa_it_w', op, { read: true }), 'support_policy');
      }
      assert.ok(events.every((e) => !e.allowed && e.denyReason === 'protected_operation'));
      // A protected segment anywhere in the name counts (same rule as the Go SDK).
      assert.equal(isProtectedOperation('orders.refund.read'), true);
      assert.equal(isProtectedOperation('orders.list'), false);
      assert.equal(isProtectedOperation('refund.read'), true);
      assert.equal(isProtectedOperation('orders.export', ['orders.export']), true);
    });

    it('denies when the audit record cannot be written (IMP-020, TEST-047)', async () => {
      tokens.set('pa_it_1', support());
      const { guard } = setup(() => {
        throw new Error('db down');
      });
      await rejects(guard.authorize('pa_it_1', 'orders.list', { read: true }), 'unavailable');
      const { guard: g2 } = setup(() => Promise.reject(new Error('db down')));
      await rejects(g2.authorize('pa_it_1', 'orders.list', { read: true }), 'unavailable');
    });

    it('requires a preserved actor and grant (TEST-045)', async () => {
      const { guard, events } = setup();
      tokens.set('a', support({ act: undefined }));
      await rejects(guard.authorize('a', 'orders.list', { read: true }), 'token_kind');
      tokens.set('b', support({ act: { sub: '' } }));
      await rejects(guard.authorize('b', 'orders.list', { read: true }), 'token_kind');
      tokens.set('c', support({ impersonation_grant_id: undefined }));
      await rejects(guard.authorize('c', 'orders.list', { read: true }), 'token_kind');
      tokens.set('d', active({ act: { sub: 'usr_agent' } }));
      await rejects(guard.authorize('d', 'orders.list', { read: true }), 'token_kind');
      assert.equal(events.length, 0);
    });

    it('denies after revocation and when introspection is unavailable, without auditing access (TEST-043/044)', async () => {
      let revoked = false;
      tokens.set('pa_it_1', () => (revoked ? { active: false } : support()));
      const { guard, events } = setup();
      await guard.authorize('pa_it_1', 'orders.list', { read: true });
      revoked = true;
      await rejects(guard.authorize('pa_it_1', 'orders.list', { read: true }), 'inactive');
      mode = 'error';
      await rejects(guard.authorize('pa_it_1', 'orders.list', { read: true }), 'unavailable');
      assert.equal(events.length, 1);
    });

    it('authorizeAny routes by the authoritative token_kind with one introspection', async () => {
      tokens.set('pa_at_user', active());
      tokens.set('pa_at_disguised', support()); // prefix does not matter
      const { guard, events } = setup();
      const before = introspections;
      const u = await guard.authorizeAny('pa_at_user', 'orders.annotate', { read: false });
      assert.equal(u.isSupport(), false);
      await rejects(guard.authorizeAny('pa_at_disguised', 'orders.annotate', { read: false }), 'support_policy');
      const s = await guard.authorizeAny('pa_at_disguised', 'orders.list', { read: true });
      assert.equal(s.isSupport(), true);
      assert.equal(introspections - before, 3);
      assert.equal(events.length, 2);
    });

    it('provides Express-style middleware with distinct statuses', async () => {
      tokens.set('pa_it_1', support());
      tokens.set('pa_at_user', active());
      const { guard } = setup();
      const readMw = guard.middleware({ operation: 'orders.list', read: true });
      const writeMw = guard.middleware({ operation: 'orders.annotate', read: false });
      const srv = createServer((req, res) => {
        const mw = req.url === '/write' ? writeMw : readMw;
        mw(req, res, (err?: unknown) => {
          res.statusCode = err ? 500 : 200;
          res.end();
        });
      });
      await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
      const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
      const call = (path: string, tok?: string): Promise<number> =>
        fetch(base + path, tok ? { headers: { authorization: 'Bearer ' + tok } } : {}).then((r) => r.status);
      try {
        assert.equal(await call('/read', 'pa_it_1'), 200);
        assert.equal(await call('/write', 'pa_it_1'), 403);
        assert.equal(await call('/write', 'pa_at_user'), 200);
        assert.equal(await call('/read', 'pa_at_unknown'), 401);
        assert.equal(await call('/read'), 401);
        mode = 'error';
        assert.equal(await call('/read', 'pa_it_1'), 503);
      } finally {
        srv.closeAllConnections();
        await new Promise<void>((r) => srv.close(() => r()));
      }
    });
  });
});
