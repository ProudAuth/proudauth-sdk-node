import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { AdminClient, AdminRequestError, ProblemError, SDK_VERSION, Secret, type User } from '../src/admin.js';
import { json, sleep, startServer, type TestServer } from './helpers.js';

const TOKEN = 'pa_at_admin_secret_token';

describe('AdminClient', () => {
  let api: TestServer;
  const seen: { method?: string; path?: string; headers?: Record<string, string | string[] | undefined>; body?: string }[] = [];

  before(async () => {
    api = await startServer(async (req, res, body) => {
      seen.push({ method: req.method!, path: req.url!, headers: req.headers, body });
      const u = new URL(req.url!, 'http://x');
      const p = u.pathname.replace('/api/v1/realms/main%20realm', '');
      if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, { code: 'unauthenticated', title: 'Unauthenticated' });
      if (p === '/users' && req.method === 'GET') {
        const cursor = u.searchParams.get('cursor');
        const pages: Record<string, { items: unknown[]; next_cursor: string }> = {
          '': { items: [{ id: 'u1' }, { id: 'u2' }], next_cursor: 'c1' },
          c1: { items: [{ id: 'u3' }], next_cursor: 'c2' },
          c2: { items: [{ id: 'u4' }], next_cursor: '' },
        };
        return json(res, 200, pages[cursor ?? '']);
      }
      if (p === '/organizations' && req.method === 'GET') return json(res, 200, { items: [{ id: 'o1' }], next_cursor: 'loop' });
      if (p === '/clients' && req.method === 'POST') {
        return json(res, 201, { client: { client_id: 'web' }, client_secret: 'pa_cs_once', recovery_codes: ['aaaa-bbbb'] }, {
          deprecation: '@1767225600',
          sunset: 'Wed, 01 Jul 2026 00:00:00 GMT',
        });
      }
      if (p === '/users' && req.method === 'POST') {
        const input = JSON.parse(body) as { email?: string };
        if (input.email === 'dup@example.test') {
          return json(
            res,
            409,
            { type: 'about:blank', code: 'conflict', title: 'Conflict', detail: 'identifier already in use', errors: { email: 'taken' }, request_id: 'req_1', retryable: false },
            { 'content-type': 'application/problem+json' },
          );
        }
        return json(res, 201, { id: 'u9', setup_token: 'pa_inv_once' });
      }
      if (p === '/users/u%2F1' && req.method === 'GET') return json(res, 200, { id: 'u/1', version: 3 }, { etag: '"v3"' });
      if (p === '/users/u%2F1' && req.method === 'PATCH') {
        if (req.headers['if-match'] !== '"v3"') return json(res, 412, { code: 'precondition_failed', title: 'Stale' });
        return json(res, 200, { id: 'u/1', version: 4 }, { etag: '"v4"' });
      }
      if (p === '/users/u1/revoke-sessions') return json(res, 200, { revoked_sessions: 3 });
      if (p === '/organizations/o1/invitations/batch' && req.method === 'POST') return json(res, 200, { results: [{ index: 0, status: 201 }] });
      if (p === '/slow') {
        await sleep(500);
        return json(res, 200, {});
      }
      if (p === '/empty') {
        res.statusCode = 204;
        return res.end();
      }
      if (p === '/teapot') {
        res.statusCode = 503;
        return res.end('upstream exploded');
      }
      json(res, 404, { code: 'not_found', title: 'Not Found' });
    });
  });
  after(() => api.close());

  const admin = (over: Partial<ConstructorParameters<typeof AdminClient>[0]> = {}): AdminClient =>
    new AdminClient({ baseUrl: api.url + '/', realm: 'main realm', token: TOKEN, userAgent: 'sdk-test', ...over });

  it('iterates every page with opaque cursors', async () => {
    const ids: string[] = [];
    for await (const u of admin().users('ann')) ids.push((u as User).id);
    assert.deepEqual(ids, ['u1', 'u2', 'u3', 'u4']);
    const paths = seen.filter((s) => s.path?.includes('/users?')).map((s) => s.path);
    assert.ok(paths.some((p) => p?.endsWith('/users?q=ann&cursor=c2')));
  });

  it('stops on a cursor loop instead of spinning', async () => {
    await assert.rejects(
      (async () => {
        for await (const _ of admin().organizations()) void _;
      })(),
      (e: unknown) => e instanceof AdminRequestError && e.code === 'invalid_response',
    );
  });

  it('returns typed RFC 9457 problems', async () => {
    await assert.rejects(admin().createUser({ email: 'dup@example.test' }), (e: unknown) => {
      assert.ok(e instanceof ProblemError);
      assert.equal(e.status, 409);
      assert.equal(e.code, 'conflict');
      assert.equal(e.title, 'Conflict');
      assert.equal(e.detail, 'identifier already in use');
      assert.deepEqual({ ...e.errors }, { email: 'taken' });
      assert.equal(e.requestId, 'req_1');
      assert.equal(e.extra.retryable, false);
      assert.equal(e.message, '409 conflict: Conflict (identifier already in use) [email: taken]');
      assert.ok(!e.message.includes(TOKEN));
      return true;
    });
    await assert.rejects(admin().request('GET', '/teapot'), (e: unknown) => e instanceof ProblemError && e.code === 'Service Unavailable');
    await assert.rejects(admin({ token: 'wrong' }).request('GET', '/users'), (e: unknown) => e instanceof ProblemError && e.status === 401);
  });

  it('sends idempotency keys on creates (random by default, caller-provided for retries)', async () => {
    await admin().createUser({ email: 'a@example.test' });
    const first = seen.at(-1)!;
    assert.match(String(first.headers?.['idempotency-key']), /^[0-9a-f]{32}$/);
    assert.equal(first.headers?.['content-type'], 'application/json');
    assert.equal(first.headers?.['user-agent'], `sdk-test proudauth-sdk-node/${SDK_VERSION}`);
    await admin().createUser({ email: 'a@example.test' }, { idempotencyKey: 'retry-key-1' });
    assert.equal(seen.at(-1)!.headers?.['idempotency-key'], 'retry-key-1');
  });

  it('keeps the generated idempotency key for batch invitations when the option is undefined', async () => {
    const results = await admin().inviteBatch('o1', [{ email: 'a@example.test' }], { idempotencyKey: undefined });
    assert.deepEqual(results, [{ index: 0, status: 201 }]);
    assert.match(String(seen.at(-1)!.headers?.['idempotency-key']), /^[0-9a-f]{32}$/);
    await admin().inviteBatch('o1', [], {});
    assert.match(String(seen.at(-1)!.headers?.['idempotency-key']), /^[0-9a-f]{32}$/);
    await admin().inviteBatch('o1', [], { idempotencyKey: 'batch-retry-1' });
    assert.equal(seen.at(-1)!.headers?.['idempotency-key'], 'batch-retry-1');
  });

  it('supports If-Match with ETags and escapes path identifiers', async () => {
    const a = admin();
    const got = await a.getUser('u/1');
    assert.equal(got.etag, '"v3"');
    const upd = await a.updateUser('u/1', { display_name: 'Ann' }, { ifMatch: got.etag! });
    assert.equal(upd.etag, '"v4"');
    await assert.rejects(a.updateUser('u/1', { display_name: 'Ann' }, { ifMatch: '"v1"' }), (e: unknown) => e instanceof ProblemError && e.status === 412);
  });

  it('enforces deadlines and cancellation via AbortSignal', async () => {
    await assert.rejects(admin({ timeoutMs: 50 }).request('GET', '/slow'), (e: unknown) => e instanceof AdminRequestError && e.code === 'timeout');
    const ctl = new AbortController();
    setTimeout(() => ctl.abort(), 20);
    await assert.rejects(admin().request('GET', '/slow', undefined, { signal: ctl.signal }), (e: unknown) => e instanceof AdminRequestError && e.code === 'aborted');
  });

  it('uses token sources, handles empty bodies and validates input', async () => {
    let calls = 0;
    const a = admin({
      token: async () => {
        calls++;
        return TOKEN;
      },
    });
    assert.equal(await a.revokeSessions('u1'), 3);
    const empty = await a.request('POST', '/empty', {});
    assert.equal(empty.status, 204);
    assert.equal(empty.data, undefined);
    assert.equal(calls, 2);
    await assert.rejects(a.setUserState('u1', 'delete' as never, 'x'), /unknown user state action/);
    await assert.rejects(a.request('GET', 'users'), /must start/);
    await assert.rejects(admin({ token: () => Promise.reject(new Error('vault down')) }).request('GET', '/users'), (e: unknown) => e instanceof AdminRequestError && e.code === 'token_source');
    assert.throws(() => new AdminClient({ baseUrl: 'not a url', realm: 'r' }), /absolute URL/);
  });

  it('never includes request bodies or tokens in transport errors', async () => {
    const dead = new AdminClient({ baseUrl: 'http://127.0.0.1:1', realm: 'main', token: TOKEN });
    await assert.rejects(dead.createUser({ password: 'hunter2' }), (e: unknown) => {
      assert.ok(e instanceof AdminRequestError);
      assert.equal(e.code, 'network');
      assert.ok(!e.message.includes('hunter2') && !e.message.includes(TOKEN));
      return true;
    });
  });

  it('wraps one-time secrets, sends its version and reports deprecation (SDK-007)', async () => {
    const notes: string[] = [];
    const a = new AdminClient({ baseUrl: api.url, realm: 'main realm', token: TOKEN, userAgent: 'tool/1', onDeprecated: (d) => notes.push(`${d.method} ${d.path} ${d.deprecation}`) });
    const res = await a.request<Record<string, unknown>>('POST', '/clients', {});
    const secret = res.data.client_secret;
    assert.ok(secret instanceof Secret);
    assert.equal(secret.reveal(), 'pa_cs_once');
    const shown = [String(secret), JSON.stringify(res.data), inspect(res.data, { depth: 5 }), `${secret}`].join(' ');
    assert.ok(!shown.includes('pa_cs_once') && !shown.includes('aaaa-bbbb'), shown);
    assert.deepEqual(res.data.client, { client_id: 'web' });
    assert.equal(res.deprecation, '@1767225600');
    assert.deepEqual(notes, ['POST /clients @1767225600']);
    const sent = seen[seen.length - 1]!.headers!;
    assert.equal(sent['proudauth-sdk'], `node/${SDK_VERSION}`);
    assert.equal(sent['user-agent'], `tool/1 proudauth-sdk-node/${SDK_VERSION}`);
  });
});
