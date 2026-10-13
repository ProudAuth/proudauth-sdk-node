import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  Verifier,
  bearerToken,
  challenge,
  fastifyHook,
  getClaims,
  isVerifierError,
  middleware,
  protect,
  requireScopes,
  VerifierError,
  type NextFunction,
} from '../src/verifier.js';
import { json, makeKey, signJWT, startServer, type TestKey, type TestServer } from './helpers.js';

const ISS = 'https://id.test/realms/main';
const AUD = 'https://api.test/orders';

function token(key: TestKey, extra: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  return signJWT(key, {
    iss: ISS,
    sub: 'usr_1',
    aud: AUD,
    client_id: 'web',
    iat: now,
    exp: now + 300,
    jti: 'j1',
    scope: 'orders:read',
    org_id: 'org_a',
    token_kind: 'user_access',
    ...extra,
  });
}

describe('bearerToken', () => {
  it('extracts a bearer token from the Authorization header only', () => {
    assert.equal(bearerToken({ headers: { authorization: 'Bearer abc.def.ghi' } }), 'abc.def.ghi');
    assert.equal(bearerToken({ headers: { authorization: 'bearer   pa_it_x-y_z  ' } }), 'pa_it_x-y_z');
    assert.equal(bearerToken({ url: '/orders?x=1', headers: { authorization: 'BEARER t' } }), 't');
  });

  it('refuses access tokens in the query string, even with a header (TOK-023)', () => {
    for (const url of ['/orders?access_token=abc', '/orders?a=1&access_token=abc']) {
      assert.throws(
        () => bearerToken({ url, headers: { authorization: 'Bearer abc' } }),
        (e: unknown) => isVerifierError(e, 'invalid_request'),
      );
    }
    assert.throws(
      () => bearerToken({ url: '/x', originalUrl: '/api/x?access_token=abc', headers: {} }),
      (e: unknown) => isVerifierError(e, 'invalid_request'),
    );
  });

  it('reports missing and malformed credentials', () => {
    const missing = (e: unknown): boolean => isVerifierError(e, 'missing_token');
    assert.throws(() => bearerToken({ headers: {} }), missing);
    assert.throws(() => bearerToken({ headers: { authorization: 'Basic dXNlcjpwYXNz' } }), missing);
    assert.throws(() => bearerToken({ headers: { authorization: 'Bearer ' } }), missing);
    assert.throws(() => bearerToken({ headers: { authorization: 'Bearer    ' } }), missing);
    assert.throws(() => bearerToken({ headers: { authorization: 'Bearer a b' } }), (e: unknown) => isVerifierError(e, 'malformed'));
    assert.throws(() => bearerToken({ headers: { authorization: 'Bearer a,b' } }), (e: unknown) => isVerifierError(e, 'malformed'));
  });
});

describe('challenge', () => {
  it('maps error categories to RFC 6750 responses', () => {
    assert.deepEqual(challenge(new VerifierError('missing_token')), { status: 401, headers: { 'www-authenticate': 'Bearer' } });
    assert.deepEqual(challenge(new VerifierError('missing_token'), { realm: 'orders "api"' }).headers, {
      'www-authenticate': 'Bearer realm="orders \\"api\\""',
    });
    assert.equal(challenge(new VerifierError('expired')).headers['www-authenticate'], 'Bearer error="invalid_token"');
    assert.equal(challenge(new VerifierError('invalid_request')).status, 400);
    const scope = challenge(new VerifierError('scope'), { scopes: ['orders:write'] });
    assert.equal(scope.status, 403);
    assert.equal(scope.headers['www-authenticate'], 'Bearer error="insufficient_scope", scope="orders:write"');
    assert.deepEqual(challenge(new VerifierError('organization')), {
      status: 403,
      headers: { 'www-authenticate': 'Bearer error="insufficient_scope"' },
      error: 'insufficient_scope',
    });
    assert.deepEqual(challenge(new VerifierError('support_policy')), { status: 403, headers: {} });
    assert.deepEqual(challenge(new VerifierError('unavailable')), { status: 503, headers: {} });
    assert.equal(challenge(new Error('boom')).status, 500);
  });
});

describe('HTTP adapters', () => {
  let key: TestKey;
  let jwks: TestServer;
  let jwksUp = true;
  let api: ReturnType<typeof createServer>;
  let base: string;
  const seen: { claimsSub?: string; reqAuth?: unknown } = {};
  const errors: string[] = [];

  before(async () => {
    key = makeKey('ES256', 'k1');
    jwks = await startServer((_q, res) => (jwksUp ? json(res, 200, { keys: [key.jwk] }) : json(res, 500, {})));
    const verifier = new Verifier({ issuer: ISS, audience: AUD, jwksUrl: jwks.url, minRefreshIntervalMs: 1_000 });
    const auth = middleware(verifier, { onError: (e) => errors.push(isVerifierError(e) ? e.code : 'other') });
    const needWrite = requireScopes('orders:write');
    const plain = protect(verifier, (_req, res, claims) => {
      res.end('plain:' + claims.subject);
    });
    // A minimal Connect-style chain.
    const chain =
      (...mws: ((req: IncomingMessage, res: ServerResponse, next: NextFunction) => void)[]) =>
      (req: IncomingMessage, res: ServerResponse, final: () => void) => {
        let i = 0;
        const next: NextFunction = (err) => {
          if (err) {
            res.statusCode = 500;
            res.end();
            return;
          }
          const mw = mws[i++];
          if (mw) mw(req, res, next);
          else final();
        };
        next();
      };
    api = createServer((req, res) => {
      if (req.url?.startsWith('/plain')) return plain(req, res);
      if (req.url?.startsWith('/write')) {
        return chain(auth as never, needWrite as never)(req, res, () => res.end('wrote'));
      }
      chain(auth as never)(req, res, () => {
        const c = getClaims(req);
        seen.claimsSub = c?.subject;
        seen.reqAuth = (req as unknown as { auth?: unknown }).auth;
        res.end('ok:' + c?.subject);
      });
    });
    await new Promise<void>((r) => api.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
  });

  after(async () => {
    api.closeAllConnections();
    await new Promise<void>((r) => api.close(() => r()));
    await jwks.close();
  });

  const call = (path: string, auth?: string): Promise<Response> =>
    fetch(base + path, auth ? { headers: { authorization: auth } } : {});

  it('passes verified claims to the next handler', async () => {
    const res = await call('/orders', 'Bearer ' + token(key));
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'ok:usr_1');
    assert.equal(seen.claimsSub, 'usr_1');
    assert.ok(seen.reqAuth, 'req.auth is set');
  });

  it('challenges a missing token without an error code', async () => {
    const res = await call('/orders');
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('www-authenticate'), 'Bearer');
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });

  it('rejects invalid tokens with invalid_token and never runs the handler', async () => {
    seen.claimsSub = undefined;
    const idToken = signJWT(key, { iss: ISS, sub: 'usr_1', aud: AUD, exp: Math.floor(Date.now() / 1000) + 60 }, { typ: 'JWT' });
    for (const t of [token(key, { aud: 'https://api.test/billing' }), idToken, 'not-a-jwt']) {
      const res = await call('/orders', 'Bearer ' + t);
      assert.equal(res.status, 401);
      assert.equal(res.headers.get('www-authenticate'), 'Bearer error="invalid_token"');
      const body = await res.text();
      assert.ok(!body.includes(t));
    }
    assert.equal(seen.claimsSub, undefined);
    assert.ok(errors.includes('audience') && errors.includes('token_type'));
  });

  it('answers 400 invalid_request for a query-string token', async () => {
    const res = await fetch(base + '/orders?access_token=' + token(key));
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('www-authenticate'), 'Bearer error="invalid_request"');
  });

  it('enforces scopes with 403 insufficient_scope', async () => {
    const denied = await call('/write', 'Bearer ' + token(key));
    assert.equal(denied.status, 403);
    assert.equal(denied.headers.get('www-authenticate'), 'Bearer error="insufficient_scope", scope="orders:write"');
    const ok = await call('/write', 'Bearer ' + token(key, { scope: 'orders:read orders:write' }));
    assert.equal(ok.status, 200);
    assert.equal(await ok.text(), 'wrote');
  });

  it('wraps plain node:http handlers', async () => {
    assert.equal((await call('/plain', 'Bearer ' + token(key))).status, 200);
    const res = await call('/plain', 'Bearer ' + token(key, { exp: 1 }));
    assert.equal(res.status, 401);
  });

  it('answers 503 (fail closed) when keys cannot be loaded', async () => {
    jwksUp = false;
    try {
      const verifier = new Verifier({ issuer: ISS, audience: AUD, jwksUrl: jwks.url });
      const handler = protect(verifier, (_q, res) => res.end('should not run'));
      const srv = createServer(handler);
      await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
      try {
        const res = await fetch(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/`, {
          headers: { authorization: 'Bearer ' + token(key) },
        });
        assert.equal(res.status, 503);
        assert.equal(res.headers.get('www-authenticate'), null);
      } finally {
        srv.closeAllConnections();
        await new Promise<void>((r) => srv.close(() => r()));
      }
    } finally {
      jwksUp = true;
    }
  });
});

describe('fastifyHook', () => {
  const stub = (result: 'ok' | 'fail') => ({
    authenticate: async () => {
      if (result === 'fail') throw new VerifierError('expired');
      return { subject: 'usr_1' } as never;
    },
  });
  const reply = () => {
    const r = { status: 0, headers: {} as Record<string, string>, body: undefined as string | undefined };
    const api = {
      code(s: number) {
        r.status = s;
        return api;
      },
      header(k: string, v: string) {
        r.headers[k.toLowerCase()] = v;
        return api;
      },
      send(b?: string) {
        r.body = b;
      },
    };
    return { r, api };
  };

  it('stores claims and lets the route run on success', async () => {
    const req = { url: '/x', headers: { authorization: 'Bearer abc' } };
    const { r, api } = reply();
    const out = await fastifyHook(stub('ok'))(req, api);
    assert.equal(out, undefined);
    assert.equal(r.status, 0);
    assert.equal((getClaims(req) as unknown as { subject: string }).subject, 'usr_1');
  });

  it('answers 401 with a challenge and stops the lifecycle on failure', async () => {
    const req = { url: '/x', headers: { authorization: 'Bearer abc' } };
    const { r, api } = reply();
    const out = await fastifyHook(stub('fail'))(req, api);
    assert.equal(out, api);
    assert.equal(r.status, 401);
    assert.match(r.headers['www-authenticate'] ?? '', /invalid_token/);
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.equal(getClaims(req), undefined);
  });
});
