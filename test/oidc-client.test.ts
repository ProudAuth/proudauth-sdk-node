import { after, before, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { OIDCClient, isOIDCError, pkceChallenge, type OIDCClientConfig, type OIDCErrorCode } from '../src/oidc-client.js';
import { b64, json, makeKey, signJWT, signRaw, sleep, startServer, type TestKey, type TestServer } from './helpers.js';

const CLIENT_ID = 'customer-web-bff';
const CLIENT_SECRET = 'bff-secret';
const REDIRECT = 'https://app.test/callback';

const atHash = (alg: string, at: string): string => {
  const d = createHash(alg === 'EdDSA' ? 'sha512' : 'sha256').update(at).digest();
  return d.subarray(0, d.length / 2).toString('base64url');
};

interface PendingCode {
  challenge: string;
  nonce: string;
  redirectUri: string;
  used: boolean;
}

describe('OIDCClient', () => {
  let idp: TestServer;
  let issuer = '';
  let key: TestKey;
  const clock = { now: 1_800_000_000_000 };
  const codes = new Map<string, PendingCode>();
  // Refresh-token rotation with family revocation on reuse, like the server (SES-007/008).
  const refreshTokens = new Map<string, { family: string; used: boolean }>();
  const revokedFamilies = new Set<string>();
  const counters = { refresh: 0, reuse: 0, code: 0, revoke: 0 };
  let lastTokenRequest: { auth?: string; form: URLSearchParams } | undefined;
  let lastRevoke: { auth?: string; form: URLSearchParams } | undefined;
  let meta: Record<string, unknown> = {};
  let idTokenOverride: ((nonce: string, at: string) => string | undefined) | undefined;

  const nowSec = (): number => Math.floor(clock.now / 1000);

  const idToken = (claims: Record<string, unknown>, header: Record<string, unknown> = { typ: 'JWT' }, k: TestKey = key): string =>
    signJWT(k, { iss: issuer, sub: 'usr_1', aud: CLIENT_ID, iat: nowSec(), exp: nowSec() + 300, ...claims }, header);

  const issue = (family: string, nonce?: string): Record<string, unknown> => {
    const at = 'pa_at_' + randomBytes(12).toString('base64url');
    const rt = 'pa_rt_' + randomBytes(12).toString('base64url');
    refreshTokens.set(rt, { family, used: false });
    let id: string | undefined;
    if (nonce !== undefined) {
      id = idTokenOverride
        ? idTokenOverride(nonce, at)
        : idToken({ nonce, at_hash: atHash(key.alg, at), azp: CLIENT_ID, sid: 'ses_1', auth_time: nowSec() - 5 });
    }
    return { access_token: at, token_type: 'Bearer', expires_in: 300, refresh_token: rt, scope: 'openid orders:read', ...(id ? { id_token: id } : {}) };
  };

  before(async () => {
    key = makeKey('ES256', 'idp-1');
    idp = await startServer(async (req, res, body) => {
      const path = req.url ?? '';
      const p = '/realms/main';
      if (path === `${p}/.well-known/openid-configuration`) return json(res, 200, meta);
      if (path === `${p}/jwks`) return json(res, 200, { keys: [key.jwk] });
      if (path === `${p}/oauth/token` && req.method === 'POST') {
        const form = new URLSearchParams(body);
        lastTokenRequest = { form, ...(req.headers.authorization ? { auth: req.headers.authorization } : {}) };
        if (form.get('grant_type') === 'authorization_code') {
          counters.code++;
          const c = codes.get(form.get('code') ?? '');
          if (!c || c.used || pkceChallenge(form.get('code_verifier') ?? '') !== c.challenge || form.get('redirect_uri') !== c.redirectUri) {
            return json(res, 400, { error: 'invalid_grant' });
          }
          c.used = true;
          return json(res, 200, issue(randomBytes(4).toString('hex'), c.nonce), { 'cache-control': 'no-store' });
        }
        if (form.get('grant_type') === 'refresh_token') {
          counters.refresh++;
          await sleep(25); // widen the race window
          const rt = refreshTokens.get(form.get('refresh_token') ?? '');
          if (!rt || revokedFamilies.has(rt.family)) return json(res, 400, { error: 'invalid_grant' });
          if (rt.used) {
            counters.reuse++;
            revokedFamilies.add(rt.family); // reuse revokes the whole family
            return json(res, 400, { error: 'invalid_grant' });
          }
          rt.used = true;
          return json(res, 200, issue(rt.family));
        }
        return json(res, 400, { error: 'unsupported_grant_type' });
      }
      if (path === `${p}/oauth/revoke` && req.method === 'POST') {
        counters.revoke++;
        lastRevoke = { form: new URLSearchParams(body), ...(req.headers.authorization ? { auth: req.headers.authorization } : {}) };
        const rt = refreshTokens.get(lastRevoke.form.get('token') ?? '');
        if (rt) revokedFamilies.add(rt.family);
        res.statusCode = 200;
        return res.end();
      }
      json(res, 404, {});
    });
    issuer = idp.url + '/realms/main';
  });
  after(() => idp.close());

  beforeEach(() => {
    clock.now = 1_800_000_000_000;
    idTokenOverride = undefined;
    meta = {
      issuer,
      authorization_endpoint: issuer + '/oauth/authorize',
      token_endpoint: issuer + '/oauth/token',
      jwks_uri: issuer + '/jwks',
      revocation_endpoint: issuer + '/oauth/revoke',
      end_session_endpoint: issuer + '/oidc/logout',
      authorization_response_iss_parameter_supported: true,
    };
  });

  const client = (over: Partial<OIDCClientConfig> = {}): OIDCClient =>
    new OIDCClient({
      issuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT,
      scopes: ['openid', 'orders:read'],
      resource: 'https://api.test/orders',
      now: () => clock.now,
      jwksMinRefreshIntervalMs: 60_000,
      ...over,
    });

  /** Simulates the user completing login at the IdP: returns the callback query. */
  const login = async (c: OIDCClient) => {
    const ar = await c.authorizationUrl();
    const u = new URL(ar.url);
    const code = 'pa_ac_' + randomBytes(8).toString('hex');
    codes.set(code, {
      challenge: u.searchParams.get('code_challenge')!,
      nonce: u.searchParams.get('nonce')!,
      redirectUri: u.searchParams.get('redirect_uri')!,
      used: false,
    });
    return { ar, code, callback: `${REDIRECT}?code=${code}&state=${ar.state}&iss=${encodeURIComponent(issuer)}` };
  };

  const rejects = (p: Promise<unknown>, code: OIDCErrorCode, reason?: string): Promise<void> =>
    assert.rejects(p, (e: unknown) => {
      assert.ok(isOIDCError(e), String(e));
      assert.equal(e.code, code, e.message);
      if (reason !== undefined) assert.equal(e.reason, reason, e.message);
      return true;
    });

  it('builds an authorization URL with PKCE S256, state, nonce and resource', async () => {
    const ar = await client().authorizationUrl({ extraParams: { prompt: 'login' } });
    const u = new URL(ar.url);
    assert.equal(u.origin + u.pathname, issuer + '/oauth/authorize');
    const q = u.searchParams;
    assert.equal(q.get('response_type'), 'code');
    assert.equal(q.get('client_id'), CLIENT_ID);
    assert.equal(q.get('redirect_uri'), REDIRECT);
    assert.equal(q.get('scope'), 'openid orders:read');
    assert.equal(q.get('state'), ar.state);
    assert.equal(q.get('nonce'), ar.nonce);
    assert.equal(q.get('code_challenge_method'), 'S256');
    assert.equal(q.get('code_challenge'), createHash('sha256').update(ar.codeVerifier).digest('base64url'));
    assert.equal(q.get('resource'), 'https://api.test/orders');
    assert.equal(q.get('prompt'), 'login');
    assert.ok(ar.codeVerifier.length >= 43 && ar.state.length >= 43 && ar.nonce.length >= 43);
    assert.notEqual(ar.state, ar.nonce);
  });

  it('refuses to override security parameters through extraParams', async () => {
    for (const k of ['state', 'nonce', 'code_challenge', 'code_challenge_method', 'redirect_uri', 'client_id', 'response_type']) {
      await assert.rejects(client().authorizationUrl({ extraParams: { [k]: 'x' } }), /cannot be set/);
    }
  });

  it('exchanges the code, validating state, iss, nonce and at_hash', async () => {
    const c = client();
    const { ar, callback } = await login(c);
    const { tokens, idClaims } = await c.exchangeCode(ar, callback);
    assert.ok(tokens.accessToken.startsWith('pa_at_'));
    assert.ok(tokens.refreshToken?.startsWith('pa_rt_'));
    assert.equal(tokens.expiresAt, clock.now + 300_000);
    assert.equal(idClaims?.subject, 'usr_1');
    assert.equal(idClaims?.nonce, ar.nonce);
    assert.equal(idClaims?.sid, 'ses_1');
    assert.equal(lastTokenRequest?.form.get('code_verifier'), ar.codeVerifier);
    assert.equal(lastTokenRequest?.form.get('redirect_uri'), REDIRECT);
    assert.equal(lastTokenRequest?.auth, 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'));
    assert.equal(lastTokenRequest?.form.get('client_secret'), null);
  });

  it('rejects a state mismatch before redeeming the code (TEST-028)', async () => {
    const c = client();
    const { ar, code } = await login(c);
    const before = counters.code;
    await rejects(c.exchangeCode(ar, { code, state: 'attacker', iss: issuer }), 'state');
    await rejects(c.exchangeCode(ar, { code, iss: issuer }), 'state');
    await rejects(c.exchangeCode(ar, `?code=${code}&state=${ar.state}&state=other&iss=${encodeURIComponent(issuer)}`), 'provider');
    assert.equal(counters.code, before);
  });

  it('rejects mix-up: wrong or missing iss in the authorization response (RFC 9207)', async () => {
    const c = client();
    const { ar, code } = await login(c);
    await rejects(c.exchangeCode(ar, { code, state: ar.state, iss: 'https://evil.test' }), 'provider');
    await rejects(c.exchangeCode(ar, { code, state: ar.state }), 'provider');
    meta.authorization_response_iss_parameter_supported = false;
    const c2 = client();
    const l2 = await login(c2);
    await c2.exchangeCode(l2.ar, { code: l2.code, state: l2.ar.state }); // iss optional when not advertised
  });

  it('surfaces provider errors without echoing arbitrary text', async () => {
    const c = client();
    const { ar } = await login(c);
    await assert.rejects(c.exchangeCode(ar, { error: 'access_denied', state: ar.state, iss: issuer }), (e: unknown) => {
      assert.ok(isOIDCError(e, 'provider'));
      assert.equal(e.providerError, 'access_denied');
      return true;
    });
    await assert.rejects(c.exchangeCode(ar, { error: '<script>', state: ar.state, iss: issuer }), (e: unknown) => {
      assert.ok(isOIDCError(e, 'provider'));
      assert.equal(e.providerError, 'unrecognized_error');
      return true;
    });
  });

  it('maps a replayed code to reauthenticate (invalid_grant)', async () => {
    const c = client();
    const { ar, callback } = await login(c);
    await c.exchangeCode(ar, callback);
    await rejects(c.exchangeCode(ar, callback), 'reauthenticate');
  });

  it('rejects a nonce mismatch and a bad at_hash', async () => {
    const c = client();
    idTokenOverride = (_nonce, at) => idToken({ nonce: 'other', at_hash: atHash('ES256', at) });
    const l1 = await login(c);
    await rejects(c.exchangeCode(l1.ar, l1.callback), 'nonce');
    idTokenOverride = (nonce) => idToken({ nonce, at_hash: atHash('ES256', 'different-token') });
    const l2 = await login(c);
    await rejects(c.exchangeCode(l2.ar, l2.callback), 'id_token', 'at_hash');
    idTokenOverride = () => undefined;
    // An openid request must return an ID token.
    const l3 = await login(c);
    await rejects(c.exchangeCode(l3.ar, l3.callback), 'id_token', 'missing ID token');
  });

  describe('ID token validation (OIDC-016)', () => {
    it('accepts a valid ID token', async () => {
      const claims = await client().validateIdToken(idToken({ nonce: 'n1' }), { nonce: 'n1' });
      assert.equal(claims.issuer, issuer);
      assert.deepEqual([...claims.audience], [CLIENT_ID]);
    });

    it('rejects wrong issuer, audience, azp, expiry, iat, subject', async () => {
      const c = client();
      await rejects(c.validateIdToken(idToken({ iss: 'https://evil.test' })), 'id_token', 'issuer');
      await rejects(c.validateIdToken(idToken({ aud: 'other-client' })), 'id_token', 'audience');
      await rejects(c.validateIdToken(idToken({ aud: [CLIENT_ID, 'other'] })), 'id_token', 'authorized party');
      await c.validateIdToken(idToken({ aud: [CLIENT_ID, 'other'], azp: CLIENT_ID }));
      await rejects(c.validateIdToken(idToken({ azp: 'other' })), 'id_token', 'authorized party');
      await rejects(c.validateIdToken(idToken({ exp: nowSec() - 31 })), 'id_token', 'expired');
      await rejects(c.validateIdToken(idToken({ exp: undefined })), 'id_token', 'expired');
      await rejects(c.validateIdToken(idToken({ iat: nowSec() + 120 })), 'id_token', 'issued in the future');
      await rejects(c.validateIdToken(idToken({ sub: '' })), 'id_token', 'subject');
      await rejects(c.validateIdToken(idToken({ nonce: 'a' }), { nonce: 'b' }), 'nonce');
      await rejects(c.validateIdToken(idToken({}), { nonce: 'b' }), 'nonce');
      await rejects(c.validateIdToken(idToken({ auth_time: nowSec() - 600 }), { maxAgeSec: 300 }), 'id_token', 'max_age');
    });

    it('rejects alg none, HS256 confusion, access tokens and foreign keys', async () => {
      const c = client();
      const payload = { iss: issuer, sub: 'usr_1', aud: CLIENT_ID, exp: nowSec() + 60 };
      const none = `${b64(JSON.stringify({ alg: 'none', kid: key.kid }))}.${b64(JSON.stringify(payload))}.`;
      await rejects(c.validateIdToken(none), 'id_token', 'algorithm');
      const input = `${b64(JSON.stringify({ alg: 'HS256', kid: key.kid }))}.${b64(JSON.stringify(payload))}`;
      const hs = `${input}.${createHmac('sha256', JSON.stringify(key.jwk)).update(input).digest('base64url')}`;
      await rejects(c.validateIdToken(hs), 'id_token', 'algorithm');
      await rejects(c.validateIdToken(idToken({}, { typ: 'at+jwt' })), 'id_token', 'type');
      await rejects(c.validateIdToken(idToken({}, { typ: 'JWT' }, makeKey('ES256', key.kid))), 'id_token', 'signature');
      const dup = signRaw(key, JSON.stringify({ alg: 'ES256', kid: key.kid }), JSON.stringify(payload).slice(0, -1) + ',"sub":"usr_admin"}');
      await rejects(c.validateIdToken(dup), 'id_token', 'duplicate member');
    });

    it('bounds JWKS fetches for unknown key IDs', async () => {
      const c = client();
      const results = await Promise.allSettled(
        Array.from({ length: 100 }, () => c.validateIdToken(idToken({}, { typ: 'JWT', kid: randomBytes(6).toString('hex') }))),
      );
      assert.ok(results.every((r) => r.status === 'rejected' && isOIDCError(r.reason, 'id_token')));
      assert.equal(c.jwksFetchCount, 1);
    });
  });

  describe('Session single-flight refresh (SES-009, TEST-030)', () => {
    const loggedIn = async () => {
      const c = client();
      const { ar, callback } = await login(c);
      const { tokens, idClaims } = await c.exchangeCode(ar, callback);
      const persisted: string[] = [];
      const s = c.session(tokens, { ...(idClaims ? { idClaims } : {}), onRefresh: (t) => void persisted.push(t.refreshToken!) });
      return { c, s, tokens, persisted };
    };

    it('returns the current token while it is fresh', async () => {
      const { s, tokens } = await loggedIn();
      assert.equal(await s.accessToken(), tokens.accessToken);
      assert.equal(s.refreshCount, 0);
    });

    it('shares one refresh among concurrent callers and survives rotation', async () => {
      const { s, tokens, persisted } = await loggedIn();
      const before = { refresh: counters.refresh, reuse: counters.reuse };
      clock.now += 290_000; // inside the 15s refresh window
      const results = await Promise.all(Array.from({ length: 25 }, () => s.accessToken()));
      assert.equal(new Set(results).size, 1);
      assert.notEqual(results[0], tokens.accessToken);
      assert.equal(counters.refresh - before.refresh, 1);
      assert.equal(s.refreshCount, 1);
      assert.notEqual(s.tokens?.refreshToken, tokens.refreshToken, 'refresh token rotated');
      assert.equal(persisted.length, 1);
      // A second expiry: the rotated token is used; no reuse, family intact.
      clock.now += 300_000;
      const again = await Promise.all(Array.from({ length: 25 }, () => s.accessToken()));
      assert.equal(new Set(again).size, 1);
      assert.equal(counters.refresh - before.refresh, 2);
      assert.equal(counters.reuse - before.reuse, 0);
      assert.equal(s.tokens?.idToken, tokens.idToken, 'ID token kept when not reissued');
    });

    it('without single-flight, parallel use of one refresh token revokes the family (fixture sanity)', async () => {
      const { c, tokens } = await loggedIn();
      const a = c.session(tokens);
      const b = c.session(tokens); // two sessions holding the same refresh token
      clock.now += 300_000;
      const r = await Promise.allSettled([a.accessToken(), b.accessToken()]);
      assert.equal(r.filter((x) => x.status === 'rejected').length, 1);
      const winner = r[0]!.status === 'fulfilled' ? a : b;
      clock.now += 300_000;
      await rejects(winner.accessToken(), 'reauthenticate'); // family revoked after reuse
    });

    it('forces one refresh for a rejected access token', async () => {
      const { s, tokens } = await loggedIn();
      const [x, y] = await Promise.all([s.accessToken({ rejectedToken: tokens.accessToken }), s.accessToken({ rejectedToken: tokens.accessToken })]);
      assert.equal(x, y);
      assert.notEqual(x, tokens.accessToken);
      assert.equal(s.refreshCount, 1);
      assert.equal(await s.accessToken({ rejectedToken: tokens.accessToken }), x, 'stale rejection does not refresh again');
      assert.equal(s.refreshCount, 1);
    });

    it('clears the session when refresh fails: the user must authenticate again', async () => {
      const { c, s, tokens } = await loggedIn();
      await c.revoke(tokens.refreshToken!);
      clock.now += 300_000;
      await rejects(s.accessToken(), 'reauthenticate');
      assert.equal(s.tokens, undefined);
      const before = counters.refresh;
      await rejects(s.accessToken(), 'reauthenticate');
      assert.equal(counters.refresh, before, 'no further provider calls');
    });
  });

  it('revokes with client authentication and builds the logout URL', async () => {
    const c = client();
    const { ar, callback } = await login(c);
    const { tokens, idClaims } = await c.exchangeCode(ar, callback);
    const s = c.session(tokens, idClaims ? { idClaims } : {});
    const url = new URL(await c.logout(s, { postLogoutRedirectUri: 'https://app.test/bye', state: 'st' }));
    assert.equal(url.origin + url.pathname, issuer + '/oidc/logout');
    assert.equal(url.searchParams.get('id_token_hint'), tokens.idToken);
    assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
    assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://app.test/bye');
    assert.equal(url.searchParams.get('state'), 'st');
    assert.equal(s.tokens, undefined);
    assert.equal(lastRevoke?.form.get('token'), tokens.refreshToken);
    assert.equal(lastRevoke?.form.get('token_type_hint'), 'refresh_token');
    assert.ok(lastRevoke?.auth?.startsWith('Basic '));
  });

  it('sends client_id in the body for public clients', async () => {
    const c = client({ clientSecret: '' });
    const { ar, callback } = await login(c);
    await c.exchangeCode(ar, callback);
    assert.equal(lastTokenRequest?.auth, undefined);
    assert.equal(lastTokenRequest?.form.get('client_id'), CLIENT_ID);
  });

  it('trusts only discovery from the configured issuer, with endpoints on its origin', async () => {
    meta.issuer = 'https://evil.test/realms/main';
    await rejects(client().authorizationUrl(), 'provider', 'discovery issuer mismatch');
    meta.issuer = issuer;
    meta.token_endpoint = 'https://evil.test/token';
    const c = client();
    const { ar, callback } = await login(c);
    await rejects(c.exchangeCode(ar, callback), 'provider', 'endpoint token_endpoint is not on the issuer origin');
    meta.token_endpoint = idp.url.replace('127.0.0.1', '127.0.0.1.evil.test') + '/token';
    const c2 = client();
    const l2 = await login(c2);
    await rejects(c2.exchangeCode(l2.ar, l2.callback), 'provider');
  });

  it('validates configuration', () => {
    assert.throws(() => client({ issuer: '' }), /required/);
    assert.throws(() => client({ algorithms: ['HS256'] }), /not allowed/);
    assert.throws(() => client({ clockSkewMs: 120_000 }), /60s/);
  });
});
