import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { Verifier, VerifierError, isVerifierError, type VerifierConfig } from '../src/verifier.js';
import { b64, json, makeKey, signJWT, signRaw, startServer, type TestKey, type TestServer } from './helpers.js';

const ISS = 'https://id.test/realms/main';
const AUD = 'https://api.test/orders';
const NOW = 1_800_000_000; // seconds

function claims(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISS,
    sub: 'usr_1',
    aud: AUD,
    client_id: 'customer-web-bff',
    iat: NOW,
    exp: NOW + 300,
    jti: 'tok_' + randomBytes(6).toString('hex'),
    sid: 'ses_1',
    scope: 'orders:read orders:create',
    org_id: 'org_a',
    token_kind: 'user_access',
    authz_version: 43,
    ...extra,
  };
}

async function rejects(p: Promise<unknown>, code: VerifierError['code']): Promise<void> {
  await assert.rejects(p, (e: unknown) => {
    assert.ok(isVerifierError(e), `expected VerifierError, got ${String(e)}`);
    assert.equal(e.code, code);
    return true;
  });
}

// First-party verifier (SDK-001): configured issuer and audience, cached keys
// with bounded refresh, an asymmetric algorithm allowlist, access-token type
// rules, organization extraction, typed errors and negative vectors.
describe('offline Verifier', () => {
  let es: TestKey, rs: TestKey, ps: TestKey, ed: TestKey;
  let jwks: TestServer;
  let published: Record<string, unknown>[];
  let status = 200;

  before(async () => {
    es = makeKey('ES256', 'es-1');
    rs = makeKey('RS256', 'rs-1');
    ps = makeKey('PS256', 'ps-1');
    ed = makeKey('EdDSA', 'ed-1');
    published = [es.jwk, rs.jwk, ps.jwk, ed.jwk];
    jwks = await startServer((_req, res) => {
      if (status !== 200) return json(res, status, { error: 'down' });
      json(res, 200, { keys: published });
    });
  });
  after(() => jwks.close());

  const make = (over: Partial<VerifierConfig> = {}, clock = { now: NOW * 1000 }): Verifier =>
    new Verifier({ issuer: ISS, audience: AUD, jwksUrl: jwks.url + '/jwks', now: () => clock.now, minRefreshIntervalMs: 60_000, ...over });

  it('accepts a valid token for every allowlisted algorithm', async () => {
    const v = make();
    for (const k of [es, rs, ps, ed]) {
      const c = await v.verify(signJWT(k, claims()));
      assert.equal(c.subject, 'usr_1');
      assert.equal(c.audience, AUD);
      assert.equal(c.clientId, 'customer-web-bff');
      assert.deepEqual([...c.scopes], ['orders:read', 'orders:create']);
      assert.equal(c.orgId, 'org_a');
      assert.equal(c.sessionId, 'ses_1');
      assert.equal(c.tokenKind, 'user_access');
      assert.equal(c.authzVersion, 43);
      assert.equal(c.online, false);
      assert.equal(c.expiry?.getTime(), (NOW + 300) * 1000);
      assert.ok(Object.isFrozen(c));
    }
    assert.equal(v.fetchCount, 1, 'keys are cached');
  });

  it('accepts application/at+jwt and a case-insensitive typ', async () => {
    const v = make();
    await v.verify(signJWT(es, claims(), { typ: 'application/at+jwt' }));
    await v.verify(signJWT(es, claims(), { typ: 'AT+JWT' }));
  });

  it('accepts the audience as a single-element array', async () => {
    await make().verify(signJWT(es, claims({ aud: [AUD] })));
  });

  it('preserves the actor of exchanged tokens', async () => {
    const c = await make().verify(
      signJWT(es, claims({ token_kind: 'exchange_access', act: { sub: 'svc_orders', iss: ISS, act: { sub: 'svc_gw' } } })),
    );
    assert.equal(c.actor?.subject, 'svc_orders');
    assert.equal(c.actor?.act?.subject, 'svc_gw');
  });

  it('rejects a token from another issuer without fetching keys (TEST-003)', async () => {
    const v = make();
    await rejects(v.verify(signJWT(es, claims({ iss: 'https://evil.test/realms/main' }))), 'issuer');
    await rejects(v.verify(signJWT(es, claims({ iss: ISS + '/' }))), 'issuer');
    await rejects(v.verify(signJWT(es, claims({ iss: undefined }))), 'issuer');
    assert.equal(v.fetchCount, 0);
  });

  it('never fetches URLs from jku / x5u / jwk headers', async () => {
    const attacker = await startServer((_q, res) => json(res, 200, { keys: [makeKey('ES256', 'evil').jwk] }));
    try {
      const evil = makeKey('ES256', 'evil');
      const v = make();
      const tok = signJWT(evil, claims(), { jku: attacker.url + '/jwks', x5u: attacker.url + '/cert', jwk: evil.jwk });
      await rejects(v.verify(tok), 'unknown_key');
      assert.equal(attacker.hits, 0);
    } finally {
      await attacker.close();
    }
  });

  it('rejects the wrong audience (TEST-001)', async () => {
    const v = make();
    await rejects(v.verify(signJWT(es, claims({ aud: 'https://api.test/billing' }))), 'audience');
    await rejects(v.verify(signJWT(es, claims({ aud: [AUD, 'https://api.test/billing'] }))), 'audience');
    await rejects(v.verify(signJWT(es, claims({ aud: [] }))), 'audience');
    await rejects(v.verify(signJWT(es, claims({ aud: undefined }))), 'audience');
    await rejects(v.verify(signJWT(es, claims({ aud: AUD + '/' }))), 'audience');
  });

  it('rejects alg "none" without fetching (TEST-004)', async () => {
    const v = make();
    const tok = `${b64(JSON.stringify({ alg: 'none', typ: 'at+jwt', kid: es.kid }))}.${b64(JSON.stringify(claims()))}.`;
    await rejects(v.verify(tok), 'algorithm');
    const tok2 = `${b64(JSON.stringify({ alg: 'None', typ: 'at+jwt', kid: es.kid }))}.${b64(JSON.stringify(claims()))}.`;
    await rejects(v.verify(tok2), 'algorithm');
    assert.equal(v.fetchCount, 0);
  });

  it('rejects HS256 signed with the public key as the HMAC secret (key confusion)', async () => {
    const v = make();
    for (const secret of [JSON.stringify(rs.jwk), rs.publicKey.export({ format: 'pem', type: 'spki' }) as string]) {
      const input = `${b64(JSON.stringify({ alg: 'HS256', typ: 'at+jwt', kid: rs.kid }))}.${b64(JSON.stringify(claims()))}`;
      const tok = `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
      await rejects(v.verify(tok), 'algorithm');
    }
    assert.equal(v.fetchCount, 0);
  });

  it('refuses symmetric, unsigned and unsupported algorithms in configuration', () => {
    assert.throws(() => make({ algorithms: ['HS256'] }), /not allowed/);
    assert.throws(() => make({ algorithms: ['none'] }), /not allowed/);
    assert.throws(() => make({ algorithms: ['RS256', 'hs512'] }), /not allowed/);
    assert.throws(() => make({ algorithms: ['ES512'] }), /not supported/);
  });

  it('rejects an algorithm outside a narrowed allowlist', async () => {
    const v = make({ algorithms: ['ES256'] });
    await v.verify(signJWT(es, claims()));
    await rejects(v.verify(signJWT(rs, claims())), 'algorithm');
  });

  it('rejects a key whose JWK alg differs from the token alg', async () => {
    // rs.jwk declares alg RS256; a PS256 token signed with the same RSA key is refused.
    const tok = signJWT({ ...rs, alg: 'PS256' }, claims(), { alg: 'PS256', kid: rs.kid });
    await rejects(make().verify(tok), 'algorithm');
  });

  it('rejects key-type confusion (ES256 header resolving to an RSA key)', async () => {
    const tok = signJWT(es, claims(), { kid: rs.kid });
    await rejects(make().verify(tok), 'algorithm'); // rs.jwk declares alg RS256
    const loose = makeKey('RS256', 'rs-noalg', { jwkAlg: false });
    published.push(loose.jwk);
    try {
      await rejects(make().verify(signJWT(es, claims(), { kid: loose.kid })), 'signature');
    } finally {
      published.pop();
    }
  });

  it('rejects an ID token (typ JWT) and untyped tokens as access tokens (TEST-002)', async () => {
    const v = make();
    await rejects(v.verify(signJWT(es, claims(), { typ: 'JWT' })), 'token_type');
    await rejects(v.verify(signJWT(es, claims(), { typ: undefined })), 'token_type');
    await rejects(v.verify(signJWT(es, claims(), { typ: 'logout+jwt' })), 'token_type');
    await rejects(v.verify(signJWT(es, claims(), { typ: 7 })), 'token_type');
  });

  it('rejects expired tokens, honouring the clock skew (TEST-006)', async () => {
    const clock = { now: (NOW + 300 + 29) * 1000 };
    const v = make({}, clock);
    await v.verify(signJWT(es, claims())); // within 30s skew
    clock.now = (NOW + 300 + 31) * 1000;
    await rejects(v.verify(signJWT(es, claims())), 'expired');
    await rejects(make().verify(signJWT(es, claims({ exp: undefined }))), 'expired');
    await rejects(make().verify(signJWT(es, claims({ exp: NOW - 100 }))), 'expired');
  });

  it('rejects not-yet-valid and future-issued tokens (TEST-006)', async () => {
    const v = make();
    await rejects(v.verify(signJWT(es, claims({ nbf: NOW + 120 }))), 'not_yet_valid');
    await v.verify(signJWT(es, claims({ nbf: NOW + 20 })));
    await rejects(v.verify(signJWT(es, claims({ iat: NOW + 120 }))), 'future_issued');
  });

  it('rejects non-numeric time claims and malformed claim types', async () => {
    const v = make();
    await rejects(v.verify(signJWT(es, claims({ exp: String(NOW + 300) }))), 'malformed');
    await rejects(v.verify(signJWT(es, claims({ scope: ['orders:read'] }))), 'malformed');
    await rejects(v.verify(signJWT(es, claims({ act: 'admin' }))), 'malformed');
    await rejects(v.verify(signJWT(es, claims({ aud: 42 }))), 'malformed');
  });

  it('rejects duplicate JSON members in payload and header', async () => {
    const v = make();
    const header = JSON.stringify({ alg: 'ES256', typ: 'at+jwt', kid: es.kid });
    const body = JSON.stringify(claims());
    const dupSub = body.slice(0, -1) + ',"sub":"usr_admin"}';
    await rejects(v.verify(signRaw(es, header, dupSub)), 'duplicate_claim');
    const dupAud = body.slice(0, -1) + `,"aud":"${AUD}"}`;
    await rejects(v.verify(signRaw(es, header, dupAud)), 'duplicate_claim');
    const escaped = body.slice(0, -1) + ',"\\u0069ss":"https://evil.test"}';
    await rejects(v.verify(signRaw(es, header, escaped)), 'duplicate_claim');
    const nested = body.slice(0, -1) + ',"act":{"sub":"a","sub":"b"}}';
    await rejects(v.verify(signRaw(es, header, nested)), 'duplicate_claim');
    const dupKid = `{"alg":"ES256","typ":"at+jwt","kid":"${es.kid}","kid":"${rs.kid}"}`;
    await rejects(v.verify(signRaw(es, dupKid, body)), 'duplicate_claim');
    const dupAlg = `{"alg":"none","typ":"at+jwt","kid":"${es.kid}","alg":"ES256"}`;
    await rejects(v.verify(signRaw(es, dupAlg, body)), 'duplicate_claim');
    assert.equal(v.fetchCount, 0);
  });

  it('rejects trailing data and malformed structure', async () => {
    const v = make();
    const header = JSON.stringify({ alg: 'ES256', typ: 'at+jwt', kid: es.kid });
    const good = signJWT(es, claims());
    await rejects(v.verify(good + '.extra'), 'malformed');
    await rejects(v.verify(signRaw(es, header, JSON.stringify(claims()) + ' {}')), 'malformed');
    await rejects(v.verify(signRaw(es, header + 'x', JSON.stringify(claims()))), 'malformed');
    await rejects(v.verify(signRaw(es, header, '[1,2]')), 'malformed');
    await rejects(v.verify(signRaw(es, header, '\uFEFF' + JSON.stringify(claims()))), 'malformed');
    await rejects(v.verify('a.b'), 'malformed');
    await rejects(v.verify('a.b.c'), 'malformed');
    const [h, p, s] = good.split('.') as [string, string, string];
    await rejects(v.verify(`${h}=.${p}.${s}`), 'malformed');
    await rejects(v.verify(`${h}.${p}.${s.replace(/-/g, '+')}+`), 'malformed');
    await rejects(v.verify(signRaw(es, JSON.stringify({ alg: 'ES256', typ: 'at+jwt', kid: es.kid, crit: ['exp'] }), JSON.stringify(claims()))), 'malformed');
    await rejects(v.verify(''), 'missing_token');
    const deep = '{"iss":"' + ISS + '","x":' + '['.repeat(40) + ']'.repeat(40) + '}';
    await rejects(v.verify(signRaw(es, header, deep)), 'malformed');
  });

  it('rejects an oversized token before parsing or fetching', async () => {
    const v = make();
    const tok = signJWT(es, claims({ pad: 'x'.repeat(9000) }));
    assert.ok(tok.length > 8192);
    await rejects(v.verify(tok), 'too_large');
    await rejects(make({ maxTokenBytes: 100 }).verify(signJWT(es, claims())), 'too_large');
    assert.equal(v.fetchCount, 0);
  });

  it('rejects a tampered payload or signature', async () => {
    const v = make();
    const [h, , s] = signJWT(es, claims()).split('.') as [string, string, string];
    const forged = b64(JSON.stringify(claims({ sub: 'usr_admin' })));
    await rejects(v.verify(`${h}.${forged}.${s}`), 'signature');
    const other = signJWT(makeKey('ES256', es.kid), claims());
    await rejects(v.verify(other), 'signature');
  });

  it('rejects impersonation and unknown token kinds offline', async () => {
    const v = make();
    await rejects(
      v.verify(signJWT(es, claims({ token_kind: 'impersonation_access', act: { sub: 'usr_agent' }, impersonation_grant_id: 'imp_1' }))),
      'token_kind',
    );
    await rejects(v.verify(signJWT(es, claims({ token_kind: undefined }))), 'token_kind');
    await rejects(v.verify(signJWT(es, claims({ token_kind: 'refresh' }))), 'token_kind');
    await rejects(v.verify(signJWT(es, claims({ sub: '' }))), 'token_kind');
    await rejects(v.verify(signJWT(es, claims({ client_id: undefined }))), 'token_kind');
    await rejects(v.verify(signJWT(es, claims({ jti: undefined }))), 'token_kind');
    assert.throws(() => make({ acceptedKinds: ['user_access', 'impersonation_access'] }), /SupportGuard/);
    const services = make({ acceptedKinds: ['service_access'] });
    await rejects(services.verify(signJWT(es, claims())), 'token_kind');
  });

  it('bounds JWKS fetches under an unknown-kid flood (TEST-005)', async () => {
    const clock = { now: NOW * 1000 };
    const v = make({}, clock);
    // Concurrent flood: one fetch, all rejected, never fail-open.
    const flood = Array.from({ length: 200 }, () => v.verify(signJWT(es, claims(), { kid: randomBytes(8).toString('hex') })));
    const results = await Promise.allSettled(flood);
    assert.ok(results.every((r) => r.status === 'rejected' && isVerifierError(r.reason, 'unknown_key')));
    assert.equal(v.fetchCount, 1);
    // Sequential flood inside the refresh interval: still no new fetches.
    for (let i = 0; i < 50; i++) await rejects(v.verify(signJWT(es, claims(), { kid: 'rand-' + i })), 'unknown_key');
    assert.equal(v.fetchCount, 1);
    // Known keys keep working during the flood.
    await v.verify(signJWT(es, claims()));
    // After the interval, one more refresh is allowed, then the bound applies again.
    clock.now += 61_000;
    for (let i = 0; i < 50; i++) await rejects(v.verify(signJWT(es, claims({ exp: NOW + 400 }), { kid: 'later-' + i })), 'unknown_key');
    assert.equal(v.fetchCount, 2);
  });

  it('picks up a rotated key after the refresh interval (TEST-036)', async () => {
    const clock = { now: NOW * 1000 };
    const v = make({}, clock);
    await v.verify(signJWT(es, claims()));
    const next = makeKey('ES256', 'es-2');
    published.push(next.jwk);
    try {
      await rejects(v.verify(signJWT(next, claims())), 'unknown_key'); // within the interval
      clock.now += 60_000;
      const c = await v.verify(signJWT(next, claims({ exp: NOW + 400 })));
      assert.equal(c.subject, 'usr_1');
      await v.verify(signJWT(es, claims({ exp: NOW + 400 }))); // planned overlap
      assert.equal(v.fetchCount, 2);
    } finally {
      published.pop();
    }
  });

  it('fails closed when the key set is unavailable', async () => {
    const v = make();
    status = 500;
    try {
      await rejects(v.verify(signJWT(es, claims())), 'unavailable');
      await rejects(v.verify(signJWT(es, claims())), 'unavailable'); // no fetch storm, still closed
      assert.equal(v.fetchCount, 1);
    } finally {
      status = 200;
    }
    const dead = new Verifier({ issuer: ISS, audience: AUD, jwksUrl: 'http://127.0.0.1:1/jwks', now: () => NOW * 1000 });
    await rejects(dead.verify(signJWT(es, claims())), 'unavailable');
  });

  it('keeps known keys when a refresh fails', async () => {
    const clock = { now: NOW * 1000 };
    const v = make({}, clock);
    await v.verify(signJWT(es, claims()));
    status = 503;
    try {
      clock.now += 61_000;
      await rejects(v.verify(signJWT(es, claims({ exp: NOW + 400 }), { kid: 'unknown' })), 'unavailable');
      await v.verify(signJWT(es, claims({ exp: NOW + 400 })));
    } finally {
      status = 200;
    }
  });

  it('skips unusable JWKS entries and ambiguous key IDs', async () => {
    const enc = makeKey('ES256', 'enc-1');
    const priv = makeKey('ES256', 'priv-1');
    const dupA = makeKey('ES256', 'dup');
    const dupB = makeKey('ES256', 'dup');
    const ks = await startServer((_q, res) =>
      json(res, 200, {
        keys: [
          { ...enc.jwk, use: 'enc' },
          { ...(priv.privateKey.export({ format: 'jwk' }) as object), kid: 'priv-1' },
          { kty: 'oct', kid: 'hmac', k: b64('secret') },
          dupA.jwk,
          dupB.jwk,
          { kty: 'RSA', kid: 'weak', n: b64(randomBytes(128)), e: 'AQAB' },
          'garbage',
          es.jwk,
        ],
      }),
    );
    try {
      const v = make({ jwksUrl: ks.url });
      await v.verify(signJWT(es, claims()));
      await rejects(v.verify(signJWT(enc, claims())), 'unknown_key');
      await rejects(v.verify(signJWT(priv, claims())), 'unknown_key');
      await rejects(v.verify(signJWT(dupA, claims())), 'unknown_key');
      const input = `${b64(JSON.stringify({ alg: 'HS256', typ: 'at+jwt', kid: 'hmac' }))}.${b64(JSON.stringify(claims()))}`;
      await rejects(v.verify(`${input}.${createHmac('sha256', 'secret').update(input).digest('base64url')}`), 'algorithm');
    } finally {
      await ks.close();
    }
  });

  it('validates configuration', () => {
    assert.throws(() => new Verifier({ issuer: '', audience: AUD }), /issuer and audience/);
    assert.throws(() => new Verifier({ issuer: ISS, audience: '' }), /issuer and audience/);
    assert.throws(() => make({ clockSkewMs: 61_000 }), /at most 60s/);
    assert.throws(() => make({ minRefreshIntervalMs: 0 }), /at least 1000/);
    assert.throws(() => make({ jwksUrl: 'file:///etc/passwd' }), /http/);
    const d = new Verifier({ issuer: ISS + '/', audience: AUD });
    assert.equal(d.issuer, ISS + '/');
  });

  it('claims helpers enforce scope and organization', async () => {
    const c = await make().verify(signJWT(es, claims()));
    assert.equal(c.hasScope('orders:read'), true);
    assert.equal(c.hasScope('orders:delete'), false);
    c.requireScope('orders:read', 'orders:create');
    assert.throws(() => c.requireScope('orders:read', 'orders:refund'), (e: unknown) => isVerifierError(e, 'scope'));
    c.requireOrganization('org_a');
    assert.throws(() => c.requireOrganization('org_b'), (e: unknown) => isVerifierError(e, 'organization'));
    assert.throws(() => c.requireOrganization(''), (e: unknown) => isVerifierError(e, 'organization'));
    const noOrg = await make().verify(signJWT(es, claims({ org_id: undefined })));
    assert.throws(() => noOrg.requireOrganization(''), (e: unknown) => isVerifierError(e, 'organization'));
    assert.equal(c.isSupport(), false);
  });

  it('never puts token material in error messages', async () => {
    const tok = signJWT(es, claims({ aud: 'https://api.test/other' }));
    try {
      await make().verify(tok);
      assert.fail('expected rejection');
    } catch (e) {
      assert.ok(e instanceof VerifierError);
      assert.ok(!e.message.includes(tok.split('.')[1]!));
      assert.ok(!e.message.includes('usr_1'));
      assert.equal(e.message, 'verifier: wrong audience');
    }
  });
});
