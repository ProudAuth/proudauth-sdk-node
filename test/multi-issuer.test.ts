import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { MultiIssuerVerifier, Verifier, VerifierError } from '../src/verifier.js';
import { json, makeKey, signJWT, startServer, type TestKey, type TestServer } from './helpers.js';

const AUD = 'https://api.test/orders';

describe('MultiIssuerVerifier (INT-009)', () => {
  const issuers: { url: string; key: TestKey; jwks?: TestServer }[] = [
    { url: 'https://id.test/realms/acme', key: makeKey('ES256', 'a1') },
    { url: 'https://id.test/realms/globex', key: makeKey('ES256', 'b1') },
    { url: 'https://rogue.test', key: makeKey('ES256', 'r1') },
  ];
  before(async () => {
    for (const i of issuers) i.jwks = await startServer((_q, res) => json(res, 200, { keys: [i.key.jwk] }));
  });
  after(async () => {
    for (const i of issuers) await i.jwks?.close();
  });
  const token = (i: { url: string; key: TestKey }) => {
    const now = Math.floor(Date.now() / 1000);
    return signJWT(i.key, { iss: i.url, sub: 'usr_same', aud: AUD, client_id: 'web', iat: now, exp: now + 300, jti: 'j', scope: 'orders:read', token_kind: 'user_access' });
  };
  const verifier = (i: { url: string; jwks?: TestServer }) => new Verifier({ issuer: i.url, audience: AUD, jwksUrl: i.jwks!.url });

  it('verifies registered issuers with their tenant and refuses others', async () => {
    const [a, b, rogue] = issuers as [(typeof issuers)[0], (typeof issuers)[0], (typeof issuers)[0]];
    const m = new MultiIssuerVerifier({ [a.url]: { verifier: verifier(a), tenant: 'acme' }, [b.url]: { verifier: verifier(b), tenant: 'globex' } });
    const ta = await m.verifyTenant(token(a));
    assert.equal(ta.tenant, 'acme');
    assert.equal(ta.claims.subject, 'usr_same');
    assert.equal((await m.verifyTenant(token(b))).tenant, 'globex');
    await assert.rejects(m.verifyTenant(token(rogue)), (e: unknown) => e instanceof VerifierError && e.code === 'issuer');
    await assert.rejects(m.authenticate('not-a-jwt'), (e: unknown) => e instanceof VerifierError && e.code === 'malformed');
    assert.throws(() => new MultiIssuerVerifier({ [b.url]: { verifier: verifier(a), tenant: 'x' } }), /exactly that issuer/);
  });
});
