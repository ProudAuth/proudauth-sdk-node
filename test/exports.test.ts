import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Imports through the package name so the "exports" map itself is exercised.
const load = (sub: string): Promise<Record<string, unknown>> => import(`@proudauth/sdk/${sub}`) as Promise<Record<string, unknown>>;

describe('package exports', () => {
  it('exposes the four public entry points', async () => {
    const verifier = await load('verifier');
    for (const k of ['Verifier', 'Claims', 'VerifierError', 'bearerToken', 'middleware', 'protect', 'requireScopes', 'challenge']) {
      assert.ok(k in verifier, `verifier.${k}`);
    }
    const introspection = await load('introspection');
    for (const k of ['Introspector', 'SupportGuard', 'PROTECTED_OPERATIONS', 'middleware']) assert.ok(k in introspection, `introspection.${k}`);
    const oidc = await load('oidc-client');
    for (const k of ['OIDCClient', 'Session', 'OIDCError', 'pkceChallenge', 'randomValue']) assert.ok(k in oidc, `oidc-client.${k}`);
    const admin = await load('admin');
    for (const k of ['AdminClient', 'ProblemError', 'AdminRequestError', 'newIdempotencyKey']) assert.ok(k in admin, `admin.${k}`);
    const bounded = await load('bounded-state');
    for (const k of ['BoundedState', 'BoundedVerifier']) assert.ok(k in bounded, `bounded-state.${k}`);
    // Both entry points share one error class.
    assert.equal(verifier.VerifierError, introspection.VerifierError);
  });

  it('does not expose internal modules', async () => {
    await assert.rejects(load('dist/src/internal/jws.js'), (e: unknown) => (e as { code?: string }).code === 'ERR_PACKAGE_PATH_NOT_EXPORTED');
    const root = '@proudauth/sdk';
    await assert.rejects(import(root), (e: unknown) => (e as { code?: string }).code === 'ERR_PACKAGE_PATH_NOT_EXPORTED');
  });

  it('has zero runtime dependencies', async () => {
    const { readFile } = await import('node:fs/promises');
    const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')) as Record<string, unknown>;
    assert.equal(pkg.dependencies, undefined);
    assert.equal(pkg.license, 'Apache-2.0');
    assert.equal(pkg.type, 'module');
  });
});
