import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Verifier, isVerifierError } from '../src/verifier.js';
import { json, startServer } from './helpers.js';

// Shared verification fixtures (SDK-009): the same accepted and rejected tokens
// the Go SDK checks, so both SDKs agree on every outcome.
interface FixtureFile {
  issuer: string;
  audience: string;
  now: number;
  jwks: { keys: Record<string, unknown>[] };
  cases: { name: string; token: string; expect: string; why: string }[];
}

const here = dirname(fileURLToPath(import.meta.url));
// Compiled tests run from dist/test; the fixtures live at testdata/contracts in this standalone repository.
const fx = JSON.parse(readFileSync(join(here, '..', '..', 'testdata', 'contracts', 'access-tokens', 'cases.json'), 'utf8')) as FixtureFile;

describe('shared verification fixtures', () => {
  it('reproduces every accepted and rejected outcome', async () => {
    const srv = await startServer((_req, res) => json(res, 200, fx.jwks));
    try {
      const v = new Verifier({ issuer: fx.issuer, audience: fx.audience, jwksUrl: srv.url + '/jwks', now: () => fx.now * 1000, minRefreshIntervalMs: 1000 });
      for (const c of fx.cases) {
        try {
          await v.verify(c.token);
          assert.equal(c.expect, 'accept', `${c.name}: accepted, want ${c.expect}`);
        } catch (e) {
          assert.ok(isVerifierError(e), `${c.name}: unexpected error ${String(e)}`);
          assert.equal(e.code, c.expect, `${c.name}: got ${e.code}, want ${c.expect}`);
        }
      }
    } finally {
      srv.close();
    }
  });
});
