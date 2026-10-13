import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Introspector,
  SupportGuard,
  isProtectedOperation,
  isVerifierError,
  isWriteOperation,
  type SupportEvent,
} from '../src/introspection.js';
import { json, startServer, type TestServer } from './helpers.js';

// The support-operation table is shared with the Go SDK
// (sdk/go/verifier/support_test.go) so both guards classify every operation
// identically.
interface SupportFixture {
  write_operations: string[];
  classification_only: { operation: string; protected: boolean; write: boolean; why: string }[];
  cases: {
    operation: string;
    read: boolean;
    support_mode: string;
    protected: boolean;
    write: boolean;
    expect: 'allow' | 'protected_operation' | 'write_not_allowlisted';
    why: string;
  }[];
}

const here = dirname(fileURLToPath(import.meta.url));
// Compiled tests run from dist/test; the fixtures live at testdata/contracts in this standalone repository.
const fx = JSON.parse(readFileSync(join(here, '..', '..', 'testdata', 'contracts', 'support-operations', 'cases.json'), 'utf8')) as SupportFixture;

const ISS = 'https://id.test/realms/main';
const AUD = 'https://api.test/orders';

describe('shared support-operation fixtures', () => {
  let idp: TestServer;

  before(async () => {
    // The token is echoed as the support mode.
    idp = await startServer((_req, res, body) => {
      const mode = new URLSearchParams(body).get('token') ?? '';
      json(res, 200, {
        active: true, iss: ISS, aud: AUD, sub: 'usr_customer', client_id: 'support-bff', token_kind: 'impersonation_access',
        act: { sub: 'usr_agent' }, impersonation_grant_id: 'imp_1', support_mode: mode, jti: 'tok_support_1', org_id: 'org_a',
      });
    });
  });
  after(() => idp.close());

  it('classifies operations like the Go SDK', () => {
    assert.ok(fx.cases.length > 0);
    for (const c of [...fx.classification_only, ...fx.cases]) {
      assert.equal(isProtectedOperation(c.operation), c.protected, `isProtectedOperation(${JSON.stringify(c.operation)}): ${c.why}`);
      assert.equal(isWriteOperation(c.operation), c.write, `isWriteOperation(${JSON.stringify(c.operation)}): ${c.why}`);
    }
  });

  it('reaches the same SupportGuard decisions as the Go SDK', async () => {
    for (const c of fx.cases) {
      const events: SupportEvent[] = [];
      const guard = new SupportGuard({
        introspector: new Introspector({ endpoint: idp.url + '/oauth/introspect', clientId: 'rs', clientSecret: 's', issuer: ISS, audience: AUD }),
        auditor: (ev) => {
          events.push(ev);
        },
        writeOperations: fx.write_operations,
      });
      const label = `${c.operation} read=${c.read} ${c.support_mode}: ${c.why}`;
      if (c.expect === 'allow') {
        await guard.authorize(c.support_mode, c.operation, { read: c.read });
      } else {
        await assert.rejects(guard.authorize(c.support_mode, c.operation, { read: c.read }), (e: unknown) => isVerifierError(e, 'support_policy'), label);
      }
      assert.equal(events.length, 1, label);
      const ev = events[0]!;
      assert.equal(ev.allowed, c.expect === 'allow', label);
      assert.equal(ev.denyReason, c.expect === 'allow' ? undefined : c.expect, label);
      assert.equal(ev.read, c.read && !c.write, label);
      assert.equal(ev.actor, 'usr_agent', label);
    }
  });

  it('denies an empty operation without auditing', async () => {
    const events: SupportEvent[] = [];
    const guard = new SupportGuard({
      introspector: new Introspector({ endpoint: idp.url + '/oauth/introspect', clientId: 'rs', clientSecret: 's', issuer: ISS, audience: AUD }),
      auditor: (ev) => {
        events.push(ev);
      },
    });
    await assert.rejects(guard.authorize('read_only', '  ', { read: true }), (e: unknown) => isVerifierError(e, 'support_policy'));
    assert.equal(events.length, 0);
  });
});
