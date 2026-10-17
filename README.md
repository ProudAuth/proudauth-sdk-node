<p align="center">
  <a href="https://proudauth.com"><img src="https://raw.githubusercontent.com/ProudAuth/.github/main/assets/banner-proudauth-sdk-node.png" alt="ProudAuth SDK for Node.js" width="100%"></a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@proudauth/sdk"><img alt="npm latest version" src="https://img.shields.io/npm/v/%40proudauth%2Fsdk/latest?label=npm&logo=npm&logoColor=3ee6b0&color=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://github.com/ProudAuth/proudauth-sdk-node/blob/main/package.json"><img alt="Repository package version" src="https://img.shields.io/github/package-json/v/ProudAuth/proudauth-sdk-node/main?label=source&color=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="#installation"><img alt="Supported Node.js versions" src="https://img.shields.io/node/v/%40proudauth%2Fsdk?label=Node.js&logo=nodedotjs&logoColor=3ee6b0&color=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://github.com/ProudAuth/proudauth-sdk-node/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ProudAuth/proudauth-sdk-node/ci.yml?branch=main&label=ci&style=for-the-badge&labelColor=06120e"></a>
  <a href="LICENSE"><img alt="Package license" src="https://img.shields.io/npm/l/%40proudauth%2Fsdk?color=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://proudauth.com/docs/sdks/node/"><img alt="Documentation" src="https://img.shields.io/badge/docs-proudauth.com-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@proudauth/sdk"><strong>npm package</strong></a> ·
  <a href="https://proudauth.com/docs/sdks/node/">Documentation</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security</a>
</p>

# ProudAuth SDK for Node.js

The official Node.js and TypeScript SDK for [ProudAuth](https://proudauth.com).
Verify access tokens, enforce strict-online access, build backend login flows,
and work with the administration API through typed clients.

- **Zero runtime dependencies**, using Node.js built-ins and the global `fetch`.
- **TypeScript declarations included**, with ESM entry points for each module.
- **RS256, PS256, ES256 and EdDSA (Ed25519)** verification; `none` and HMAC are rejected.
- **Apache-2.0 licensed**.

## Installation

Requires **Node.js 20.10 or later** and an ESM application (`"type": "module"`).

```sh
npm install @proudauth/sdk
```

[View on npm](https://www.npmjs.com/package/@proudauth/sdk) ·
[Published versions](https://www.npmjs.com/package/@proudauth/sdk?activeTab=versions)

The command installs the release tagged `latest` on npm. Import the module you
need, for example:

```js
import { Verifier } from '@proudauth/sdk/verifier';
import { AdminClient } from '@proudauth/sdk/admin';
```

<details>
<summary>Build and install from source</summary>

```sh
git clone https://github.com/proudauth/proudauth-sdk-node.git
cd proudauth-sdk-node
npm ci
npm pack
```

In your application, run `npm install` with the path to the `.tgz` filename
printed by `npm pack`.

The tarball includes the built ESM entry points, TypeScript declarations and
license notices; it excludes tests and synthetic fixtures. No runtime dependencies
are installed by this package.

</details>

The SDK is in its **0.x release series**; APIs may change between minor versions.
See the [changelog](CHANGELOG.md) and
[compatibility and security-update policy](https://proudauth.com/docs/integrations/sdk-compatibility/)
before upgrading.

## SDK modules

The SDK implements spec §28 (SDK-001 to SDK-009), preserving the security
behavior of the Go SDK:

| Entry point                      | Purpose                                                                                       | Go equivalent                     |
| -------------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------- |
| `@proudauth/sdk/verifier`        | Offline JWT access-token verification, bearer extraction, Express/Connect, `node:http` and Fastify adapters, `MultiIssuerVerifier` | `sdk/go/verifier` (verifier.go, multi.go, metadata.go) |
| `@proudauth/sdk/introspection`   | Strict-online introspection and the support-access contract (`SupportGuard`)                  | `sdk/go/verifier` (introspect.go) |
| `@proudauth/sdk/bounded-state`   | Local verification plus revocations replayed from the session-event stream, failing closed when stale | `sdk/go/verifier` (boundedstate.go) |
| `@proudauth/sdk/oidc-client`     | Backend-for-frontend login: code + PKCE, ID-token validation, single-flight refresh, logout   | `sdk/go/oidcclient`               |
| `@proudauth/sdk/admin`           | Typed admin API client: RFC 9457 problems, cursor pagination, idempotency, If-Match, deadlines, one-time secrets wrapped in `Secret`, deprecation reporting | `sdk/go/admin`                    |

## Which validation profile should I use?

Every API must decide, per operation, how fresh its view of revocation has to be (§13.2, §28.2). Write the decision down for each route.

| Profile           | Use it for                                                                                                                                                    | Revocation exposure                                                                                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Offline JWT** (`Verifier`) | Ordinary, low-risk reads and writes on short-lived JWT access tokens. No per-request network call.                                                | **Bounded by token lifetime.** A token issued before logout, session revocation, suspension or membership removal keeps working until its `exp` plus the clock skew. With the default 5-minute access tokens and 30 s skew, that is up to about 5.5 minutes (SES-023, TEST-034). |
| **Strict-online** (`Introspector`) | Identity administration, credential and security changes, payments and other high-risk operations, and any route that must stop at the moment of revocation. | None for new requests. Every request asks the identity provider. If the provider can't be reached, the request is **denied** (503). The SDK never falls back to offline checks and never caches a positive result (TEST-035).                                                       |
| **Support** (`SupportGuard`) | Any route that serves administrator support (impersonation) sessions. These sessions carry opaque `pa_it_…` tokens.                                                          | Strict-online, plus the support contract: the actor is preserved, the default is read-only, writes need an explicit allowlist, protected operations are always denied, and an audit record is written **before** access (IMP-006 to IMP-020).                                     |
| **Bounded state** (`BoundedState` + `BoundedVerifier`, `./bounded-state`) | APIs that verify JWTs locally but must stop accepting them within a known time after session, account, organization or membership revocation. Needs a service token with `realm.session_events.read`. | At most `maxStalenessMs`: revocations are replayed from the session-event stream, and when the replayed state is older than that, every check fails closed (503). |

Rules that hold in every profile:

- **Support tokens are always strict-online.** The offline `Verifier` rejects `impersonation_access`, and it refuses to be configured to accept it.
- **One audience per API.** Configure the exact issuer and this API's own audience, and never a wildcard.
- **Organization and ownership come from your data.** Compare `claims.orgId` with the organization of the resource as stored in your database (`claims.requireOrganization(row.orgId)`). Never compare it with an ID taken from the request.
- **`authz_version` is only a hint.** It means something only when you compare it with trusted current state.
- **Bounded state follows the stream.** Call `start()` once, then keep `run(signal)` running (it long-polls with `sync(20, signal)`). `start()` keeps the revocations already replayed and moves the position to now. A `410 cursor_expired` rewinds to the oldest retained event and throws `CursorExpiredError` from `sync()`; `run()` replays at once and keeps following. The state is fresh only after a read reaches the end of the stream, replays never weaken a revocation, and `user.recovery_restricted` is not a revocation. Aborting `signal` stops an in-flight long poll and a backoff wait at once.

## Express API with offline verification

```js
import express from 'express';
import { Verifier, middleware, requireScopes, getClaims } from '@proudauth/sdk/verifier';

const verifier = new Verifier({
  issuer: 'https://id.example.com/realms/main', // exact; other issuers are rejected before any fetch
  audience: 'https://api.example.com/orders',   // this API only
  // jwksUrl defaults to `${issuer}/jwks`; it is never taken from a token (no jku/x5u)
});

const app = express();
app.use('/orders', middleware(verifier, {
  realm: 'orders',
  onError: (err) => metrics.increment('auth_failure', { code: err.code }), // categories only, no tokens
}));

app.get('/orders/:id', requireScopes('orders:read'), async (req, res) => {
  const claims = getClaims(req);                       // also available as req.auth
  const order = await db.orders.find(req.params.id);
  if (!order) return res.sendStatus(404);
  claims.requireOrganization(order.orgId);             // throws VerifierError('organization') -> 403
  res.json(order);
});

// Turn helper errors thrown inside handlers into 401/403/503 responses.
import { challenge, isVerifierError } from '@proudauth/sdk/verifier';
app.use((err, req, res, next) => {
  if (!isVerifierError(err)) return next(err);
  const ch = challenge(err);
  res.status(ch.status).set(ch.headers).end();
});
```

With plain `node:http`:

```js
import { createServer } from 'node:http';
import { Verifier, protect } from '@proudauth/sdk/verifier';

const verifier = new Verifier({ issuer, audience });
createServer(protect(verifier, (req, res, claims) => {
  claims.requireScope('orders:read');
  res.end(JSON.stringify({ subject: claims.subject }));
})).listen(8080);
```

With Fastify, use the hook as `onRequest` or `preHandler`; on failure it sends the response and returns the reply, so the route never runs:

```js
import Fastify from 'fastify';
import { Verifier, fastifyHook, getClaims } from '@proudauth/sdk/verifier';

const app = Fastify();
app.addHook('onRequest', fastifyHook(new Verifier({ issuer, audience })));
app.get('/orders', async (request) => listOrders(getClaims(request)));   // also request.auth
```

An application that accepts tokens from several realms registers each issuer with its own tenant (INT-009). A token from any other issuer is rejected with `VerifierError('issuer')`, even when it is validly signed. Key your records by tenant and subject, never by email:

```js
import { Verifier, MultiIssuerVerifier } from '@proudauth/sdk/verifier';

const multi = new MultiIssuerVerifier({
  'https://id.example.com/realms/acme':   { verifier: new Verifier({ issuer: 'https://id.example.com/realms/acme', audience }), tenant: 'acme' },
  'https://id.example.com/realms/globex': { verifier: new Verifier({ issuer: 'https://id.example.com/realms/globex', audience }), tenant: 'globex' },
});
const { claims, tenant } = await multi.verifyTenant(rawToken);
```

`MultiIssuerVerifier` also works as the authenticator of the adapters above (`authenticate()`), but then the tenant is not passed on. More integration patterns (GraphQL, WebSockets, streams, background jobs) are in [docs/integrations/patterns.md](https://proudauth.com/docs/integrations/patterns/).

The adapters answer according to RFC 6750:

| Outcome                                              | Status | `WWW-Authenticate`                                  |
| ---------------------------------------------------- | ------ | --------------------------------------------------- |
| No bearer token                                      | 401    | `Bearer` (no error code)                            |
| `access_token` in the query string (TOK-023)         | 400    | `Bearer error="invalid_request"`                    |
| Invalid, expired or wrong-audience token, ID token, unknown key, and so on | 401    | `Bearer error="invalid_token"`                      |
| Missing scope (`requireScopes`)                      | 403    | `Bearer error="insufficient_scope", scope="…"`      |
| Organization mismatch                                | 403    | `Bearer error="insufficient_scope"`                 |
| Support-policy denial                                | 403    | none                                                |
| JWKS, introspection or audit store unavailable       | 503    | none (fails closed)                                 |

You can also verify a token directly: `await verifier.verify(rawToken)`. It returns immutable `Claims` (`subject`, `audience`, `clientId`, `scopes`, `orgId`, `sessionId`, `tokenKind`, `actor`, `expiry`, …) or rejects with a `VerifierError` whose `code` is one of the stable categories in `VERIFIER_ERROR_CODES`.

## Strict-online, support-aware API

```js
import express from 'express';
import { Introspector, SupportGuard, getClaims } from '@proudauth/sdk/introspection';

const introspector = new Introspector({
  endpoint: 'https://id.example.com/realms/main/oauth/introspect',
  clientId: process.env.ORDERS_RS_CLIENT_ID,         // a confidential client registered as this resource server
  clientSecret: process.env.ORDERS_RS_CLIENT_SECRET, // sent with client_secret_basic, never logged
  issuer: 'https://id.example.com/realms/main',
  audience: 'https://api.example.com/orders',
  timeoutMs: 3000,                                   // a timeout denies the request, it doesn't downgrade
});

const guard = new SupportGuard({
  introspector,
  // Called BEFORE access for every support request, allowed or denied. If it throws, access is denied.
  auditor: async (ev) => {
    await db.supportAudit.insert({
      grant_id: ev.grantId, actor: ev.actor, subject: ev.subject, org_id: ev.orgId,
      operation: ev.operation, allowed: ev.allowed, deny_reason: ev.denyReason, at: ev.at,
    });
  },
  writeOperations: ['orders.annotate'], // the only writes allowed, and only for allowlisted_write grants
});

const app = express();
// One introspection per request. Ordinary tokens follow the introspector's accepted kinds;
// support tokens follow the support contract. Routing uses the authoritative token_kind, never a token prefix.
app.get('/orders', guard.middleware({ operation: 'orders.list', read: true }), listOrders);
app.post('/orders/:id/notes', guard.middleware({ operation: 'orders.annotate', read: false }), annotate);
app.post('/orders/:id/refund', guard.middleware({ operation: 'orders.refund', read: false }), refund); // support always denied

function listOrders(req, res) {
  const claims = getClaims(req);
  if (claims.isSupport()) res.set('x-support-session', claims.impersonationGrantId); // IMP-021 indicator
  // ...load data, then claims.requireOrganization(row.orgId)
}
```

- For routes that never serve support sessions, `middleware(introspector)` from the same entry point is enough. It rejects support tokens with 401.
- `guard.authorize(raw, operation, { read })` accepts support tokens only. `guard.authorizeAny(...)` accepts both kinds and is the function the middleware uses.
- `read` must be `true` for an operation to count as a read. If it's omitted, the operation is treated as a write. An operation whose name contains a write verb as a segment (`WRITE_SEGMENTS`: `create`, `update`, `delete`, `cancel`, `issue` and so on) is always a write, even with `read: true`. Write allowlist entries match the whole operation name, case-insensitively.
- Protected operations (`PROTECTED_OPERATIONS`: password, MFA, identifier and credential changes, API-key and personal-token creation, payments, refunds, ownership transfer, secrets, deletes, purges) are always denied to support sessions. Operation names are split into segments on `.`, `:` and `/`, case-insensitively, and an entry matches when its segments appear anywhere in the name as a run, with or without a trailing `s`. For example, `orders.delete`, `users.password.change`, `payments.create`, `refunds.issue`, `secrets.read`, `read.payments` and `orders.purge` are protected; `secretary.list` is not. You can add more with `protectedOperations`. You can't remove the defaults from a guard. A list passed as the second argument of `isProtectedOperation(op, list)` replaces the defaults instead of adding to them, so pass `[...PROTECTED_OPERATIONS, ...yours]`. The Go SDK and the server's decision API apply the same rule; the shared cases are in `testdata/contracts/support-operations/cases.json`. `isWriteOperation(op)` and `isProtectedOperation(op)` expose the classification.
- When your service also calls the decision API (`POST /authorization/check`) with a support token as `subject_token`, the server allows an `allowlisted_write` grant only the writes listed in the resource's `impersonation_policy.write_actions` (`SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED` otherwise). Keep that list equal to `writeOperations`.

## Backend-for-frontend (BFF)

```js
import express from 'express';
import { OIDCClient, isOIDCError } from '@proudauth/sdk/oidc-client';

const oidc = new OIDCClient({
  issuer: 'https://id.example.com/realms/main',
  clientId: 'customer-web-bff',
  clientSecret: process.env.BFF_CLIENT_SECRET,
  redirectUri: 'https://app.example.com/callback',
  scopes: ['openid', 'orders:read'],
  resource: 'https://api.example.com/orders',
});

const pendingLogins = new Map(); // server-side login state: loginId -> AuthRequest
const sessions = new Map();      // server-side sessions: sessionId -> Session (one per browser session)

app.get('/login', async (req, res) => {
  const ar = await oidc.authorizationUrl();          // state, nonce, PKCE S256, resource
  const loginId = crypto.randomUUID();
  pendingLogins.set(loginId, ar);
  res.cookie('login', loginId, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600_000 });
  res.redirect(ar.url);
});

app.get('/callback', async (req, res) => {
  const ar = pendingLogins.get(req.cookies.login);
  pendingLogins.delete(req.cookies.login);           // single use
  if (!ar) return res.sendStatus(400);
  // Validates state, iss (RFC 9207), redeems the code with the PKCE verifier,
  // and validates the ID token (signature, iss, aud, azp, exp, nonce, at_hash).
  const { tokens, idClaims } = await oidc.exchangeCode(ar, req.originalUrl);
  const sid = crypto.randomUUID();
  sessions.set(sid, oidc.session(tokens, { idClaims, onRefresh: (t) => persist(sid, t) }));
  res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'lax' });
  res.redirect('/');
});

app.get('/api/orders', async (req, res) => {
  const session = sessions.get(req.cookies.sid);
  if (!session) return res.sendStatus(401);
  try {
    let at = await session.accessToken();           // single-flight refresh near expiry
    let r = await fetch('https://api.example.com/orders', { headers: { authorization: `Bearer ${at}` } });
    if (r.status === 401) {                          // refresh once; concurrent callers share it
      at = await session.accessToken({ rejectedToken: at });
      r = await fetch('https://api.example.com/orders', { headers: { authorization: `Bearer ${at}` } });
    }
    res.status(r.status).json(await r.json());
  } catch (err) {
    if (isOIDCError(err, 'reauthenticate')) { sessions.delete(req.cookies.sid); return res.sendStatus(401); }
    throw err;
  }
});

app.post('/logout', async (req, res) => {
  const session = sessions.get(req.cookies.sid);
  sessions.delete(req.cookies.sid);
  res.clearCookie('sid');
  if (!session) return res.redirect('/');
  // Clears the session, revokes the refresh token, and returns the RP-initiated logout URL.
  res.redirect(await oidc.logout(session, { postLogoutRedirectUri: 'https://app.example.com/' }));
});
```

**Refresh tokens rotate, and reusing one revokes the whole token family (SES-007/008).**

- `Session.accessToken()` is single-flight. Concurrent callers share one refresh request, so one process never sends the same refresh token twice.
- If a refresh fails, the session is cleared and the error is `reauthenticate`. A lost refresh response can't be retried safely.
- Keep exactly one `Session` object per browser session per process. Persist rotated tokens in `onRefresh`.
- If you run several BFF instances, use sticky sessions or a distributed lock around refresh.
- Never send refresh tokens or ID tokens to business APIs.

## Admin client

```js
import { AdminClient, ProblemError } from '@proudauth/sdk/admin';

const admin = new AdminClient({
  baseUrl: 'https://id.example.com',
  realm: 'main',
  token: async (signal) => getAdminAccessToken(signal), // or a string
  timeoutMs: 30_000,
});

for await (const user of admin.users('ann')) console.log(user.id);    // follows next_cursor

try {
  await admin.createUser({ email: 'a@example.com' }, { idempotencyKey: savedKey }); // reuse the key when retrying
} catch (err) {
  if (err instanceof ProblemError) console.error(err.status, err.code, err.errors); // RFC 9457
}

const { data, etag } = await admin.getUser('usr_1');
await admin.updateUser('usr_1', { display_name: 'Ann' }, { ifMatch: etag }); // 412 when stale
await admin.request('GET', '/sessions', undefined, { signal: AbortSignal.timeout(2000) });
```

Transport failures reject with `AdminRequestError` (`timeout`, `aborted`, `network`, `invalid_response`, `token_source`). The SDK never logs anything, and its error messages never contain request bodies, tokens or secrets (SDK-008).

One-time secrets in response data (`client_secret`, `client_secrets`, `api_key`, `signing_secret`, `setup_token`, `recovery_codes`, `invitation_secret`, `access_token`, `refresh_token`, `id_token`, `handoff_code`, `download_token`, `token`, `secret`, `webhook_secrets`) are `Secret` instances: `toString()`, `toJSON()` and `util.inspect` print `[REDACTED]`, and `reveal()` returns the value for the one place that must store it. This changed in 0.2.0: code that used these members as strings must call `reveal()`.

```js
import { AdminClient, Secret } from '@proudauth/sdk/admin';

const admin = new AdminClient({ baseUrl, realm: 'main', token,
  userAgent: 'billing-provisioner/3.1',                       // sent before "proudauth-sdk-node/0.2.0"
  onDeprecated: ({ method, path, deprecation, sunset }) =>    // Deprecation and Sunset headers (API-013); path without query
    log.warn('deprecated ProudAuth API', { method, path, deprecation, sunset }) });

const { data } = await admin.request('POST', '/clients', { client_id: 'svc', name: 'Service', client_type: 'confidential',
  grant_types: ['authorization_code'], redirect_uris: ['https://svc.example.com/callback'] });
if (data.client_secret instanceof Secret) await vault.store('svc', data.client_secret.reveal());
console.log(data);                                            // client_secret: Secret([REDACTED])
```

Every request carries `proudauth-sdk: node/0.2.0`.

## Security properties (offline verifier)

The `Verifier` implements the §14.4 algorithm:

1. **Issuer first.** The payload's `iss` must equal the configured issuer before any key lookup. Tokens from other issuers never trigger a network fetch (TEST-003).
2. **Strict parsing.**
   - Tokens over 8192 bytes are rejected.
   - The token must have exactly three canonical base64url segments, with no padding and nothing trailing.
   - Duplicate JSON member names are rejected in the header and the payload, including escaped duplicates such as `"iss"`.
   - Nesting deeper than 32 levels, lone surrogates and a BOM are rejected.
   - A `crit` header is rejected.
3. **Typing.** `typ` must be `at+jwt` or `application/at+jwt` (case-insensitive), so ID tokens are refused (TEST-002).
4. **Algorithm allowlist.** Only RS256, PS256, ES256 and EdDSA are accepted.
   - The SDK refuses to configure `none` or `HS*`.
   - The key type must match the algorithm, and a JWK `alg`, when present, must match the header.
   - RSA keys must be at least 2048 bits.
5. **Keys only from the configured JWKS.**
   - `jku`, `x5u` and an embedded `jwk` are ignored.
   - JWKS entries that are private, symmetric, not for signing, or ambiguous (duplicate `kid`) are skipped.
   - An unknown `kid` triggers at most one coalesced refresh per `minRefreshIntervalMs` (default 30 s). Floods of random key IDs cause a bounded number of fetches (`verifier.fetchCount`, TEST-005).
   - If a refresh fails, the known keys are kept.
6. **Claims.**
   - The token must have exactly one audience, equal to the configured one (TEST-001).
   - `exp` is required. `nbf` and `iat` are checked when present. Clock skew defaults to 30 s and can't exceed 60 s (TEST-006).
   - `sub`, `client_id` and `jti` are required.
   - `token_kind` must be in the allowlist. The default is `user_access`, `service_access` and `exchange_access`.
7. **Fail closed.** Every failure rejects, and a key-set outage becomes `unavailable` (503).

## Known limitations

- **Emergency signing-key rotation needs a restart.** The verifier loads the
  issuer's JWKS once and refreshes it only when a token names an unknown
  `kid`; it has no key expiry, no `refresh()` or `rejectKey()` method, and
  `BoundedState` does not act on the server's `signing_key.rotated` event.
  After an emergency rotation (`previous_key_compromised`), a key the server
  has retired stays trusted by a running verifier until the process restarts.
  Restart resource servers after an emergency rotation. SDK 0.3.0 adds key
  expiry that honours the server's `Cache-Control`, explicit refresh and
  rejection, and `signing_key.rotated` handling.

## Differences from the Go SDK

Both SDKs require issuer/audience configuration, keep support tokens out of
ordinary authentication, share the protected-operation fixtures, pin OIDC
endpoints to the issuer's origin, send `client_id` for public clients, check
ID-token subjects and report unsuccessful revocation responses. Earlier
descriptions of Go bypasses in these areas are obsolete.

Node.js validates introspector configuration at construction; Go validates
the exported settings when authenticating. Node support audit events also
include `clientId` and `tokenId`. Node uses its own bounded, coalesced key
cache. Both SDKs refuse HTTP redirects for SDK requests. The Go SDK
additionally supplies the request-level `SenderVerifier` described below;
this Node SDK rejects bound tokens through its token-only API.

## Sender-constrained tokens

Token-only verification and introspection reject any `cnf` claim with
`sender_constraint`, including malformed or unsupported bindings. This SDK
does not yet provide request-level DPoP or TLS certificate verification. Use
the Go `SenderVerifier` or a separately reviewed request verifier for bound
tokens; see the [resource-server profile](https://proudauth.com/docs/integrations/resource-servers/#sender-constrained-tokens).

## Development

```sh
npm install   # dev dependencies only: typescript, @types/node
npm test      # clean, compile with tsc, run node:test suites
```

The tests (`test/*.test.ts`) run the spec's negative scenarios against real keys generated with `node:crypto` and local `node:http` servers. They cover:

- wrong issuer without a fetch, wrong audience, `none`, HS256 key confusion, ID token used as an access token
- expired and not-yet-valid tokens, duplicate claims, the unknown-`kid` flood, oversized tokens, impersonation tokens used offline
- introspection fail-closed behavior and the support contract, including audit-before-access
- OIDC state, `iss`, nonce and `at_hash` checks, and single-flight refresh against an IdP that revokes the token family on reuse
- the shared verification fixtures (SDK-009): `test/fixtures.test.ts` runs every case of [`testdata/contracts/access-tokens/cases.json`](testdata/contracts/README.md) (22 accepted and rejected access tokens signed with test-only keys) through the offline verifier and expects the same outcome as the Go SDK
