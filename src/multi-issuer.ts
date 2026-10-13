/**
 * Multi-issuer applications (INT-009): tokens from several explicitly
 * registered issuers, for example one realm per customer. The token's `iss`
 * only selects the registration; that issuer's Verifier then checks
 * everything, `iss` included. A validly signed token from any other issuer is
 * refused, even when its subject or email matches a known user. Subjects are
 * unique per issuer only: key application records by (tenant, subject).
 */

import type { Claims } from './claims.js';
import { VerifierError } from './errors.js';
import type { Authenticator } from './middleware.js';
import type { Verifier } from './verifier.js';

export interface IssuerRegistration {
  verifier: Verifier;
  /** The application's own tenant for tokens of this issuer. */
  tenant: string;
}

export interface TenantClaims {
  claims: Claims;
  tenant: string;
}

export class MultiIssuerVerifier implements Authenticator {
  readonly #issuers: Map<string, IssuerRegistration>;

  /** Registrations keyed by exact issuer URL. */
  constructor(registrations: Record<string, IssuerRegistration>) {
    this.#issuers = new Map();
    for (const [iss, reg] of Object.entries(registrations)) {
      if (!iss || !reg?.tenant || !reg.verifier || reg.verifier.issuer !== iss) {
        throw new TypeError('verifier: each registration needs a tenant and a verifier configured for exactly that issuer');
      }
      this.#issuers.set(iss, reg);
    }
    if (this.#issuers.size === 0) throw new TypeError('verifier: register at least one issuer');
  }

  /** Verifies a token and returns its claims with the issuer's tenant. */
  async verifyTenant(raw: string, options: { signal?: AbortSignal } = {}): Promise<TenantClaims> {
    const reg = this.#issuers.get(unverifiedIssuer(raw));
    if (!reg) throw new VerifierError('issuer');
    const claims = await reg.verifier.verify(raw, options);
    return { claims, tenant: reg.tenant };
  }

  /** Authenticator interface; prefer verifyTenant where tenants matter. */
  async authenticate(raw: string, options: { signal?: AbortSignal } = {}): Promise<Claims> {
    return (await this.verifyTenant(raw, options)).claims;
  }
}

/** Reads iss only to choose a verifier; nothing else in the unverified payload is used. */
function unverifiedIssuer(raw: string): string {
  if (typeof raw !== 'string' || raw.length > 16 << 10) throw new VerifierError('malformed');
  const parts = raw.split('.');
  if (parts.length !== 3) throw new VerifierError('malformed');
  let iss: unknown;
  try {
    iss = (JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as { iss?: unknown }).iss;
  } catch (cause) {
    throw new VerifierError('malformed', { cause });
  }
  if (typeof iss !== 'string' || iss === '') throw new VerifierError('malformed');
  return iss;
}
