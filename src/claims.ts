import { VerifierError } from './errors.js';

/** RFC 8693 actor claim ("act"): who is acting on behalf of the subject. */
export interface Actor {
  readonly issuer?: string;
  readonly subject: string;
  readonly act?: Actor;
}

export interface ClaimsInit {
  issuer: string;
  subject: string;
  audience: string;
  clientId: string;
  scopes: readonly string[];
  orgId: string;
  sessionId: string;
  tokenKind: string;
  jti: string;
  issuedAt?: Date | undefined;
  expiry?: Date | undefined;
  authTime?: Date | undefined;
  acr: string;
  authzVersion: number;
  actor?: Actor | undefined;
  supportMode?: string;
  impersonationGrantId?: string;
  online: boolean;
}

/**
 * The verified security context of one request. Instances are immutable.
 *
 * Organization and object ownership remain resource-server decisions: compare
 * `orgId` with the organization of the resource taken from your own data
 * (`requireOrganization`), never with an identifier from the request.
 */
export class Claims {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly orgId: string;
  readonly sessionId: string;
  readonly tokenKind: string;
  readonly jti: string;
  readonly issuedAt: Date | undefined;
  readonly expiry: Date | undefined;
  readonly authTime: Date | undefined;
  readonly acr: string;
  /** Authorization revision; only meaningful when compared with trusted current state. */
  readonly authzVersion: number;
  readonly actor: Actor | undefined;
  /** "read_only" or "allowlisted_write" for support tokens (strict-online only). */
  readonly supportMode: string;
  readonly impersonationGrantId: string;
  /** True when live server state was consulted (introspection). */
  readonly online: boolean;

  constructor(init: ClaimsInit) {
    this.issuer = init.issuer;
    this.subject = init.subject;
    this.audience = init.audience;
    this.clientId = init.clientId;
    this.scopes = Object.freeze([...init.scopes]);
    this.orgId = init.orgId;
    this.sessionId = init.sessionId;
    this.tokenKind = init.tokenKind;
    this.jti = init.jti;
    this.issuedAt = init.issuedAt;
    this.expiry = init.expiry;
    this.authTime = init.authTime;
    this.acr = init.acr;
    this.authzVersion = init.authzVersion;
    this.actor = init.actor ? freezeActor(init.actor) : undefined;
    this.supportMode = init.supportMode ?? '';
    this.impersonationGrantId = init.impersonationGrantId ?? '';
    this.online = init.online;
    Object.freeze(this);
  }

  /** Reports whether the token carries scope `scope`. */
  hasScope(scope: string): boolean {
    return this.scopes.includes(scope);
  }

  /** Throws a `scope` VerifierError unless every listed scope is present. */
  requireScope(...scopes: string[]): void {
    for (const s of scopes) {
      if (!this.hasScope(s)) throw new VerifierError('scope');
    }
  }

  /**
   * Matches the verified organization context with the organization that owns the
   * requested resource, taken from the service's own trusted data (§14.4 step 8,
   * TEST-007/008). Throws an `organization` VerifierError on any mismatch,
   * including when either side is empty.
   */
  requireOrganization(resourceOrgId: string): void {
    if (this.orgId === '' || typeof resourceOrgId !== 'string' || resourceOrgId === '' || this.orgId !== resourceOrgId) {
      throw new VerifierError('organization');
    }
  }

  /** Reports whether this is a support (impersonation) request. */
  isSupport(): boolean {
    return this.tokenKind === 'impersonation_access';
  }
}

function freezeActor(a: Actor): Actor {
  const out: { issuer?: string; subject: string; act?: Actor } = { subject: a.subject };
  if (a.issuer !== undefined) out.issuer = a.issuer;
  if (a.act) out.act = freezeActor(a.act);
  return Object.freeze(out);
}
