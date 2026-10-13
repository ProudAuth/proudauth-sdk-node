/**
 * Verification error categories. They are stable, safe to log and never contain
 * token material, secrets or claim values (SDK-008).
 */

const MESSAGES = {
  missing_token: 'missing bearer token',
  invalid_request: 'bearer token must be sent in the Authorization header, not the query string',
  malformed: 'malformed token',
  too_large: 'token too large',
  duplicate_claim: 'duplicate JSON member',
  token_type: 'wrong token type',
  algorithm: 'algorithm not allowed',
  unknown_key: 'unknown signing key',
  signature: 'invalid signature',
  issuer: 'untrusted issuer',
  audience: 'wrong audience',
  expired: 'token expired',
  not_yet_valid: 'token not yet valid',
  future_issued: 'token issued in the future',
  token_kind: 'token kind not accepted',
  sender_constraint: 'sender constraint not satisfied',
  inactive: 'token is not active',
  unavailable: 'verification dependency unavailable',
  organization: 'organization mismatch',
  scope: 'required scope missing',
  support_policy: 'support access not permitted for this operation',
  contract: 'support contract not satisfied (auditor required)',
  stale_state: 'revocation state is older than the configured bound',
  revoked: 'session or subject was revoked',
} as const;

export type VerifierErrorCode = keyof typeof MESSAGES;

/** All error codes, for exhaustive handling and telemetry dimensions. */
export const VERIFIER_ERROR_CODES = Object.freeze(Object.keys(MESSAGES) as VerifierErrorCode[]);

export class VerifierError extends Error {
  override readonly name = 'VerifierError';
  readonly code: VerifierErrorCode;

  constructor(code: VerifierErrorCode, options?: { cause?: unknown }) {
    super(`verifier: ${MESSAGES[code]}`, options);
    this.code = code;
  }
}

/** Type guard; with `code`, also checks the category. */
export function isVerifierError(err: unknown, code?: VerifierErrorCode): err is VerifierError {
  return err instanceof VerifierError && (code === undefined || err.code === code);
}
