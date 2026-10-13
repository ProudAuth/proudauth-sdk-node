/**
 * Thin HTTP adapters (SDK-011). Every security decision stays in the common
 * Verifier / Introspector / SupportGuard code; these helpers only extract the
 * bearer token, call the authenticator and translate errors into RFC 6750
 * responses. They deny by default: the next handler only runs with verified claims.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Claims } from './claims.js';
import { isVerifierError, VerifierError } from './errors.js';

/** Satisfied by Verifier (offline) and Introspector (strict-online). */
export interface Authenticator {
  authenticate(raw: string, options?: { signal?: AbortSignal }): Promise<Claims>;
}

/** The parts of a Node/Express/Connect request the adapters read. */
export interface RequestLike {
  url?: string | undefined;
  /** Express keeps the unmodified URL here when routers rewrite `url`. */
  originalUrl?: string | undefined;
  headers: Record<string, string | string[] | undefined>;
}

/** The parts of a Node/Express/Connect response the adapters write. */
export interface ResponseLike {
  statusCode: number;
  readonly headersSent: boolean;
  setHeader(name: string, value: string): unknown;
  end(chunk?: string): unknown;
}

export type NextFunction = (err?: unknown) => void;

// RFC 6750 §2.1 b64token.
const B64TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;

/**
 * Extracts a bearer token from the Authorization header only. Tokens in the query
 * string are refused (TOK-023) even when a header is also present.
 */
export function bearerToken(req: RequestLike): string {
  const url = req.originalUrl ?? req.url ?? '';
  const q = url.indexOf('?');
  if (q >= 0) {
    const params = new URLSearchParams(url.slice(q + 1).split('#', 1)[0]);
    if (params.has('access_token')) throw new VerifierError('invalid_request');
  }
  let h = req.headers['authorization'];
  if (Array.isArray(h)) {
    if (h.length !== 1) throw new VerifierError('invalid_request');
    h = h[0];
  }
  if (typeof h !== 'string' || h.length <= 7 || h.slice(0, 7).toLowerCase() !== 'bearer ') {
    throw new VerifierError('missing_token');
  }
  const token = h.slice(7).trim();
  if (token === '') throw new VerifierError('missing_token');
  if (!B64TOKEN.test(token)) throw new VerifierError('malformed');
  return token;
}

/** Extracts the bearer token and authenticates it. */
export async function authenticateRequest(
  authenticator: Authenticator,
  req: RequestLike,
  options: { signal?: AbortSignal } = {},
): Promise<Claims> {
  const raw = bearerToken(req);
  return authenticator.authenticate(raw, options);
}

export interface ChallengeOptions {
  /** Optional realm for the WWW-Authenticate challenge. */
  realm?: string;
  /** Scopes to advertise with insufficient_scope. */
  scopes?: readonly string[];
}

export interface AuthChallenge {
  status: number;
  headers: Record<string, string>;
  /** RFC 6750 error code, when one applies. */
  error?: 'invalid_request' | 'invalid_token' | 'insufficient_scope';
}

function quote(v: string): string {
  return '"' + v.replace(/[\\"]/g, (c) => '\\' + c).replace(/[\r\n]/g, ' ') + '"';
}

/**
 * Maps any error to an HTTP status and RFC 6750 challenge:
 * missing token -> 401 without error code; token in query -> 400 invalid_request;
 * scope or organization -> 403 insufficient_scope; support policy -> 403;
 * dependency unavailable -> 503 (fail closed, never a downgrade); any other
 * verification failure -> 401 invalid_token; unexpected errors -> 500.
 */
export function challenge(err: unknown, options: ChallengeOptions = {}): AuthChallenge {
  const params: string[] = [];
  if (options.realm) params.push(`realm=${quote(options.realm)}`);
  const bearer = (extra: string[] = []): string => {
    const all = [...params, ...extra];
    return all.length ? `Bearer ${all.join(', ')}` : 'Bearer';
  };
  if (!isVerifierError(err)) return { status: 500, headers: {} };
  switch (err.code) {
    case 'missing_token':
      return { status: 401, headers: { 'www-authenticate': bearer() } };
    case 'invalid_request':
      return {
        status: 400,
        headers: { 'www-authenticate': bearer(['error="invalid_request"']) },
        error: 'invalid_request',
      };
    case 'scope': {
      const extra = ['error="insufficient_scope"'];
      if (options.scopes && options.scopes.length > 0) extra.push(`scope=${quote(options.scopes.join(' '))}`);
      return { status: 403, headers: { 'www-authenticate': bearer(extra) }, error: 'insufficient_scope' };
    }
    case 'organization':
      // The token lacks the organization the resource needs (same as the Go SDK).
      return { status: 403, headers: { 'www-authenticate': bearer(['error="insufficient_scope"']) }, error: 'insufficient_scope' };
    case 'support_policy':
      return { status: 403, headers: {} };
    case 'unavailable':
    case 'stale_state':
      return { status: 503, headers: {} };
    case 'contract':
      return { status: 500, headers: {} };
    default:
      return {
        status: 401,
        headers: { 'www-authenticate': bearer(['error="invalid_token"']) },
        error: 'invalid_token',
      };
  }
}

const STATUS_TEXT: Record<number, string> = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  500: 'Internal Server Error',
  503: 'Service Unavailable',
};

/** Writes a challenge response (plain text body, no token material, no-store). */
export function sendChallenge(res: ResponseLike, ch: AuthChallenge): void {
  if (res.headersSent) return;
  res.statusCode = ch.status;
  for (const [k, v] of Object.entries(ch.headers)) res.setHeader(k, v);
  res.setHeader('cache-control', 'no-store');
  res.setHeader('content-type', 'text/plain; charset=utf-8');
  res.end(STATUS_TEXT[ch.status] ?? 'Error');
}

const CLAIMS = new WeakMap<object, Claims>();

/** Returns the claims attached to a request by one of the adapters. */
export function getClaims(req: object): Claims | undefined {
  return CLAIMS.get(req);
}

export interface MiddlewareOptions extends ChallengeOptions {
  /**
   * Also expose the claims as `req[requestProperty]` (default "auth"). Set to
   * false to only use `getClaims(req)`.
   */
  requestProperty?: string | false;
  /**
   * Called with the error category for telemetry before the challenge is sent.
   * The error never contains token material.
   */
  onError?: (err: unknown, req: RequestLike) => void;
  /** `protect` only: called when the wrapped handler throws (the response becomes 500). */
  onHandlerError?: (err: unknown, req: RequestLike) => void;
}

export function attachClaims(req: object, claims: Claims, options: MiddlewareOptions): void {
  CLAIMS.set(req, claims);
  const prop = options.requestProperty ?? 'auth';
  if (prop !== false) (req as Record<string, unknown>)[prop] = claims;
}

export function reportError(err: unknown, req: RequestLike, options: MiddlewareOptions): void {
  try {
    options.onError?.(err, req);
  } catch {
    // Telemetry must not change the authorization outcome.
  }
}

/**
 * Express/Connect middleware: authenticates every request and stores the claims
 * (`getClaims(req)` / `req.auth`). Failures never reach `next`.
 */
export function middleware(authenticator: Authenticator, options: MiddlewareOptions = {}) {
  return function proudauthAuthenticate(req: RequestLike, res: ResponseLike, next: NextFunction): void {
    const run = async (): Promise<void> => {
      let claims: Claims;
      try {
        claims = await authenticateRequest(authenticator, req);
      } catch (err) {
        reportError(err, req, options);
        sendChallenge(res, challenge(err, options));
        return;
      }
      attachClaims(req, claims, options);
      next();
    };
    run().catch(next);
  };
}

/**
 * Express/Connect middleware that requires scopes on an already-authenticated
 * request (403 insufficient_scope). Without claims it fails closed with 401.
 */
export function requireScopes(...scopes: string[]) {
  return function proudauthRequireScopes(req: RequestLike, res: ResponseLike, next: NextFunction): void {
    const claims = getClaims(req);
    if (!claims) {
      sendChallenge(res, challenge(new VerifierError('missing_token')));
      return;
    }
    try {
      claims.requireScope(...scopes);
    } catch (err) {
      sendChallenge(res, challenge(err, { scopes }));
      return;
    }
    next();
  };
}

/**
 * Wraps a plain node:http handler. The handler only runs with verified claims;
 * otherwise the RFC 6750 response is written and the handler is skipped.
 */
export function protect<Req extends IncomingMessage = IncomingMessage, Res extends ServerResponse = ServerResponse>(
  authenticator: Authenticator,
  handler: (req: Req, res: Res, claims: Claims) => unknown,
  options: MiddlewareOptions = {},
): (req: Req, res: Res) => void {
  return (req, res) => {
    const run = async (): Promise<void> => {
      let claims: Claims;
      try {
        claims = await authenticateRequest(authenticator, req as RequestLike);
      } catch (err) {
        reportError(err, req as RequestLike, options);
        sendChallenge(res, challenge(err, options));
        return;
      }
      attachClaims(req, claims, options);
      await handler(req, res, claims);
    };
    run().catch((err: unknown) => {
      try {
        options.onHandlerError?.(err, req as RequestLike);
      } catch {
        // ignore reporting failures
      }
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end();
      } else if (!res.writableEnded) {
        res.end();
      }
    });
  };
}

/** The parts of a Fastify reply the hook writes. */
export interface FastifyReplyLike {
  code(status: number): FastifyReplyLike;
  header(name: string, value: string): FastifyReplyLike;
  send(payload?: string): unknown;
}

/**
 * Fastify `onRequest` / `preHandler` hook (SDK-011): authenticates the request
 * and stores the claims (`getClaims(request)` / `request.auth`). On failure it
 * sends the RFC 6750 response and returns the reply, which stops Fastify's
 * lifecycle; the route handler never runs without verified claims.
 */
export function fastifyHook(authenticator: Authenticator, options: MiddlewareOptions = {}) {
  return async function proudauthFastify(request: RequestLike, reply: FastifyReplyLike): Promise<unknown> {
    let claims: Claims;
    try {
      claims = await authenticateRequest(authenticator, request);
    } catch (err) {
      reportError(err, request, options);
      const ch = challenge(err, options);
      reply.code(ch.status);
      for (const [k, v] of Object.entries(ch.headers)) reply.header(k, v);
      reply.header('cache-control', 'no-store').header('content-type', 'text/plain; charset=utf-8');
      await reply.send(STATUS_TEXT[ch.status] ?? 'Error');
      return reply;
    }
    attachClaims(request, claims, options);
    return undefined;
  };
}
