import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { constants, generateKeyPairSync, randomBytes, sign as cryptoSign, type KeyObject } from 'node:crypto';
import type { AddressInfo } from 'node:net';

export type Alg = 'ES256' | 'RS256' | 'PS256' | 'EdDSA';

export interface TestKey {
  kid: string;
  alg: Alg;
  privateKey: KeyObject;
  publicKey: KeyObject;
  jwk: Record<string, unknown>;
}

export function makeKey(alg: Alg, kid = `${alg.toLowerCase()}-${randomBytes(4).toString('hex')}`, opts: { jwkAlg?: boolean } = {}): TestKey {
  let pair: { privateKey: KeyObject; publicKey: KeyObject };
  switch (alg) {
    case 'ES256':
      pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      break;
    case 'RS256':
    case 'PS256':
      pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
      break;
    case 'EdDSA':
      pair = generateKeyPairSync('ed25519');
      break;
  }
  const jwk: Record<string, unknown> = { ...(pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid, use: 'sig' };
  if (opts.jwkAlg !== false) jwk.alg = alg;
  return { kid, alg, privateKey: pair.privateKey, publicKey: pair.publicKey, jwk };
}

export const b64 = (v: string | Buffer): string => Buffer.from(v).toString('base64url');

export function signature(alg: string, key: KeyObject, data: Buffer): Buffer {
  switch (alg) {
    case 'ES256':
      return cryptoSign('sha256', data, { key, dsaEncoding: 'ieee-p1363' });
    case 'RS256':
      return cryptoSign('sha256', data, { key, padding: constants.RSA_PKCS1_PADDING });
    case 'PS256':
      return cryptoSign('sha256', data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST });
    case 'EdDSA':
      return cryptoSign(null, data, key);
    default:
      throw new Error('unsupported test alg ' + alg);
  }
}

/** Signs raw header/payload JSON text (lets tests craft duplicate members). */
export function signRaw(key: TestKey, headerJSON: string, payloadJSON: string, alg: string = key.alg): string {
  const input = `${b64(headerJSON)}.${b64(payloadJSON)}`;
  return `${input}.${b64(signature(alg, key.privateKey, Buffer.from(input)))}`;
}

export function signJWT(key: TestKey, payload: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const h = { alg: key.alg, kid: key.kid, typ: 'at+jwt', ...header };
  for (const [k, v] of Object.entries(h)) if (v === undefined) delete (h as Record<string, unknown>)[k];
  return signRaw(key, JSON.stringify(h), JSON.stringify(payload), String(h.alg));
}

export interface TestServer {
  url: string;
  hits: number;
  paths: string[];
  close(): Promise<void>;
}

export async function startServer(handler: (req: IncomingMessage, res: ServerResponse, body: string) => unknown): Promise<TestServer> {
  const state = { hits: 0, paths: [] as string[] };
  const server: Server = createServer((req, res) => {
    state.hits++;
    state.paths.push(req.url ?? '');
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      Promise.resolve(handler(req, res, Buffer.concat(chunks).toString('utf8'))).catch(() => {
        if (!res.headersSent) res.statusCode = 500;
        res.end();
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    get hits() {
      return state.hits;
    },
    get paths() {
      return state.paths;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  } as TestServer;
}

export function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** A port that refuses connections (server started and closed). */
export async function deadUrl(): Promise<string> {
  const s = await startServer((_q, r) => r.end());
  const u = s.url;
  await s.close();
  return u;
}
