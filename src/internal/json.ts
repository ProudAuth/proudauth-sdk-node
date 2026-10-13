/**
 * Strict JSON parsing for security-sensitive inputs (JOSE headers, JWT payloads,
 * JWKS documents and introspection responses).
 *
 * `JSON.parse` silently keeps the last of several members with the same name, so
 * two parties can read different values from one document. This parser validates
 * the complete RFC 8259 grammar first and rejects duplicate member names (compared
 * after unescaping, so `"iss"` and `"iss"` collide), excessive nesting, lone
 * surrogates and trailing data. Only then is the text handed to `JSON.parse`.
 *
 * @internal
 */

export type StrictJSONFailure = 'malformed' | 'duplicate';

export class StrictJSONError extends Error {
  override readonly name = 'StrictJSONError';
  constructor(readonly reason: StrictJSONFailure) {
    super(reason === 'duplicate' ? 'duplicate JSON member name' : 'malformed JSON');
  }
}

/** Default nesting limit, matching the Go SDK (values deeper than 32 levels are rejected). */
export const DEFAULT_MAX_DEPTH = 32;

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

export function parseStrictJSON(text: string, maxDepth: number = DEFAULT_MAX_DEPTH): unknown {
  let i = 0;
  const n = text.length;

  const fail = (): never => {
    throw new StrictJSONError('malformed');
  };

  const skipWhitespace = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const readString = (): string => {
    // text[i] === '"'
    const start = i;
    i++;
    let escaped = false;
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        const literal = text.slice(start, i);
        const value = escaped ? (JSON.parse(literal) as string) : literal.slice(1, -1);
        if (!value.isWellFormed()) fail();
        return value;
      }
      if (c === 0x5c) {
        escaped = true;
        i++;
        if (i >= n) fail();
        const e = text[i];
        if (e === 'u') {
          if (!HEX4.test(text.slice(i + 1, i + 5))) fail();
          i += 5;
        } else if (e === '"' || e === '\\' || e === '/' || e === 'b' || e === 'f' || e === 'n' || e === 'r' || e === 't') {
          i++;
        } else {
          fail();
        }
        continue;
      }
      if (c < 0x20) fail();
      i++;
    }
    return fail();
  };

  const readValue = (depth: number): void => {
    if (depth > maxDepth) fail();
    skipWhitespace();
    if (i >= n) fail();
    const c = text[i];
    switch (c) {
      case '{': {
        i++;
        const seen = new Set<string>();
        skipWhitespace();
        if (text[i] === '}') {
          i++;
          return;
        }
        for (;;) {
          skipWhitespace();
          if (text[i] !== '"') fail();
          const key = readString();
          if (seen.has(key)) throw new StrictJSONError('duplicate');
          seen.add(key);
          skipWhitespace();
          if (text[i] !== ':') fail();
          i++;
          readValue(depth + 1);
          skipWhitespace();
          if (text[i] === ',') {
            i++;
            continue;
          }
          if (text[i] === '}') {
            i++;
            return;
          }
          fail();
        }
      }
      // eslint-disable-next-line no-fallthrough
      case '[': {
        i++;
        skipWhitespace();
        if (text[i] === ']') {
          i++;
          return;
        }
        for (;;) {
          readValue(depth + 1);
          skipWhitespace();
          if (text[i] === ',') {
            i++;
            continue;
          }
          if (text[i] === ']') {
            i++;
            return;
          }
          fail();
        }
      }
      // eslint-disable-next-line no-fallthrough
      case '"':
        readString();
        return;
      case 't':
        if (text.startsWith('true', i)) {
          i += 4;
          return;
        }
        return fail();
      case 'f':
        if (text.startsWith('false', i)) {
          i += 5;
          return;
        }
        return fail();
      case 'n':
        if (text.startsWith('null', i)) {
          i += 4;
          return;
        }
        return fail();
      default: {
        NUMBER.lastIndex = i;
        const m = NUMBER.exec(text);
        if (!m || m[0].length === 0) fail();
        i += m![0].length;
        return;
      }
    }
  };

  readValue(0);
  skipWhitespace();
  if (i !== n) fail();
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return fail();
  }
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
