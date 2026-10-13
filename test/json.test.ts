import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseStrictJSON, StrictJSONError } from '../src/internal/json.js';
import { decodeBase64Url } from '../src/internal/jws.js';

const reason = (text: string): string | undefined => {
  try {
    parseStrictJSON(text);
    return undefined;
  } catch (e) {
    return e instanceof StrictJSONError ? e.reason : 'other';
  }
};

describe('strict JSON', () => {
  it('parses valid JSON like JSON.parse', () => {
    for (const t of ['{}', '[]', '{"a":[1,2,{"b":null}],"c":"\\u00e9\\n","d":-1.5e3,"e":true,"f":false}', ' "x" ', '0', '{"a":{"a":1}}']) {
      assert.deepEqual(parseStrictJSON(t), JSON.parse(t));
    }
  });

  it('rejects duplicate member names, including escaped ones', () => {
    assert.equal(reason('{"a":1,"a":2}'), 'duplicate');
    assert.equal(reason('{"iss":"x","\\u0069ss":"y"}'), 'duplicate');
    assert.equal(reason('{"x":{"a":1,"a":1}}'), 'duplicate');
    assert.equal(reason('[{"a":1,"a":1}]'), 'duplicate');
  });

  it('rejects trailing data, invalid grammar, lone surrogates and deep nesting', () => {
    for (const t of [
      '{} {}',
      '{}x',
      '{"a":1,}',
      '[1,]',
      "{'a':1}",
      '{"a":01}',
      '{"a":.5}',
      '{"a":NaN}',
      '{"a":"\t"}',
      '{"a":"\\x41"}',
      '{"a":"\\ud800"}',
      '﻿{}',
      '',
      '{"a":1',
      '[' .repeat(34) + ']'.repeat(34),
    ]) {
      assert.equal(reason(t), 'malformed', t);
    }
    assert.doesNotThrow(() => parseStrictJSON('['.repeat(33) + ']'.repeat(33)));
  });

  it('decodes only canonical unpadded base64url', () => {
    assert.equal(decodeBase64Url('aGk').toString(), 'hi');
    for (const s of ['aGk=', 'aG+k', 'aG/k', 'aGl', 'a', 'aG k']) assert.throws(() => decodeBase64Url(s), s);
  });
});
