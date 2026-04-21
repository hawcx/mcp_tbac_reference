// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { decodeTokenBody, encodeTokenBody } from './token.js';

describe('TokenBody TLV (§3.0.2)', () => {
  const body = {
    scope_json: new Uint8Array([1, 2, 3]),
    priv_sig: new Uint8Array(32).fill(0x01),
    response_key: new Uint8Array(32).fill(0x02),
    mutual_auth: new Uint8Array(32).fill(0x03),
    verifier_secret: new Uint8Array(32).fill(0x04),
  };

  it('round-trips', () => {
    const bytes = encodeTokenBody(body);
    const r = decodeTokenBody(bytes);
    expect([...r.scope_json]).toEqual([1, 2, 3]);
    expect([...r.priv_sig]).toEqual([...body.priv_sig]);
    expect([...r.response_key]).toEqual([...body.response_key]);
    expect([...r.mutual_auth]).toEqual([...body.mutual_auth]);
    expect([...r.verifier_secret]).toEqual([...body.verifier_secret]);
  });

  it('rejects missing scope_json', () => {
    const partialBytes = encodeTokenBody({
      ...body,
      scope_json: new Uint8Array(0),
    });
    // The encoder will include scope_json as an empty-length field so the
    // decoder still sees it. Instead, synthesise bytes that omit tag 0x01.
    const bytes = partialBytes.slice(2); // drop the `[0x01, 0x00]` prefix
    expect(() => decodeTokenBody(bytes)).toThrow(/scope_json/);
  });

  it('rejects wrong-length priv_sig', () => {
    // Manually craft bytes with a 10-byte priv_sig
    const bytes = encodeTokenBody({ ...body, priv_sig: new Uint8Array(10) });
    expect(() => decodeTokenBody(bytes)).toThrow(/priv_sig/);
  });
});
