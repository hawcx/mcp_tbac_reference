// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { decodeTlv, encodeTlv, isCanonical } from './tlv.js';

describe('TLV encoding (Appendix A.1)', () => {
  it('short length uses 1 byte', () => {
    const out = encodeTlv([{ tag: 0x01, value: new Uint8Array([0xaa, 0xbb]) }]);
    expect([...out]).toEqual([0x01, 0x02, 0xaa, 0xbb]);
  });

  it('length 127 fits in 1 byte', () => {
    const out = encodeTlv([{ tag: 0x05, value: new Uint8Array(127).fill(0x42) }]);
    expect(out[0]).toBe(0x05);
    expect(out[1]).toBe(0x7f);
    expect(out.length).toBe(2 + 127);
  });

  it('length 128 uses 2 bytes with high bit set', () => {
    const out = encodeTlv([{ tag: 0x06, value: new Uint8Array(128).fill(0x42) }]);
    expect(out[0]).toBe(0x06);
    expect(out[1]).toBe(0x80);
    expect(out[2]).toBe(128);
    expect(out.length).toBe(3 + 128);
  });

  it('rejects length over 0x7FFF', () => {
    const tooBig = new Uint8Array(0x8000);
    expect(() => encodeTlv([{ tag: 0x01, value: tooBig }])).toThrow();
  });

  it('round-trips', () => {
    const a = new Uint8Array(5).fill(0xaa);
    const b = new Uint8Array(200).fill(0xbb);
    const encoded = encodeTlv([
      { tag: 0x01, value: a },
      { tag: 0x02, value: b },
    ]);
    const decoded = decodeTlv(encoded);
    expect(decoded.length).toBe(2);
    expect(decoded[0]!.tag).toBe(0x01);
    expect([...decoded[0]!.value]).toEqual([...a]);
    expect(decoded[1]!.tag).toBe(0x02);
    expect([...decoded[1]!.value]).toEqual([...b]);
  });

  it('isCanonical detects non-ascending tags', () => {
    expect(
      isCanonical([
        { tag: 0x01, value: new Uint8Array() },
        { tag: 0x02, value: new Uint8Array() },
      ]),
    ).toBe(true);
    expect(
      isCanonical([
        { tag: 0x02, value: new Uint8Array() },
        { tag: 0x01, value: new Uint8Array() },
      ]),
    ).toBe(false);
  });

  it('rejects truncated input', () => {
    expect(() => decodeTlv(new Uint8Array([0x01]))).toThrow(); // missing length
    expect(() => decodeTlv(new Uint8Array([0x01, 0x05, 0xaa]))).toThrow(); // value short
    expect(() => decodeTlv(new Uint8Array([0x01, 0x81]))).toThrow(); // missing length byte 2
  });
});
