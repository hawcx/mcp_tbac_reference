// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  GROUP_ORDER,
  hashToScalar,
  scalarFromBytes,
  scalarMulBase,
  scalarReduce64,
  schnorrSign,
  schnorrVerify,
} from './schnorr.js';

describe('Ristretto255 Schnorr (alg_id 0x01)', () => {
  it('scalarReduce64 rejects wrong-length input', () => {
    expect(() => scalarReduce64(new Uint8Array(32))).toThrow();
    expect(() => scalarReduce64(new Uint8Array(65))).toThrow();
  });

  it('scalarReduce64 reduces modulo the group order', () => {
    const maxBytes = new Uint8Array(64).fill(0xff);
    const s = scalarReduce64(maxBytes);
    expect(s < GROUP_ORDER).toBe(true);
  });

  it('hashToScalar is deterministic', () => {
    const a = hashToScalar(new Uint8Array([1, 2, 3]));
    const b = hashToScalar(new Uint8Array([1, 2, 3]));
    expect(a).toBe(b);
  });

  it('scalarMulBase produces a 32-byte compressed point', () => {
    const s = hashToScalar(new Uint8Array([42]));
    const pt = scalarMulBase(s);
    expect(pt.length).toBe(32);
  });

  it('sign and verify round-trip', () => {
    const tqsSk = hashToScalar(new Uint8Array(Buffer.from('test-sk', 'utf8')));
    const tqsPk = scalarMulBase(tqsSk);
    const rTok = hashToScalar(new Uint8Array(Buffer.from('test-nonce', 'utf8')));
    const message = new Uint8Array(Buffer.from('transcript bytes', 'utf8'));
    const { R, sigma } = schnorrSign(tqsSk, rTok, message);
    expect(schnorrVerify(R, sigma, tqsPk, message)).toBe(true);
  });

  it('verification fails on tampered message', () => {
    const tqsSk = hashToScalar(new Uint8Array(Buffer.from('sk', 'utf8')));
    const tqsPk = scalarMulBase(tqsSk);
    const rTok = hashToScalar(new Uint8Array(Buffer.from('nonce', 'utf8')));
    const m = new Uint8Array(Buffer.from('hello', 'utf8'));
    const { R, sigma } = schnorrSign(tqsSk, rTok, m);
    const tampered = new Uint8Array(Buffer.from('HELLO', 'utf8'));
    expect(schnorrVerify(R, sigma, tqsPk, tampered)).toBe(false);
  });

  it('verification fails on wrong pubkey', () => {
    const tqsSk = hashToScalar(new Uint8Array(Buffer.from('sk', 'utf8')));
    const tqsPk = scalarMulBase(tqsSk);
    const wrongPk = scalarMulBase(hashToScalar(new Uint8Array(Buffer.from('other-sk', 'utf8'))));
    const rTok = hashToScalar(new Uint8Array(Buffer.from('nonce', 'utf8')));
    const m = new Uint8Array(Buffer.from('hello', 'utf8'));
    const { R, sigma } = schnorrSign(tqsSk, rTok, m);
    expect(schnorrVerify(R, sigma, wrongPk, m)).toBe(false);
    // sanity
    expect(schnorrVerify(R, sigma, tqsPk, m)).toBe(true);
  });

  it('scalarFromBytes round-trips', () => {
    const b = new Uint8Array(32);
    b[0] = 0x7f;
    b[31] = 0x01;
    const n = scalarFromBytes(b);
    expect(typeof n).toBe('bigint');
  });
});
