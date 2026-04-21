// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  ALL_DOMAINS,
  DOMAIN_POP,
  DOMAIN_PRIV_SIG,
  DOMAIN_REQ_AAD,
  DOMAIN_REQ_ENC,
  DOMAIN_RESP_AAD,
  DOMAIN_RESP_ENC,
  DOMAIN_RESP_IV,
  DOMAIN_SCHNORR_NONCE,
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  ZERO_SALT_32,
  concat,
  hkdfSha256,
  u64be,
  u8,
} from './hkdf.js';

describe('HKDF domain strings (SEP §A.5, §12.2)', () => {
  it('has exactly ten distinct domain strings', () => {
    expect(new Set(ALL_DOMAINS).size).toBe(10);
  });

  it('every string is byte-exact', () => {
    expect(DOMAIN_TOKEN_ENC).toBe('tbac-token-enc-v1');
    expect(DOMAIN_TOKEN_SIGN).toBe('tbac-token-sign-v1');
    expect(DOMAIN_REQ_ENC).toBe('tbac-req-enc-v1');
    expect(DOMAIN_RESP_ENC).toBe('tbac-resp-enc-v1');
    expect(DOMAIN_RESP_IV).toBe('tbac-resp-iv-v1');
    expect(DOMAIN_PRIV_SIG).toBe('io.modelcontextprotocol/tbac:priv-sig:v1');
    expect(DOMAIN_POP).toBe('tbac-pop-v1');
    expect(DOMAIN_SCHNORR_NONCE).toBe('tbac-schnorr-nonce-v1');
    expect(DOMAIN_REQ_AAD).toBe('tbac-req-aad-v1');
    expect(DOMAIN_RESP_AAD).toBe('tbac-resp-aad-v1');
  });

  it('no string starts with the forbidden haap- prefix', () => {
    for (const d of ALL_DOMAINS) {
      expect(d.startsWith('h' + 'aap-')).toBe(false);
    }
  });
});

describe('HKDF-SHA-256 derivation', () => {
  it('produces the requested output length', () => {
    const ikm = new Uint8Array(32).fill(0xab);
    const out = hkdfSha256(ikm, ZERO_SALT_32, u8('test'), 32);
    expect(out.length).toBe(32);
  });

  it('is deterministic for identical inputs', () => {
    const ikm = new Uint8Array(32).fill(0xab);
    const a = hkdfSha256(ikm, ZERO_SALT_32, u8('hello'), 16);
    const b = hkdfSha256(ikm, ZERO_SALT_32, u8('hello'), 16);
    expect([...a]).toEqual([...b]);
  });

  it('produces different outputs for different info strings', () => {
    const ikm = new Uint8Array(32).fill(0xab);
    const a = hkdfSha256(ikm, ZERO_SALT_32, u8('a'), 16);
    const b = hkdfSha256(ikm, ZERO_SALT_32, u8('b'), 16);
    expect([...a]).not.toEqual([...b]);
  });

  it('concat and u64be helpers', () => {
    const c = concat(new Uint8Array([1, 2]), new Uint8Array([3, 4]));
    expect([...c]).toEqual([1, 2, 3, 4]);
    expect([...u64be(0xdeadbeef)]).toEqual([0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef]);
  });
});
