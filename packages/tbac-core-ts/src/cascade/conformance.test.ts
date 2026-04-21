// SPDX-License-Identifier: Apache-2.0
//
// Conformance test: the library must produce byte-exact outputs for the
// §A.5.1 fixed inputs. Loads `test-vectors/v1/expected.json` at test time
// and compares hex-encoded derivations. If CI reports drift, either the
// library has regressed or the vectors were deliberately updated and need
// to be committed.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2';
import {
  DOMAIN_PRIV_SIG,
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  SEP_VERSION,
  ZERO_SALT_32,
  canonicalizeScope,
  concat,
  hkdfSha256,
  scalarMulBase,
  scalarReduce64,
  u64be,
  u8,
} from '../index.js';
import { mintToken } from './mint.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const expected = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../test-vectors/v1/expected.json'), 'utf8'),
);
const inputs = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../test-vectors/v1/inputs.json'), 'utf8'),
);

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  return out;
}

describe('conformance vectors (test-vectors/v1)', () => {
  it('reports the normative SEP version', () => {
    expect(SEP_VERSION).toBe(expected.sep_version);
    expect(SEP_VERSION).toBe('2026-04-21-r41');
  });

  it('aud_hash matches §A.5.4 expectation', () => {
    const aud_hash = sha256(u8(inputs.aud));
    expect(hex(aud_hash)).toBe(expected.aud_hash_hex);
  });

  it('K_tok_enc derivation matches', () => {
    const K_session = fromHex(inputs.K_session_hex);
    const out = hkdfSha256(K_session, ZERO_SALT_32, concat(u8(DOMAIN_TOKEN_ENC), u8(inputs.jti)), 32);
    expect(hex(out)).toBe(expected.K_tok_enc_hex);
  });

  it('tqs_sk and TQS_PK derivations match', () => {
    const K_session = fromHex(inputs.K_session_hex);
    const tqsSkBytes = hkdfSha256(
      K_session,
      ZERO_SALT_32,
      concat(u8(DOMAIN_TOKEN_SIGN), u8(inputs.jti)),
      64,
    );
    const tqs_sk = scalarReduce64(tqsSkBytes);
    const TQS_PK = scalarMulBase(tqs_sk);
    expect(hex(TQS_PK)).toBe(expected.TQS_PK_hex);
  });

  it('K_priv derivation matches', () => {
    const K_session = fromHex(inputs.K_session_hex);
    const session_id = BigInt('0x' + inputs.session_id_hex);
    const K_priv = hkdfSha256(
      K_session,
      u64be(BigInt(inputs.policy_epoch)),
      concat(u8(DOMAIN_PRIV_SIG), u64be(session_id)),
      32,
    );
    expect(hex(K_priv)).toBe(expected.K_priv_hex);
  });

  it('scope canonical TLV matches', () => {
    const tlv = canonicalizeScope(inputs.scope);
    expect(hex(tlv)).toBe(expected.scope_tlv_hex);
  });

  it('mintToken with deterministic rTokSeed reproduces the full token_hex', () => {
    const K_session = fromHex(inputs.K_session_hex);
    const verifier_secret = sha256(u8(inputs.verifier_secret_src));
    const mutual_auth = sha256(u8(inputs.mutual_auth_src));
    const response_key = sha256(u8(inputs.response_key_src));
    const SEK_PK = scalarMulBase(BigInt('0x' + inputs.SEK_scalar_hex));
    const rTokSeed = (() => {
      const out = new Uint8Array(64);
      const s = sha256(u8('conformance-vector-rtok-seed-v1'));
      out.set(s, 0);
      out.set(s, 32);
      return out;
    })();
    const minted = mintToken({
      K_session,
      verifier_secret,
      mutual_auth,
      SEK_PK,
      session_id: BigInt('0x' + inputs.session_id_hex),
      policy_epoch: BigInt(inputs.policy_epoch),
      iat: inputs.iat,
      exp: inputs.exp,
      token_iv: fromHex(inputs.token_iv_hex),
      jti: inputs.jti,
      scope: inputs.scope,
      response_key,
      rTokSeed,
    });
    expect(hex(minted.token)).toBe(expected.token_hex);
    expect(hex(minted.priv_sig)).toBe(expected.priv_sig_hex);
  });
});
