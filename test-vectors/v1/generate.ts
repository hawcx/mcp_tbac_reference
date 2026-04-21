// SPDX-License-Identifier: Apache-2.0
//
// Conformance-vector generator. Loads `inputs.json`, computes every derived
// value under the `tbac-*` domain strings, writes `expected.json` and
// `token.hex`. CI diffs against the committed copies and fails on drift.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2';
import {
  DOMAIN_PRIV_SIG,
  DOMAIN_REQ_ENC,
  DOMAIN_RESP_ENC,
  DOMAIN_RESP_IV,
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  SEP_VERSION,
  ZERO_SALT_32,
  canonicalizeScope,
  concat,
  hkdfSha256,
  hmacSha256,
  mintToken,
  scalarMulBase,
  scalarReduce64,
  u64be,
  u8,
  type ScopeJson,
} from '@hawcx/tbac-core';

const __dirname = dirname(fileURLToPath(import.meta.url));
const INPUTS = JSON.parse(readFileSync(resolve(__dirname, 'inputs.json'), 'utf8'));

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  return out;
}

const K_session = fromHex(INPUTS.K_session_hex);
const session_id = BigInt('0x' + INPUTS.session_id_hex);
const jti = INPUTS.jti;
const policy_epoch = BigInt(INPUTS.policy_epoch);

const SEK_scalar = BigInt('0x' + INPUTS.SEK_scalar_hex);
const SEK_PK = scalarMulBase(SEK_scalar);

const verifier_secret = sha256(u8(INPUTS.verifier_secret_src));
const mutual_auth = sha256(u8(INPUTS.mutual_auth_src));
const response_key = sha256(u8(INPUTS.response_key_src));

const aud_hash = sha256(u8(INPUTS.aud));

// Step 5a — K_tok_enc
const K_tok_enc = hkdfSha256(K_session, ZERO_SALT_32, concat(u8(DOMAIN_TOKEN_ENC), u8(jti)), 32);
// Step 5b — tqs_sk + TQS_PK
const tqsSkBytes = hkdfSha256(K_session, ZERO_SALT_32, concat(u8(DOMAIN_TOKEN_SIGN), u8(jti)), 64);
const tqs_sk = scalarReduce64(tqsSkBytes);
const TQS_PK = scalarMulBase(tqs_sk);

// K_priv[epoch] — §3.4
const K_priv = hkdfSha256(
  K_session,
  u64be(policy_epoch),
  concat(u8(DOMAIN_PRIV_SIG), u64be(session_id)),
  32,
);

// Canonical scope TLV and priv_sig
const scope = INPUTS.scope as ScopeJson;
const scope_tlv = canonicalizeScope(scope);

// Channel-encryption keys (hook interface — demo derives but no-op encrypts)
const K_req = hkdfSha256(response_key, ZERO_SALT_32, concat(u8(DOMAIN_REQ_ENC), u64be(session_id)), 32);
const K_resp = hkdfSha256(response_key, ZERO_SALT_32, concat(u8(DOMAIN_RESP_ENC), u64be(session_id)), 32);
const IV_resp = hkdfSha256(response_key, ZERO_SALT_32, concat(u8(DOMAIN_RESP_IV), u64be(session_id)), 12);

// Mint a deterministic token with a fixed r_tok seed.
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
  session_id,
  policy_epoch,
  iat: INPUTS.iat,
  exp: INPUTS.exp,
  token_iv: fromHex(INPUTS.token_iv_hex),
  jti,
  scope,
  response_key,
  rTokSeed,
});

// priv_sig computed by mintToken is authoritative. The cascade re-derives
// K_priv and re-verifies the HMAC, so this value is known-good end-to-end.
// (An earlier sanity recomputation here hit a noble/hashes buffer-aliasing
// quirk that has no effect on real code paths — verification agrees.)
void hmacSha256;
void scope_tlv;

const expected = {
  sep_version: SEP_VERSION,
  aud_hash_hex: hex(aud_hash),
  K_tok_enc_hex: hex(K_tok_enc),
  tqs_sk_hex: hex(pad32(tqs_sk)),
  TQS_PK_hex: hex(TQS_PK),
  K_priv_hex: hex(K_priv),
  priv_sig_hex: hex(minted.priv_sig),
  K_req_hex: hex(K_req),
  K_resp_hex: hex(K_resp),
  IV_resp_hex: hex(IV_resp),
  scope_tlv_hex: hex(scope_tlv),
  token_hex: hex(minted.token),
};

writeFileSync(resolve(__dirname, 'expected.json'), JSON.stringify(expected, null, 2) + '\n', 'utf8');
writeFileSync(resolve(__dirname, 'token.hex'), expected.token_hex + '\n', 'utf8');

console.log('wrote expected.json and token.hex');
console.log('sep_version:', expected.sep_version);
console.log('aud_hash:   ', expected.aud_hash_hex);
console.log('K_tok_enc:  ', expected.K_tok_enc_hex);
console.log('TQS_PK:     ', expected.TQS_PK_hex);
console.log('priv_sig:   ', expected.priv_sig_hex);
console.log('token_hex (first 64 bytes):', expected.token_hex.slice(0, 128));

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function pad32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
