// SPDX-License-Identifier: Apache-2.0
//
// HKDF-SHA-256 with the ten `tbac-*` domain-separation strings from SEP
// §A.5 and §12.2. These are the sole normative domain strings for MCP
// TBAC; the HAAP canonical spec uses different `haap-*` strings (§12.2
// migration table) and interop with HAAP requires an explicit conformance
// mode in the HAAP SDK.
//
// Clean-room note: this file is the single place where the historical
// `haap-*` strings are referenced (only in a comment, for migration
// clarity). The guard script exempts this file so that comment is permitted.

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

export const DOMAIN_TOKEN_ENC = 'tbac-token-enc-v1';
export const DOMAIN_TOKEN_SIGN = 'tbac-token-sign-v1';
export const DOMAIN_REQ_ENC = 'tbac-req-enc-v1';
export const DOMAIN_RESP_ENC = 'tbac-resp-enc-v1';
export const DOMAIN_RESP_IV = 'tbac-resp-iv-v1';
export const DOMAIN_PRIV_SIG = 'io.modelcontextprotocol/tbac:priv-sig:v1';
export const DOMAIN_POP = 'tbac-pop-v1';
export const DOMAIN_SCHNORR_NONCE = 'tbac-schnorr-nonce-v1';
export const DOMAIN_REQ_AAD = 'tbac-req-aad-v1';
export const DOMAIN_RESP_AAD = 'tbac-resp-aad-v1';

/** Every normative domain string. Keep in sync with §12.2 table. */
export const ALL_DOMAINS = [
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  DOMAIN_REQ_ENC,
  DOMAIN_RESP_ENC,
  DOMAIN_RESP_IV,
  DOMAIN_PRIV_SIG,
  DOMAIN_POP,
  DOMAIN_SCHNORR_NONCE,
  DOMAIN_REQ_AAD,
  DOMAIN_RESP_AAD,
] as const;

/** Thin wrapper around @noble/hashes HKDF-SHA-256 with explicit salt semantics. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

const utf8 = new TextEncoder();

/** 32-byte zero salt used by per-token derivations (§3.0.1). */
export const ZERO_SALT_32 = new Uint8Array(32);

/** Concatenate multiple byte arrays into one. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** UTF-8 encode (exported for convenience). */
export function u8(s: string): Uint8Array {
  return utf8.encode(s);
}

/** Encode a uint64 as 8-byte big-endian bytes. */
export function u64be(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}
