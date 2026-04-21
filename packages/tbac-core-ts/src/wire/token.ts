// SPDX-License-Identifier: Apache-2.0
//
// TokenBody (the encrypted CT_body) encoding per §3.0.2.

import { decodeTlv, encodeTlv, type TlvField } from './tlv.js';

export const TOKEN_BODY_TAGS = {
  scope_json: 0x01,
  priv_sig: 0x02,
  response_key: 0x03,
  mutual_auth: 0x04,
  verifier_secret: 0x05,
} as const;

export interface TokenBodyFields {
  readonly scope_json: Uint8Array; // TLV-canonical scope JSON bytes
  readonly priv_sig: Uint8Array; // 32 bytes
  readonly response_key: Uint8Array; // 32 bytes
  readonly mutual_auth: Uint8Array; // 32 bytes
  readonly verifier_secret: Uint8Array; // 32 bytes
}

/** Serialize TokenBody in ascending tag order. */
export function encodeTokenBody(b: TokenBodyFields): Uint8Array {
  const fields: TlvField[] = [
    { tag: TOKEN_BODY_TAGS.scope_json, value: b.scope_json },
    { tag: TOKEN_BODY_TAGS.priv_sig, value: b.priv_sig },
    { tag: TOKEN_BODY_TAGS.response_key, value: b.response_key },
    { tag: TOKEN_BODY_TAGS.mutual_auth, value: b.mutual_auth },
    { tag: TOKEN_BODY_TAGS.verifier_secret, value: b.verifier_secret },
  ];
  return encodeTlv(fields);
}

/** Parse TokenBody. Rejects if any REQUIRED field is missing (§3.0.2). */
export function decodeTokenBody(plaintext: Uint8Array): TokenBodyFields {
  const fields = decodeTlv(plaintext);
  const map = new Map<number, Uint8Array>();
  for (const f of fields) map.set(f.tag, f.value);

  const need = (tag: number, name: string, len?: number): Uint8Array => {
    const v = map.get(tag);
    if (v === undefined) throw new Error(`TokenBody missing required field: ${name}`);
    if (len !== undefined && v.length !== len)
      throw new Error(`TokenBody.${name} length ${v.length} != expected ${len}`);
    return v;
  };

  return {
    scope_json: need(TOKEN_BODY_TAGS.scope_json, 'scope_json'),
    priv_sig: need(TOKEN_BODY_TAGS.priv_sig, 'priv_sig', 32),
    response_key: need(TOKEN_BODY_TAGS.response_key, 'response_key', 32),
    mutual_auth: need(TOKEN_BODY_TAGS.mutual_auth, 'mutual_auth', 32),
    verifier_secret: need(TOKEN_BODY_TAGS.verifier_secret, 'verifier_secret', 32),
  };
}
