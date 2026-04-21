// SPDX-License-Identifier: Apache-2.0
//
// Test/demo-only token minting helper. Production TQS paths live elsewhere.
// This is normative in the following narrow sense: the §8.1 delegation
// attenuation check at mint-time MUST reject a widening child. That check
// is invoked by the caller (stub TQS in hawcx-mcp-auth) — this helper only
// performs the cryptographic assembly.

import { sha256 } from '@noble/hashes/sha2';
import {
  aesGcmEncrypt,
  hkdfSha256,
  hmacSha256,
  scalarMulBase,
  scalarReduce64,
  schnorrSign,
  DOMAIN_PRIV_SIG,
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  ZERO_SALT_32,
  concat,
  u8,
  u64be,
} from '../crypto/index.js';
import { canonicalizeScope } from '../scope/canonical.js';
import type { ScopeJson } from '../scope/schema.js';
import {
  ALG_ID_0x01,
  MSG_TYPE_ENTERPRISE,
  REQUEST_FORMAT_DIRECT,
  TOKEN_VERSION_0x03,
  assembleToken,
  buildAad,
} from '../wire/framing.js';
import { encodeTokenBody } from '../wire/token.js';

export interface MintInputs {
  readonly K_session: Uint8Array; // 32 bytes
  readonly verifier_secret: Uint8Array; // 32 bytes
  readonly mutual_auth: Uint8Array; // 32 bytes
  readonly SEK_PK: Uint8Array; // 32 bytes (compressed Ristretto255)
  readonly session_id: bigint;
  readonly policy_epoch: bigint;
  readonly iat: number;
  readonly exp: number;
  readonly token_iv: Uint8Array; // 12 bytes
  readonly jti: string; // 22-byte base64url
  readonly scope: ScopeJson;
  readonly response_key: Uint8Array; // 32 bytes
  /** CSPRNG-supplied 32-byte nonce source for r_tok (test can inject). */
  readonly rTokSeed: Uint8Array; // 64 bytes → reduced via scalarReduce64
}

export interface MintedToken {
  readonly token: Uint8Array;
  readonly aud_hash: Uint8Array;
  readonly scope_tlv: Uint8Array;
  readonly priv_sig: Uint8Array;
}

/** Mint a fresh enterprise-profile token. */
export function mintToken(i: MintInputs): MintedToken {
  const aud_hash = sha256(u8(i.scope.aud));
  const aad = buildAad({
    version: TOKEN_VERSION_0x03,
    alg_id: ALG_ID_0x01,
    msg_type: MSG_TYPE_ENTERPRISE,
    request_format: REQUEST_FORMAT_DIRECT,
    session_id: i.session_id,
    token_iv: i.token_iv,
    iat: BigInt(i.iat),
    exp: BigInt(i.exp),
    policy_epoch: i.policy_epoch,
    aud_hash,
    jti: i.jti,
  });

  // Per-token keys
  const K_tok_enc = hkdfSha256(i.K_session, ZERO_SALT_32, concat(u8(DOMAIN_TOKEN_ENC), u8(i.jti)), 32);
  const tqsSkBytes = hkdfSha256(
    i.K_session,
    ZERO_SALT_32,
    concat(u8(DOMAIN_TOKEN_SIGN), u8(i.jti)),
    64,
  );
  const tqsSk = scalarReduce64(tqsSkBytes);
  const tqsPk = scalarMulBase(tqsSk);

  // priv_sig = HMAC-SHA-256(K_priv[epoch], scope_tlv)
  const K_priv = hkdfSha256(
    i.K_session,
    u64be(i.policy_epoch),
    concat(u8(DOMAIN_PRIV_SIG), u64be(i.session_id)),
    32,
  );
  const scope_tlv = canonicalizeScope(i.scope);
  const priv_sig = hmacSha256(K_priv, scope_tlv);

  // Encrypt TokenBody
  const tokenBody = encodeTokenBody({
    scope_json: scope_tlv,
    priv_sig,
    response_key: i.response_key,
    mutual_auth: i.mutual_auth,
    verifier_secret: i.verifier_secret,
  });
  const { ciphertext, tag } = aesGcmEncrypt({
    key: K_tok_enc,
    iv: i.token_iv,
    aad,
    plaintext: tokenBody,
  });

  // Schnorr signature
  const rTok = scalarReduce64(i.rTokSeed);
  const R = scalarMulBase(rTok);
  const schnorrMessage = concat(
    R,
    tqsPk,
    i.SEK_PK,
    i.verifier_secret,
    tag,
    ciphertext,
    aad,
  );
  const { sigma } = schnorrSign(tqsSk, rTok, schnorrMessage);

  const token = assembleToken({
    version: TOKEN_VERSION_0x03,
    alg_id: ALG_ID_0x01,
    msg_type: MSG_TYPE_ENTERPRISE,
    request_format: REQUEST_FORMAT_DIRECT,
    session_id: i.session_id,
    token_iv: i.token_iv,
    iat: BigInt(i.iat),
    exp: BigInt(i.exp),
    policy_epoch: i.policy_epoch,
    aud_hash,
    jti: i.jti,
    R_tok: R,
    GCM_tag: tag,
    sigma_tok: sigma,
    CT_body: ciphertext,
  });

  return { token, aud_hash, scope_tlv, priv_sig };
}
