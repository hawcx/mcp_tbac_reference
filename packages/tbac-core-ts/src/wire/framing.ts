// SPDX-License-Identifier: Apache-2.0
//
// 184-byte fixed prefix layout per §3.0. Byte offsets are normative.

export const TOKEN_VERSION_0x03 = 0x03;
export const ALG_ID_0x01 = 0x01;

export const MSG_TYPE_ENTERPRISE = 0x03;
export const MSG_TYPE_CONSUMER = 0x08;
export const MSG_TYPE_T0_EPHEMERAL = 0x09;

export const REQUEST_FORMAT_DIRECT = 0x00;
export const REQUEST_FORMAT_ENVELOPED = 0x01;

export const AAD_LENGTH = 104;
export const HEADER_LENGTH = 184;

/** Offsets of each fixed-prefix field (§3.0 normative table). */
export const OFFSETS = {
  version: 0,
  alg_id: 1,
  msg_type: 2,
  request_format: 3,
  session_id: 4,
  token_iv: 12,
  iat: 24,
  exp: 32,
  policy_epoch: 40,
  aud_hash: 48,
  jti: 80,
  jti_pad: 102,
  R_tok: 104,
  GCM_tag: 136,
  sigma_tok: 152,
  CT_body: 184,
} as const;

export interface TokenHeader {
  readonly version: number;
  readonly alg_id: number;
  readonly msg_type: number;
  readonly request_format: number;
  readonly session_id: bigint;
  readonly token_iv: Uint8Array; // 12 bytes
  readonly iat: bigint;
  readonly exp: bigint;
  readonly policy_epoch: bigint;
  readonly aud_hash: Uint8Array; // 32 bytes
  readonly jti: string; // 22-byte base64url, no pad
  readonly R_tok: Uint8Array; // 32 bytes
  readonly GCM_tag: Uint8Array; // 16 bytes
  readonly sigma_tok: Uint8Array; // 32 bytes
}

export interface ParsedToken {
  readonly header: TokenHeader;
  readonly aad: Uint8Array; // bytes 0..103 — bound into AES-GCM AAD
  readonly ctBody: Uint8Array; // bytes 184..end
  readonly raw: Uint8Array; // the full token
}

/** Parse the 184-byte prefix and extract the ciphertext body. Throws on malformed input. */
export function parseTokenBytes(bytes: Uint8Array): ParsedToken {
  if (bytes.length < HEADER_LENGTH) throw new Error('token shorter than 184-byte prefix');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const version = v.getUint8(OFFSETS.version);
  const alg_id = v.getUint8(OFFSETS.alg_id);
  const msg_type = v.getUint8(OFFSETS.msg_type);
  const request_format = v.getUint8(OFFSETS.request_format);

  const session_id = v.getBigUint64(OFFSETS.session_id, false);
  const token_iv = bytes.slice(OFFSETS.token_iv, OFFSETS.token_iv + 12);
  const iat = v.getBigUint64(OFFSETS.iat, false);
  const exp = v.getBigUint64(OFFSETS.exp, false);
  const policy_epoch = v.getBigUint64(OFFSETS.policy_epoch, false);
  const aud_hash = bytes.slice(OFFSETS.aud_hash, OFFSETS.aud_hash + 32);

  const jtiBytes = bytes.slice(OFFSETS.jti, OFFSETS.jti + 22);
  const jti = new TextDecoder('utf-8').decode(jtiBytes);
  const jtiPadHi = v.getUint8(OFFSETS.jti_pad);
  const jtiPadLo = v.getUint8(OFFSETS.jti_pad + 1);
  if (jtiPadHi !== 0 || jtiPadLo !== 0) throw new Error('jti_pad must be 0x00 0x00');

  const R_tok = bytes.slice(OFFSETS.R_tok, OFFSETS.R_tok + 32);
  const GCM_tag = bytes.slice(OFFSETS.GCM_tag, OFFSETS.GCM_tag + 16);
  const sigma_tok = bytes.slice(OFFSETS.sigma_tok, OFFSETS.sigma_tok + 32);

  const aad = bytes.slice(0, AAD_LENGTH);
  const ctBody = bytes.slice(HEADER_LENGTH);

  return {
    header: {
      version,
      alg_id,
      msg_type,
      request_format,
      session_id,
      token_iv,
      iat,
      exp,
      policy_epoch,
      aud_hash,
      jti,
      R_tok,
      GCM_tag,
      sigma_tok,
    },
    aad,
    ctBody,
    raw: bytes,
  };
}

export interface AssembleInput {
  readonly version?: number; // defaults to 0x03
  readonly alg_id?: number; // defaults to 0x01
  readonly msg_type: number;
  readonly request_format: number;
  readonly session_id: bigint;
  readonly token_iv: Uint8Array;
  readonly iat: bigint;
  readonly exp: bigint;
  readonly policy_epoch: bigint;
  readonly aud_hash: Uint8Array;
  readonly jti: string;
}

/** Build the 104-byte AAD prefix bytes 0..103 from scalar fields. */
export function buildAad(input: AssembleInput): Uint8Array {
  const out = new Uint8Array(AAD_LENGTH);
  const v = new DataView(out.buffer);
  v.setUint8(OFFSETS.version, input.version ?? TOKEN_VERSION_0x03);
  v.setUint8(OFFSETS.alg_id, input.alg_id ?? ALG_ID_0x01);
  v.setUint8(OFFSETS.msg_type, input.msg_type);
  v.setUint8(OFFSETS.request_format, input.request_format);
  v.setBigUint64(OFFSETS.session_id, input.session_id, false);
  out.set(input.token_iv, OFFSETS.token_iv);
  v.setBigUint64(OFFSETS.iat, input.iat, false);
  v.setBigUint64(OFFSETS.exp, input.exp, false);
  v.setBigUint64(OFFSETS.policy_epoch, input.policy_epoch, false);
  out.set(input.aud_hash, OFFSETS.aud_hash);
  const jtiBytes = new TextEncoder().encode(input.jti);
  if (jtiBytes.length !== 22) throw new Error('jti MUST be 22 UTF-8 bytes');
  out.set(jtiBytes, OFFSETS.jti);
  // jti_pad already zero
  return out;
}

export interface AssembleTokenInput extends AssembleInput {
  readonly R_tok: Uint8Array;
  readonly GCM_tag: Uint8Array;
  readonly sigma_tok: Uint8Array;
  readonly CT_body: Uint8Array;
}

/** Assemble the complete token (184-byte prefix + body). */
export function assembleToken(input: AssembleTokenInput): Uint8Array {
  const aad = buildAad(input);
  const out = new Uint8Array(HEADER_LENGTH + input.CT_body.length);
  out.set(aad, 0);
  out.set(input.R_tok, OFFSETS.R_tok);
  out.set(input.GCM_tag, OFFSETS.GCM_tag);
  out.set(input.sigma_tok, OFFSETS.sigma_tok);
  out.set(input.CT_body, HEADER_LENGTH);
  return out;
}
