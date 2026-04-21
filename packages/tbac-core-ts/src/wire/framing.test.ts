// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  AAD_LENGTH,
  ALG_ID_0x01,
  HEADER_LENGTH,
  MSG_TYPE_ENTERPRISE,
  OFFSETS,
  REQUEST_FORMAT_DIRECT,
  TOKEN_VERSION_0x03,
  assembleToken,
  buildAad,
  parseTokenBytes,
} from './framing.js';

const jti = 'AAECAwQFBgcICQoLDA0ODw'; // §A.5.1 fixed input (22 b64url chars)

const header = {
  msg_type: MSG_TYPE_ENTERPRISE,
  request_format: REQUEST_FORMAT_DIRECT,
  session_id: 0xdeadbeefn,
  token_iv: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0x01]),
  iat: 1741305600n,
  exp: 1741305660n,
  policy_epoch: 1n,
  aud_hash: new Uint8Array(32).fill(0x77),
  jti,
};

describe('wire framing (§3.0)', () => {
  it('AAD length is exactly 104 bytes', () => {
    expect(AAD_LENGTH).toBe(104);
  });

  it('buildAad fills known offsets', () => {
    const aad = buildAad(header);
    expect(aad.length).toBe(AAD_LENGTH);
    expect(aad[OFFSETS.version]).toBe(TOKEN_VERSION_0x03);
    expect(aad[OFFSETS.alg_id]).toBe(ALG_ID_0x01);
    expect(aad[OFFSETS.msg_type]).toBe(MSG_TYPE_ENTERPRISE);
    expect(aad[OFFSETS.request_format]).toBe(REQUEST_FORMAT_DIRECT);
    // jti_pad
    expect(aad[OFFSETS.jti_pad]).toBe(0);
    expect(aad[OFFSETS.jti_pad + 1]).toBe(0);
  });

  it('rejects non-22-byte jti', () => {
    expect(() => buildAad({ ...header, jti: 'tooshort' })).toThrow();
  });

  it('assembleToken produces 184-byte prefix + body', () => {
    const R_tok = new Uint8Array(32).fill(0xaa);
    const GCM_tag = new Uint8Array(16).fill(0xbb);
    const sigma_tok = new Uint8Array(32).fill(0xcc);
    const CT_body = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const token = assembleToken({ ...header, R_tok, GCM_tag, sigma_tok, CT_body });
    expect(token.length).toBe(HEADER_LENGTH + 4);
    expect(token[OFFSETS.R_tok]).toBe(0xaa);
    expect(token[OFFSETS.GCM_tag]).toBe(0xbb);
    expect(token[OFFSETS.sigma_tok]).toBe(0xcc);
    expect(token[OFFSETS.CT_body]).toBe(0xde);
  });

  it('parse round-trips assembleToken', () => {
    const R_tok = new Uint8Array(32).fill(0xaa);
    const GCM_tag = new Uint8Array(16).fill(0xbb);
    const sigma_tok = new Uint8Array(32).fill(0xcc);
    const CT_body = new Uint8Array([1, 2, 3, 4, 5]);
    const token = assembleToken({ ...header, R_tok, GCM_tag, sigma_tok, CT_body });
    const parsed = parseTokenBytes(token);
    expect(parsed.header.version).toBe(0x03);
    expect(parsed.header.alg_id).toBe(0x01);
    expect(parsed.header.msg_type).toBe(0x03);
    expect(parsed.header.session_id).toBe(0xdeadbeefn);
    expect(parsed.header.jti).toBe(jti);
    expect(parsed.aad.length).toBe(104);
    expect([...parsed.ctBody]).toEqual([1, 2, 3, 4, 5]);
  });

  it('parse rejects short tokens', () => {
    expect(() => parseTokenBytes(new Uint8Array(100))).toThrow();
  });

  it('parse rejects non-zero jti_pad', () => {
    const R_tok = new Uint8Array(32);
    const GCM_tag = new Uint8Array(16);
    const sigma_tok = new Uint8Array(32);
    const CT_body = new Uint8Array();
    const token = assembleToken({ ...header, R_tok, GCM_tag, sigma_tok, CT_body });
    token[OFFSETS.jti_pad] = 0x01;
    expect(() => parseTokenBytes(token)).toThrow();
  });
});
