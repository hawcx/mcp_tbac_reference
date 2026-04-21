// SPDX-License-Identifier: Apache-2.0
//
// AES-256-GCM wrapper. SEP `alg_id = 0x01` uses 96-bit IVs and a 128-bit
// authentication tag. Authentication failures throw `AeadAuthError` — the
// caller maps this to denial code DECRYPTION_FAILED / failed_check
// AEAD_DECRYPTION. Do not catch-and-return-null at the wrapper layer.

import { gcm } from '@noble/ciphers/aes';

export class AeadAuthError extends Error {
  constructor(cause?: unknown) {
    super('AES-256-GCM authentication failed');
    this.name = 'AeadAuthError';
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

export interface AeadEncryptInput {
  readonly key: Uint8Array; // 32 bytes
  readonly iv: Uint8Array; // 12 bytes
  readonly aad: Uint8Array;
  readonly plaintext: Uint8Array;
}

export interface AeadEncryptOutput {
  /** Ciphertext WITHOUT the tag. */
  readonly ciphertext: Uint8Array;
  /** 16-byte authentication tag. */
  readonly tag: Uint8Array;
}

/** Encrypts and separates `(ct, tag)` so the wire layer can place the tag at offset 136. */
export function aesGcmEncrypt(input: AeadEncryptInput): AeadEncryptOutput {
  if (input.key.length !== 32) throw new Error('AES-256-GCM key must be 32 bytes');
  if (input.iv.length !== 12) throw new Error('GCM IV must be 12 bytes');
  const full = gcm(input.key, input.iv, input.aad).encrypt(input.plaintext);
  const ct = full.slice(0, full.length - 16);
  const tag = full.slice(full.length - 16);
  return { ciphertext: ct, tag };
}

export interface AeadDecryptInput {
  readonly key: Uint8Array;
  readonly iv: Uint8Array;
  readonly aad: Uint8Array;
  readonly ciphertext: Uint8Array; // WITHOUT tag
  readonly tag: Uint8Array; // 16 bytes
}

/** Decrypts `(ct, tag)` separately; throws {@link AeadAuthError} on auth failure. */
export function aesGcmDecrypt(input: AeadDecryptInput): Uint8Array {
  if (input.key.length !== 32) throw new Error('AES-256-GCM key must be 32 bytes');
  if (input.iv.length !== 12) throw new Error('GCM IV must be 12 bytes');
  if (input.tag.length !== 16) throw new Error('GCM tag must be 16 bytes');
  const combined = new Uint8Array(input.ciphertext.length + 16);
  combined.set(input.ciphertext, 0);
  combined.set(input.tag, input.ciphertext.length);
  try {
    return gcm(input.key, input.iv, input.aad).decrypt(combined);
  } catch (e) {
    throw new AeadAuthError(e);
  }
}
