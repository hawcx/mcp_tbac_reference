// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { AeadAuthError, aesGcmDecrypt, aesGcmEncrypt } from './aead.js';
import { constantTimeEqual, hmacSha256 } from './hmac.js';

describe('AES-256-GCM wrapper', () => {
  const key = new Uint8Array(32).fill(0x11);
  const iv = new Uint8Array(12).fill(0x22);
  const aad = new Uint8Array([1, 2, 3, 4]);
  const plaintext = new Uint8Array([10, 20, 30, 40, 50]);

  it('encrypt produces 16-byte tag', () => {
    const { ciphertext, tag } = aesGcmEncrypt({ key, iv, aad, plaintext });
    expect(tag.length).toBe(16);
    expect(ciphertext.length).toBe(plaintext.length);
  });

  it('round-trips plaintext', () => {
    const { ciphertext, tag } = aesGcmEncrypt({ key, iv, aad, plaintext });
    const recovered = aesGcmDecrypt({ key, iv, aad, ciphertext, tag });
    expect([...recovered]).toEqual([...plaintext]);
  });

  it('throws AeadAuthError on tag tamper', () => {
    const { ciphertext, tag } = aesGcmEncrypt({ key, iv, aad, plaintext });
    const tampered = new Uint8Array(tag);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff;
    expect(() => aesGcmDecrypt({ key, iv, aad, ciphertext, tag: tampered })).toThrow(
      AeadAuthError,
    );
  });

  it('throws AeadAuthError on AAD tamper', () => {
    const { ciphertext, tag } = aesGcmEncrypt({ key, iv, aad, plaintext });
    expect(() =>
      aesGcmDecrypt({ key, iv, aad: new Uint8Array([9, 9, 9, 9]), ciphertext, tag }),
    ).toThrow(AeadAuthError);
  });

  it('rejects wrong key length', () => {
    expect(() => aesGcmEncrypt({ key: new Uint8Array(16), iv, aad, plaintext })).toThrow();
  });
  it('rejects wrong IV length', () => {
    expect(() =>
      aesGcmEncrypt({ key, iv: new Uint8Array(11), aad, plaintext }),
    ).toThrow();
  });
});

describe('HMAC-SHA-256 and constant-time equal', () => {
  it('produces a 32-byte tag', () => {
    const tag = hmacSha256(new Uint8Array(32).fill(0xaa), new Uint8Array([1, 2, 3]));
    expect(tag.length).toBe(32);
  });

  it('constant-time equality returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('constant-time equality returns false for different arrays', () => {
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([2]))).toBe(false);
  });

  it('constant-time equality returns false for different lengths', () => {
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
});
