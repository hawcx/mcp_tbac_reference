// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { embedToken, extractToken } from './embed.js';

describe('_meta token embed / extract', () => {
  it('round-trips', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 254, 255]);
    const meta = embedToken(bytes);
    const recovered = extractToken(meta);
    expect(recovered).not.toBeNull();
    expect([...recovered!]).toEqual([...bytes]);
  });

  it('returns null for non-TBAC meta', () => {
    expect(extractToken(null)).toBeNull();
    expect(extractToken({})).toBeNull();
    expect(extractToken({ 'io.modelcontextprotocol/tbac': {} })).toBeNull();
    expect(
      extractToken({ 'io.modelcontextprotocol/tbac': { token: 42 } }),
    ).toBeNull();
  });

  it('format field is always "opaque"', () => {
    const meta = embedToken(new Uint8Array([0]));
    expect(
      (meta['io.modelcontextprotocol/tbac'] as { format: string }).format,
    ).toBe('opaque');
  });
});
