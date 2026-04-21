// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { embedToken, extractTbacMeta, extractToken } from './embed.js';

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

describe('extractTbacMeta — enc-presence bit', () => {
  const tokenBytes = new Uint8Array([9, 8, 7]);
  it('reports hasEncryption=false when enc is absent', () => {
    const meta = embedToken(tokenBytes);
    const x = extractTbacMeta(meta);
    expect(x).not.toBeNull();
    expect(x!.hasEncryption).toBe(false);
  });

  it('reports hasEncryption=true when enc is present', () => {
    const meta = embedToken(tokenBytes);
    (meta['io.modelcontextprotocol/tbac'] as unknown as Record<string, unknown>)['enc'] = {
      ct: 'b64url-opaque',
    };
    const x = extractTbacMeta(meta);
    expect(x).not.toBeNull();
    expect(x!.hasEncryption).toBe(true);
  });

  it('treats enc=null as absent (not a truthy envelope)', () => {
    const meta = embedToken(tokenBytes);
    (meta['io.modelcontextprotocol/tbac'] as unknown as Record<string, unknown>)['enc'] = null;
    const x = extractTbacMeta(meta);
    expect(x).not.toBeNull();
    expect(x!.hasEncryption).toBe(false);
  });

  it('returns null for malformed meta (parity with extractToken)', () => {
    expect(extractTbacMeta(null)).toBeNull();
    expect(extractTbacMeta({})).toBeNull();
    expect(extractTbacMeta({ 'io.modelcontextprotocol/tbac': { token: 42 } })).toBeNull();
  });
});
