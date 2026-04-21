// SPDX-License-Identifier: Apache-2.0
//
// Helpers for the `_meta["io.modelcontextprotocol/tbac"]` envelope per
// SEP §10.1. The raw token bytes are base64url-encoded for transport in
// JSON-RPC.

import { EXTENSION_KEY } from 'tbac-core';

export interface TbacMetaFields {
  readonly token: string; // base64url(opaque-token)
  readonly format: 'opaque';
}

export function embedToken(tokenBytes: Uint8Array): { [key: string]: TbacMetaFields } {
  return {
    [EXTENSION_KEY]: {
      token: bytesToB64Url(tokenBytes),
      format: 'opaque',
    },
  };
}

export function extractToken(meta: unknown): Uint8Array | null {
  if (meta === null || typeof meta !== 'object') return null;
  const section = (meta as Record<string, unknown>)[EXTENSION_KEY];
  if (section === null || typeof section !== 'object') return null;
  const token = (section as Record<string, unknown>)['token'];
  if (typeof token !== 'string') return null;
  return b64urlToBytes(token);
}

function bytesToB64Url(b: Uint8Array): string {
  const bin = Array.from(b, (x) => String.fromCharCode(x)).join('');
  const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
