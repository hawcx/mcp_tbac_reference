// SPDX-License-Identifier: Apache-2.0
//
// Helpers for the `_meta["io.modelcontextprotocol/tbac"]` envelope per
// SEP §10.1. The raw token bytes are base64url-encoded for transport in
// JSON-RPC. The optional `enc` field signals that the request payload
// arrived encrypted via the §9 bidirectional channel; it is opaque at
// this layer — decryption is a hook interface in the reference impl,
// but the presence-or-absence bit is what the §3.3
// `require_channel_encryption` gate needs.

import { EXTENSION_KEY } from 'tbac-core';

/**
 * Minimal typed shape of `_meta["io.modelcontextprotocol/tbac"]`. `enc` is
 * intentionally `unknown` because its payload schema (§10.2: `{ ct, ... }`)
 * is a hook interface in the reference implementation; consumers that wire
 * full channel encryption refine the type at the call site.
 */
export interface TbacMetaFields {
  readonly token: string; // base64url(opaque-token)
  readonly format: 'opaque';
  readonly enc?: unknown;
}

/** Result of a successful `extractTbacMeta`. */
export interface ExtractedMeta {
  readonly token: Uint8Array;
  /** True iff `_meta[...].enc` was present (non-null) on the wire. */
  readonly hasEncryption: boolean;
}

export function embedToken(tokenBytes: Uint8Array): { [key: string]: TbacMetaFields } {
  return {
    [EXTENSION_KEY]: {
      token: bytesToB64Url(tokenBytes),
      format: 'opaque',
    },
  };
}

/**
 * Parse `_meta` into the token bytes plus the encryption-present bit. The
 * presence-only surface on `enc` is deliberate: §3.3's
 * `require_channel_encryption` gate needs to know whether the caller sent
 * an `enc` envelope at all, not what's inside it.
 */
export function extractTbacMeta(meta: unknown): ExtractedMeta | null {
  if (meta === null || typeof meta !== 'object') return null;
  const section = (meta as Record<string, unknown>)[EXTENSION_KEY];
  if (section === null || typeof section !== 'object') return null;
  const token = (section as Record<string, unknown>)['token'];
  if (typeof token !== 'string') return null;
  const enc = (section as Record<string, unknown>)['enc'];
  return {
    token: b64urlToBytes(token),
    hasEncryption: enc !== undefined && enc !== null,
  };
}

/**
 * Legacy accessor that returns only the token bytes. New code should use
 * {@link extractTbacMeta} so the `enc` state can be plumbed to the
 * `require_channel_encryption` gate (§3.3).
 */
export function extractToken(meta: unknown): Uint8Array | null {
  const x = extractTbacMeta(meta);
  return x === null ? null : x.token;
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
