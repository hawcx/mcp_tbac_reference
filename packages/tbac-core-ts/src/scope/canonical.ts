// SPDX-License-Identifier: Apache-2.0
//
// TLV canonicalization for scope JSON per §3.4 and Appendix A. Fields are
// serialized in strictly ascending numeric type-code order (§A.4). The
// output bytes are the input to priv_sig (§3.4) and to the `parent_token_hash`
// digest used in delegation checks (§8).

import type { Constraints, ScopeJson } from './schema.js';
import { decodeTlv, encodeTlv, type TlvField } from '../wire/tlv.js';

/**
 * Scope field → type-code registry (§A.2). `action` can repeat with tag 0x05.
 * Constraints is encoded as a nested TLV under tag 0x07 (§A.3).
 */
export const SCOPE_TAGS = {
  iss: 0x01,
  sub: 0x02,
  agent_instance_id: 0x03,
  tool: 0x04,
  action: 0x05,
  resource: 0x06,
  constraints: 0x07,
  delegation_depth: 0x08,
  parent_token_hash: 0x09,
  require_pop: 0x0a,
  aud: 0x0b,
  org_id: 0x0c,
  trust_level: 0x0d,
  human_confirmed_at: 0x0e,
  approval_digest: 0x0f,
  purpose: 0x10,
  txn_id: 0x11,
  user_raw_intent: 0x12,
  intent_hash: 0x13,
} as const;

/** §A.3 constraint tags. */
export const CONSTRAINT_TAGS = {
  max_rows: 0x01,
  max_calls: 0x02,
  time_window_sec: 0x03,
  require_channel_encryption: 0x04,
  data_classification: 0x05,
  allowed_parameters: 0x06,
} as const;

const utf8 = new TextEncoder();

function u64be(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  v.setBigUint64(0, BigInt(n), false);
  return b;
}

function boolByte(b: boolean): Uint8Array {
  return new Uint8Array([b ? 0x01 : 0x00]);
}

/**
 * Canonically TLV-encode the scope JSON per §A.4. Fields are emitted in
 * strictly ascending tag order. The `action` field, when given a list, is
 * emitted as repeated TLV entries each tagged 0x05 preserving list order.
 */
export function canonicalizeScope(scope: ScopeJson): Uint8Array {
  const fields: TlvField[] = [];

  fields.push({ tag: SCOPE_TAGS.iss, value: utf8.encode(scope.iss) });
  fields.push({ tag: SCOPE_TAGS.sub, value: utf8.encode(scope.sub) });
  fields.push({ tag: SCOPE_TAGS.agent_instance_id, value: utf8.encode(scope.agent_instance_id) });
  fields.push({ tag: SCOPE_TAGS.tool, value: utf8.encode(scope.tool) });

  const actions = typeof scope.action === 'string' ? [scope.action] : scope.action;
  for (const a of actions) {
    fields.push({ tag: SCOPE_TAGS.action, value: utf8.encode(a) });
  }

  fields.push({ tag: SCOPE_TAGS.resource, value: utf8.encode(scope.resource) });

  if (scope.constraints !== undefined) {
    fields.push({
      tag: SCOPE_TAGS.constraints,
      value: canonicalizeConstraints(scope.constraints),
    });
  }

  fields.push({ tag: SCOPE_TAGS.delegation_depth, value: u64be(scope.delegation_depth) });

  if (scope.parent_token_hash !== undefined) {
    fields.push({
      tag: SCOPE_TAGS.parent_token_hash,
      value: b64urlDecode(scope.parent_token_hash),
    });
  }

  fields.push({ tag: SCOPE_TAGS.require_pop, value: boolByte(scope.require_pop === true) });
  fields.push({ tag: SCOPE_TAGS.aud, value: utf8.encode(scope.aud) });
  fields.push({ tag: SCOPE_TAGS.org_id, value: utf8.encode(scope.org_id) });
  fields.push({ tag: SCOPE_TAGS.trust_level, value: u64be(scope.trust_level) });
  fields.push({ tag: SCOPE_TAGS.human_confirmed_at, value: u64be(scope.human_confirmed_at) });

  if (scope.approval_digest !== undefined) {
    fields.push({ tag: SCOPE_TAGS.approval_digest, value: hexToBytes(scope.approval_digest) });
  }
  if (scope.purpose !== undefined) {
    fields.push({ tag: SCOPE_TAGS.purpose, value: utf8.encode(scope.purpose) });
  }
  if (scope.txn_id !== undefined) {
    fields.push({ tag: SCOPE_TAGS.txn_id, value: hexToBytes(scope.txn_id) });
  }
  if (scope.user_raw_intent !== undefined) {
    fields.push({ tag: SCOPE_TAGS.user_raw_intent, value: utf8.encode(scope.user_raw_intent) });
  }
  if (scope.intent_hash !== undefined) {
    fields.push({ tag: SCOPE_TAGS.intent_hash, value: utf8.encode(scope.intent_hash) });
  }

  // Stable sort is correct since tags are unique except for `action` (which
  // must preserve list order; sorted relative to other tags it stays together).
  fields.sort((a, b) => a.tag - b.tag);
  return encodeTlv(fields);
}

const KNOWN_CONSTRAINT_KEY_NAMES = new Set<string>([
  'max_rows',
  'max_calls',
  'time_window_sec',
  'require_channel_encryption',
  'data_classification',
  'allowed_parameters',
]);

function canonicalizeConstraints(c: Constraints): Uint8Array {
  // §3.3: Unknown constraint fields MUST cause rejection unless `x-`-prefixed.
  // Enforced at mint time so a well-behaved TQS cannot accidentally emit
  // a token with an unknown constraint key.
  for (const k of Object.keys(c)) {
    if (!KNOWN_CONSTRAINT_KEY_NAMES.has(k) && !k.startsWith('x-')) {
      throw new Error(
        `unknown constraint field "${k}" — MUST be prefixed with "x-" for vendor extensions (§3.3)`,
      );
    }
  }
  const f: TlvField[] = [];
  if (typeof c.max_rows === 'number') f.push({ tag: CONSTRAINT_TAGS.max_rows, value: u64be(c.max_rows) });
  if (typeof c.max_calls === 'number') f.push({ tag: CONSTRAINT_TAGS.max_calls, value: u64be(c.max_calls) });
  if (typeof c.time_window_sec === 'number')
    f.push({ tag: CONSTRAINT_TAGS.time_window_sec, value: u64be(c.time_window_sec) });
  if (typeof c.require_channel_encryption === 'boolean')
    f.push({ tag: CONSTRAINT_TAGS.require_channel_encryption, value: boolByte(c.require_channel_encryption) });
  if (typeof c.data_classification === 'string')
    f.push({ tag: CONSTRAINT_TAGS.data_classification, value: utf8.encode(c.data_classification) });
  if (c.allowed_parameters !== undefined && c.allowed_parameters !== null) {
    f.push({
      tag: CONSTRAINT_TAGS.allowed_parameters,
      value: encodeAllowedParameters(c.allowed_parameters),
    });
  }
  f.sort((a, b) => a.tag - b.tag);
  return encodeTlv(f);
}

/**
 * Encode `allowed_parameters` per SEP §A.3 ("ascending UTF-8 byte-order").
 * §A.3.1 is referenced but not present in r40 draft — [I] we encode each
 * entry as a pair of inner TLV fields (key tag 0x01, pattern tag 0x02) and
 * emit entries in ascending byte-order of their UTF-8-encoded keys. This
 * matches the spec's ordering rule; the inner sub-tag assignment is a
 * reasonable [I] choice flagged for confirmation in r41.
 */
const AP_KEY_TAG = 0x01;
const AP_PATTERN_TAG = 0x02;

function encodeAllowedParameters(map: Record<string, string>): Uint8Array {
  const entries = Object.entries(map).filter(
    ([, v]) => typeof v === 'string',
  );
  // Sort by ascending UTF-8 byte-order of keys (§A.3).
  const encoded = entries.map(
    ([k, v]) => [utf8.encode(k), utf8.encode(v)] as const,
  );
  encoded.sort(([ak], [bk]) => compareBytes(ak, bk));
  const parts: Uint8Array[] = [];
  for (const [k, v] of encoded) {
    parts.push(
      encodeTlv([
        { tag: AP_KEY_TAG, value: k },
        { tag: AP_PATTERN_TAG, value: v },
      ]),
    );
  }
  // Concatenate entries.
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i]! - b[i]!;
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return 0;
}

function decodeAllowedParameters(bytes: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {};
  // Walk the byte stream as a concatenation of inner TLV-pairs. Each entry's
  // outer TLV is itself two TLV fields; we decode them pairwise.
  let off = 0;
  const td = new TextDecoder('utf-8');
  while (off < bytes.length) {
    // Inner envelope: we wrote each entry as `encodeTlv([ key, pattern ])`
    // which yields a raw concatenation of [key_tlv][pattern_tlv] bytes. So
    // we read two TLV fields at each entry boundary.
    const keyField = readOneTlv(bytes, off);
    if (keyField === null) break;
    off = keyField.nextOff;
    const patField = readOneTlv(bytes, off);
    if (patField === null) break;
    off = patField.nextOff;
    if (keyField.tag !== AP_KEY_TAG || patField.tag !== AP_PATTERN_TAG) {
      throw new Error(
        `allowed_parameters entry has unexpected inner tags (${keyField.tag}, ${patField.tag})`,
      );
    }
    out[td.decode(keyField.value)] = td.decode(patField.value);
  }
  return out;
}

function readOneTlv(
  bytes: Uint8Array,
  off: number,
): { tag: number; value: Uint8Array; nextOff: number } | null {
  if (off + 2 > bytes.length) return null;
  const tag = bytes[off]!;
  const lenHi = bytes[off + 1]!;
  let len: number;
  let hdrLen: number;
  if ((lenHi & 0x80) === 0) {
    len = lenHi;
    hdrLen = 2;
  } else {
    if (off + 3 > bytes.length) throw new Error('truncated length byte');
    len = ((lenHi & 0x7f) << 8) | bytes[off + 2]!;
    hdrLen = 3;
  }
  if (off + hdrLen + len > bytes.length) throw new Error('truncated value');
  return {
    tag,
    value: bytes.slice(off + hdrLen, off + hdrLen + len),
    nextOff: off + hdrLen + len,
  };
}

/** Decode TLV-canonical scope bytes back into a ScopeJson. */
export function decanonicalizeScope(tlv: Uint8Array): ScopeJson {
  const fields = decodeTlv(tlv);
  const byTag = new Map<number, Uint8Array[]>();
  for (const f of fields) {
    const arr = byTag.get(f.tag) ?? [];
    arr.push(f.value);
    byTag.set(f.tag, arr);
  }
  const utf8d = new TextDecoder('utf-8');
  const getStr = (tag: number): string | undefined => {
    const v = byTag.get(tag);
    return v === undefined || v.length === 0 ? undefined : utf8d.decode(v[0]!);
  };
  const getU64 = (tag: number): number | undefined => {
    const v = byTag.get(tag);
    if (v === undefined || v.length === 0) return undefined;
    const dv = new DataView(v[0]!.buffer, v[0]!.byteOffset, v[0]!.byteLength);
    return Number(dv.getBigUint64(0, false));
  };
  const getBool = (tag: number): boolean | undefined => {
    const v = byTag.get(tag);
    if (v === undefined || v.length === 0) return undefined;
    return v[0]!.length > 0 && v[0]![0] !== 0;
  };

  // Actions may appear multiple times — preserve insertion order.
  const actionValues = byTag.get(SCOPE_TAGS.action) ?? [];
  const actions = actionValues.map((b) => utf8d.decode(b));
  const action: string | readonly string[] = actions.length === 1 ? actions[0]! : actions;

  let constraints: Constraints | undefined;
  const cBytes = byTag.get(SCOPE_TAGS.constraints);
  if (cBytes !== undefined && cBytes.length > 0) {
    constraints = decanonicalizeConstraints(cBytes[0]!);
  }

  const scope: ScopeJson = {
    iss: getStr(SCOPE_TAGS.iss)!,
    sub: getStr(SCOPE_TAGS.sub)!,
    agent_instance_id: getStr(SCOPE_TAGS.agent_instance_id)!,
    tool: getStr(SCOPE_TAGS.tool)!,
    action,
    aud: getStr(SCOPE_TAGS.aud)!,
    resource: getStr(SCOPE_TAGS.resource)!,
    delegation_depth: getU64(SCOPE_TAGS.delegation_depth) ?? 0,
    org_id: getStr(SCOPE_TAGS.org_id)!,
    trust_level: (getU64(SCOPE_TAGS.trust_level) ?? 0) as 0 | 1 | 2 | 3,
    human_confirmed_at: getU64(SCOPE_TAGS.human_confirmed_at) ?? 0,
    ...(constraints !== undefined ? { constraints } : {}),
    ...(byTag.has(SCOPE_TAGS.parent_token_hash)
      ? {
          parent_token_hash: bytesToB64Url(byTag.get(SCOPE_TAGS.parent_token_hash)![0]!),
        }
      : {}),
    ...(getBool(SCOPE_TAGS.require_pop) !== undefined
      ? { require_pop: getBool(SCOPE_TAGS.require_pop)! }
      : {}),
    ...(byTag.has(SCOPE_TAGS.approval_digest)
      ? { approval_digest: bytesToHex(byTag.get(SCOPE_TAGS.approval_digest)![0]!) }
      : {}),
    ...(getStr(SCOPE_TAGS.purpose) !== undefined ? { purpose: getStr(SCOPE_TAGS.purpose)! } : {}),
    ...(byTag.has(SCOPE_TAGS.txn_id)
      ? { txn_id: bytesToHex(byTag.get(SCOPE_TAGS.txn_id)![0]!) }
      : {}),
    ...(getStr(SCOPE_TAGS.user_raw_intent) !== undefined
      ? { user_raw_intent: getStr(SCOPE_TAGS.user_raw_intent)! }
      : {}),
    ...(getStr(SCOPE_TAGS.intent_hash) !== undefined
      ? { intent_hash: getStr(SCOPE_TAGS.intent_hash)! }
      : {}),
  };
  return scope;
}

function decanonicalizeConstraints(b: Uint8Array): Constraints {
  const fields = decodeTlv(b);
  const by = new Map<number, Uint8Array>();
  for (const f of fields) {
    // §3.3 defense-in-depth: reject unknown normative-range constraint tags
    // (0x07-0x7F). Vendor tags (0x80+) are treated as advisory per §A.1.
    const known =
      f.tag === CONSTRAINT_TAGS.max_rows ||
      f.tag === CONSTRAINT_TAGS.max_calls ||
      f.tag === CONSTRAINT_TAGS.time_window_sec ||
      f.tag === CONSTRAINT_TAGS.require_channel_encryption ||
      f.tag === CONSTRAINT_TAGS.data_classification ||
      f.tag === CONSTRAINT_TAGS.allowed_parameters;
    if (!known) {
      if (f.tag < 0x80) {
        throw new Error(
          `unknown constraint TLV tag 0x${f.tag.toString(16).padStart(2, '0')} in normative range — MUST be rejected per §3.3`,
        );
      }
      // Vendor tag — skip (advisory).
      continue;
    }
    by.set(f.tag, f.value);
  }
  const getU = (tag: number): number | undefined => {
    const v = by.get(tag);
    if (v === undefined) return undefined;
    const dv = new DataView(v.buffer, v.byteOffset, v.byteLength);
    return Number(dv.getBigUint64(0, false));
  };
  const out: Record<string, unknown> = {};
  const mr = getU(CONSTRAINT_TAGS.max_rows);
  if (mr !== undefined) out['max_rows'] = mr;
  const mc = getU(CONSTRAINT_TAGS.max_calls);
  if (mc !== undefined) out['max_calls'] = mc;
  const tw = getU(CONSTRAINT_TAGS.time_window_sec);
  if (tw !== undefined) out['time_window_sec'] = tw;
  const rce = by.get(CONSTRAINT_TAGS.require_channel_encryption);
  if (rce !== undefined) out['require_channel_encryption'] = rce.length > 0 && rce[0] !== 0;
  const dc = by.get(CONSTRAINT_TAGS.data_classification);
  if (dc !== undefined) out['data_classification'] = new TextDecoder().decode(dc);
  const ap = by.get(CONSTRAINT_TAGS.allowed_parameters);
  if (ap !== undefined) out['allowed_parameters'] = decodeAllowedParameters(ap);
  return out as Constraints;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function bytesToB64Url(b: Uint8Array): string {
  const bin = Array.from(b, (x) => String.fromCharCode(x)).join('');
  const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('hex string must have even length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
