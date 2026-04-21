// SPDX-License-Identifier: Apache-2.0
//
// TLV canonicalization for scope JSON per §3.4 and Appendix A. Fields are
// serialized in strictly ascending numeric type-code order (§A.4). The
// output bytes are the input to priv_sig (§3.4) and to the `parent_token_hash`
// digest used in delegation checks (§8).
//
// §A.4 clause 4 (r41) partitions the tag space: normative range 0x01-0x7F
// MUST be strict-rejected when unknown; vendor range 0x80-0xFE MUST be
// silent-skipped when unknown; tag 0xFF is reserved and MUST be rejected.
// The partition is enforced at every nesting level (scope, constraints,
// allowed_parameters inner entries) by `enforceTagPartition` below.

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

export function canonicalizeConstraints(c: Constraints): Uint8Array {
  // §3.3: Unknown constraint fields MUST cause rejection unless `x-`-prefixed.
  // Known fields MUST also carry the right type — silently dropping a wrong-
  // typed value would let a caller believe it minted a constrained token
  // while the encoder omitted the constraint. Throws on either violation so
  // a well-behaved TQS cannot accidentally emit an under-constrained token.
  for (const k of Object.keys(c)) {
    if (!KNOWN_CONSTRAINT_KEY_NAMES.has(k) && !k.startsWith('x-')) {
      throw new Error(
        `unknown constraint field "${k}" — MUST be prefixed with "x-" for vendor extensions (§3.3)`,
      );
    }
  }
  const f: TlvField[] = [];
  if (c.max_rows !== undefined) {
    if (!Number.isInteger(c.max_rows) || (c.max_rows as number) < 0) {
      throw new Error('constraints.max_rows MUST be a non-negative integer (§3.3)');
    }
    f.push({ tag: CONSTRAINT_TAGS.max_rows, value: u64be(c.max_rows as number) });
  }
  if (c.max_calls !== undefined) {
    if (!Number.isInteger(c.max_calls) || (c.max_calls as number) < 0) {
      throw new Error('constraints.max_calls MUST be a non-negative integer (§3.3)');
    }
    f.push({ tag: CONSTRAINT_TAGS.max_calls, value: u64be(c.max_calls as number) });
  }
  if (c.time_window_sec !== undefined) {
    if (!Number.isInteger(c.time_window_sec) || (c.time_window_sec as number) < 0) {
      throw new Error('constraints.time_window_sec MUST be a non-negative integer (§3.3)');
    }
    f.push({ tag: CONSTRAINT_TAGS.time_window_sec, value: u64be(c.time_window_sec as number) });
  }
  if (c.require_channel_encryption !== undefined) {
    if (typeof c.require_channel_encryption !== 'boolean') {
      throw new Error('constraints.require_channel_encryption MUST be a boolean (§3.3)');
    }
    f.push({
      tag: CONSTRAINT_TAGS.require_channel_encryption,
      value: boolByte(c.require_channel_encryption),
    });
  }
  if (c.data_classification !== undefined) {
    if (typeof c.data_classification !== 'string') {
      throw new Error('constraints.data_classification MUST be a string (§3.3)');
    }
    f.push({ tag: CONSTRAINT_TAGS.data_classification, value: utf8.encode(c.data_classification) });
  }
  if (c.allowed_parameters !== undefined && c.allowed_parameters !== null) {
    if (typeof c.allowed_parameters !== 'object' || Array.isArray(c.allowed_parameters)) {
      throw new Error('constraints.allowed_parameters MUST be a JSON object (§3.3)');
    }
    for (const [k, v] of Object.entries(c.allowed_parameters as Record<string, unknown>)) {
      if (typeof v !== 'string') {
        throw new Error(
          `constraints.allowed_parameters["${k}"] MUST be a string pattern (§3.3)`,
        );
      }
    }
    f.push({
      tag: CONSTRAINT_TAGS.allowed_parameters,
      value: encodeAllowedParameters(c.allowed_parameters),
    });
  }
  f.sort((a, b) => a.tag - b.tag);
  return encodeTlv(f);
}

/**
 * Encode `allowed_parameters` per SEP §A.3 and §A.3.1 (r41). Each entry is
 * a pair of inner TLV fields — inner tag 0x01 (key, UTF-8) and inner tag
 * 0x02 (pattern, UTF-8, literal wildcards escaped per §3.3). Entries are
 * emitted in strictly ascending UTF-8 byte-order of their keys. An empty
 * object encodes as an outer TLV with length 0 (see §A.3.1 "Empty object"
 * — omission and empty-object carry different semantics; the producer-side
 * callers decide which).
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
    const keyField = readOneTlv(bytes, off);
    if (keyField === null) break;
    off = keyField.nextOff;
    // §A.4 clause 4 partition enforced at the inner level too: the key slot
    // MUST carry tag 0x01 exactly; any other normative-range tag or 0xFF is
    // a hard reject. Vendor-range tags (0x80-0xFE) are not permitted as inner
    // slots because §A.3.1 defines the entry layout as a fixed pair.
    if (keyField.tag !== AP_KEY_TAG) {
      throw new Error(
        `allowed_parameters inner entry: expected key tag 0x01, got 0x${keyField.tag.toString(16).padStart(2, '0')}`,
      );
    }
    const patField = readOneTlv(bytes, off);
    if (patField === null) {
      throw new Error('allowed_parameters inner entry: truncated after key, pattern missing');
    }
    off = patField.nextOff;
    if (patField.tag !== AP_PATTERN_TAG) {
      throw new Error(
        `allowed_parameters inner entry: expected pattern tag 0x02, got 0x${patField.tag.toString(16).padStart(2, '0')}`,
      );
    }
    const key = td.decode(keyField.value);
    // §A.3.1 duplicate-key rejection: JSON already forbids duplicates, so
    // this is defense against malformed producer input that a tolerant JSON
    // parser might have coalesced.
    if (Object.prototype.hasOwnProperty.call(out, key)) {
      throw new Error(
        `allowed_parameters contains duplicate key "${key}" (§A.3.1)`,
      );
    }
    out[key] = td.decode(patField.value);
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

const KNOWN_SCOPE_TAGS: ReadonlySet<number> = new Set(Object.values(SCOPE_TAGS));
const KNOWN_CONSTRAINT_TAGS: ReadonlySet<number> = new Set(Object.values(CONSTRAINT_TAGS));

/**
 * §A.4 clause 4 partition. `known` is the set of tags the SEP defines at this
 * nesting level. Throws on an unknown normative-range tag (0x01-0x7F) or on
 * the reserved 0xFF; returns `false` to signal the caller to silently skip
 * vendor-range (0x80-0xFE) tags that are unrecognized at this level.
 */
function acceptOrRejectTag(tag: number, known: ReadonlySet<number>, site: string): boolean {
  if (known.has(tag)) return true;
  if (tag === 0xff) {
    throw new Error(`${site}: tag 0xFF is reserved (§A.4)`);
  }
  if (tag < 0x80) {
    throw new Error(
      `${site}: unknown normative-range tag 0x${tag.toString(16).padStart(2, '0')} MUST be rejected (§A.4)`,
    );
  }
  // Vendor range (0x80-0xFE) unknown → silent-skip per §A.4.
  return false;
}

/** Decode TLV-canonical scope bytes back into a ScopeJson. */
export function decanonicalizeScope(tlv: Uint8Array): ScopeJson {
  const fields = decodeTlv(tlv);
  const byTag = new Map<number, Uint8Array[]>();
  for (const f of fields) {
    if (!acceptOrRejectTag(f.tag, KNOWN_SCOPE_TAGS, 'scope TLV')) continue;
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
    // §A.4 clause 4 partition: strict-reject unknown normative-range (0x01-
    // 0x7F), silent-skip unknown vendor-range (0x80-0xFE), reject reserved
    // 0xFF. §3.3 additionally requires rejection of unknown scope-level JSON
    // constraint keys, which is enforced at `canonicalizeConstraints` and
    // `validateScope`; this path handles the TLV-decode side.
    if (!acceptOrRejectTag(f.tag, KNOWN_CONSTRAINT_TAGS, 'constraints TLV')) continue;
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
