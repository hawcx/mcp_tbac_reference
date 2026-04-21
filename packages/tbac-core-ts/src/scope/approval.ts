// SPDX-License-Identifier: Apache-2.0
//
// §3.2 `approval_digest` computation. The spec defines the digest as
// "SHA-256 over the canonical approval tuple (`agent_instance_id`, `tool`,
// `action`, `resource`, `constraints`, `purpose`, `org_id`, `txn_id`,
// `intent_hash`)" but does not prescribe the canonicalization byte-exactly.
//
// [I] Implementation choice (to be confirmed/overridden in a future SEP
// revision): TLV-encode the nine named fields using the same type-code
// assignments as `canonicalizeScope` (§A.2), emitted in strictly ascending
// tag order, then SHA-256 the resulting bytes. This reuses the canonical
// form the spec already defines for scope-level `priv_sig`, restricted to
// the nine-field subset named by §3.2.
//
// Fields that are absent in the scope are omitted from the tuple TLV. For
// T3 the minting side and the RS side MUST produce byte-identical tuples
// for the same scope; this file is the single source of truth for that
// computation.

import { sha256 } from '@noble/hashes/sha2';
import { encodeTlv, type TlvField } from '../wire/tlv.js';
import type { ScopeJson } from './schema.js';
import { SCOPE_TAGS, canonicalizeConstraints } from './canonical.js';

const utf8 = new TextEncoder();

/**
 * Compute the canonical approval-tuple digest for T3 scope. Returns the
 * 32-byte SHA-256. Callers that need the hex form should use {@link approvalDigestHex}.
 */
export function computeApprovalDigest(scope: ScopeJson): Uint8Array {
  const fields: TlvField[] = [];

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

  fields.push({ tag: SCOPE_TAGS.org_id, value: utf8.encode(scope.org_id) });

  if (scope.purpose !== undefined) {
    fields.push({ tag: SCOPE_TAGS.purpose, value: utf8.encode(scope.purpose) });
  }
  if (scope.txn_id !== undefined) {
    fields.push({ tag: SCOPE_TAGS.txn_id, value: hexToBytes(scope.txn_id) });
  }
  if (scope.intent_hash !== undefined) {
    fields.push({ tag: SCOPE_TAGS.intent_hash, value: utf8.encode(scope.intent_hash) });
  }

  fields.sort((a, b) => a.tag - b.tag);
  return sha256(encodeTlv(fields));
}

/** Hex-encode the approval digest as 64 lowercase characters. */
export function approvalDigestHex(scope: ScopeJson): string {
  return bytesToHex(computeApprovalDigest(scope));
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('hex string must have even length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}
