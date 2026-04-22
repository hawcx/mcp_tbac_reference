// SPDX-License-Identifier: Apache-2.0
//
// §8.1 delegation attenuation check. This module is load-bearing: it runs
// at BOTH the TQS mint-gate (returning SCOPE_CEILING_EXCEEDED via the
// caller) and at the RS cascade Step 13 (returning TBAC_SCOPE_EVALUATION).
// Both layers are required for the r40 defense-in-depth property.
//
// Privilege fields checked (all MUST be monotonically non-increasing):
//   - tool           byte-equal (or child ⊆ parent action set)
//   - action         child set ⊆ parent set
//   - resource       isSubset(child.resource, parent.resource) under §8.1
//   - org_id         byte-equal (no cross-tenant delegation)
//   - delegation_depth  strictly decreasing
//   - trust_level    child ≤ parent
//   - constraints.max_rows, max_calls, time_window_sec: child ≤ parent where present
//   - require_channel_encryption: parent=true ⇒ child=true

import { denial, DENIAL_CODES, FAILED_CHECKS, type Denial } from '../denial/codes.js';
import type { ScopeJson } from './schema.js';
import { isSubset } from './glob.js';

export type AttenuationSite = 'mint' | 'rs';

function actionSet(a: string | readonly string[]): Set<string> {
  return new Set(typeof a === 'string' ? [a] : a);
}

function numLe(child: number | undefined, parent: number | undefined): boolean {
  if (parent === undefined) return true;
  if (child === undefined) return false;
  return child <= parent;
}

/**
 * Returns a Denial if the `child` scope widens any privilege relative to
 * `parent`, otherwise null. The denial code depends on `site`:
 *   - 'mint' — INSUFFICIENT_PRIVILEGE / TBAC_SCOPE_EVALUATION with
 *              internalTag 'r40.8.1.mint_gate.ScopeCeilingExceeded'
 *   - 'rs'   — INSUFFICIENT_PRIVILEGE / TBAC_SCOPE_EVALUATION with
 *              internalTag 'r40.8.1.rs_cascade.widening_attack'
 */
// SEP r41 §8.1: the subset predicate is NOT transitive across literal-
// prefix and wildcard rules. Always evaluate the (child, parent) pair
// directly; do not chain subset judgments.
export function checkAttenuation(
  child: ScopeJson,
  parent: ScopeJson,
  site: AttenuationSite,
): Denial | null {
  const fail = (detail: string, tag: string): Denial =>
    denial(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      detail,
      site === 'mint'
        ? `r40.8.1.mint_gate.${tag}`
        : `r40.8.1.rs_cascade.${tag}`,
    );

  if (child.tool !== parent.tool) {
    return fail(
      `child tool "${child.tool}" diverges from parent tool "${parent.tool}"`,
      'tool_mismatch',
    );
  }
  if (child.org_id !== parent.org_id) {
    return fail('org_id mismatch across delegation (cross-tenant forbidden)', 'org_id_mismatch');
  }
  if (child.delegation_depth >= parent.delegation_depth) {
    return fail(
      `delegation_depth must strictly decrease (child=${child.delegation_depth} parent=${parent.delegation_depth})`,
      'delegation_depth_not_decreasing',
    );
  }
  if (child.trust_level > parent.trust_level) {
    return fail(
      `child trust_level ${child.trust_level} exceeds parent ${parent.trust_level}`,
      'trust_level_widened',
    );
  }

  const cs = actionSet(child.action);
  const ps = actionSet(parent.action);
  for (const a of cs) {
    if (!ps.has(a)) {
      return fail(`child action "${a}" not in parent action set`, 'action_widened');
    }
  }

  // r40 §8.1 — the load-bearing resource check.
  if (!isSubset(child.resource, parent.resource)) {
    return fail(
      `child resource "${child.resource}" is not a subset of parent "${parent.resource}" (§8.1)`,
      'widening_attack',
    );
  }

  const cc = child.constraints;
  const pc = parent.constraints;
  if (pc !== undefined) {
    if (cc === undefined) {
      return fail('parent carries constraints, child omits them', 'constraints_missing');
    }
    if (!numLe(cc.max_rows, pc.max_rows)) {
      return fail(`child max_rows ${cc.max_rows} exceeds parent ${pc.max_rows}`, 'max_rows_widened');
    }
    if (!numLe(cc.max_calls, pc.max_calls)) {
      return fail(
        `child max_calls ${cc.max_calls} exceeds parent ${pc.max_calls}`,
        'max_calls_widened',
      );
    }
    if (!numLe(cc.time_window_sec, pc.time_window_sec)) {
      return fail(
        `child time_window_sec ${cc.time_window_sec} exceeds parent ${pc.time_window_sec}`,
        'time_window_widened',
      );
    }
    if (pc.require_channel_encryption === true && cc.require_channel_encryption !== true) {
      return fail(
        'parent requires channel encryption, child does not',
        'channel_enc_downgraded',
      );
    }
  }

  return null;
}
