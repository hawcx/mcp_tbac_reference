// SPDX-License-Identifier: Apache-2.0
//
// Scope JSON schema + validation. `resource` is REQUIRED with explicit `"*"`
// for tool-wide per §3.2 (normative since r40). `null` / absent is a denial;
// the transition-window fallback for r39-version tokens lives in
// `r39_fallback.ts` and is gated on the peer advertising r39. r41 is
// wire-compatible with r40 and uses the same scope-JSON validation.

import { denial, DENIAL_CODES, FAILED_CHECKS, type Denial } from '../denial/codes.js';

/** §3.3 constraints object. `allowed_parameters` modelled as opaque map. */
export interface Constraints {
  readonly max_rows?: number;
  readonly max_calls?: number;
  readonly time_window_sec?: number;
  readonly require_channel_encryption?: boolean;
  readonly data_classification?: string;
  readonly allowed_parameters?: Record<string, string>;
  readonly [k: string]: unknown;
}

/** §3.2 scope JSON. `resource` REQUIRED since r40. */
export interface ScopeJson {
  readonly iss: string;
  readonly sub: string;
  readonly agent_instance_id: string;
  readonly tool: string;
  readonly action: string | readonly string[];
  readonly aud: string;
  readonly resource: string;
  readonly constraints?: Constraints;
  readonly delegation_depth: number;
  readonly parent_token_hash?: string;
  readonly require_pop?: boolean;
  readonly org_id: string;
  readonly trust_level: 0 | 1 | 2 | 3;
  readonly human_confirmed_at: number;
  readonly approval_digest?: string;
  readonly purpose?: string;
  readonly txn_id?: string;
  readonly user_raw_intent?: string;
  readonly intent_hash?: string;
}

/** Header fields that MUST NOT appear in scope JSON (§3.2). */
export const RESERVED_HEADER_FIELDS = ['jti', 'aud_hash', 'iat', 'exp', 'policy_epoch'] as const;

/** §A.3 constraint field names known to this implementation. */
export const KNOWN_CONSTRAINT_KEYS: ReadonlySet<string> = new Set([
  'max_rows',
  'max_calls',
  'time_window_sec',
  'require_channel_encryption',
  'data_classification',
  'allowed_parameters',
]);

export interface ValidateOptions {
  /**
   * Peer-advertised capability version. When set to the literal r39 value,
   * and `acceptR39Tokens` is enabled, an absent `resource` is coerced to
   * `"*"` with a deprecation warning (emitted by the caller, not here).
   */
  readonly peerVersion?: string;
  readonly acceptR39Tokens?: boolean;
}

export interface ValidateOutcome {
  readonly scope: ScopeJson;
  /** True iff the r39 fallback coercion was exercised. */
  readonly r39FallbackUsed: boolean;
}

const R39_VERSION = '2026-04-17-r39';

/**
 * Validate and normalize a parsed scope JSON object against §3.2. The
 * return value either carries a normalized {@link ScopeJson} or a denial.
 */
export function validateScope(
  raw: unknown,
  opts: ValidateOptions = {},
): { ok: true; value: ValidateOutcome } | { ok: false; denial: Denial } {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'scope JSON is not an object',
      ),
    };
  }
  const obj = raw as Record<string, unknown>;

  for (const reserved of RESERVED_HEADER_FIELDS) {
    if (reserved in obj) {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.MALFORMED_TOKEN,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          `scope JSON may not contain reserved header field "${reserved}"`,
        ),
      };
    }
  }

  for (const req of [
    'iss',
    'sub',
    'agent_instance_id',
    'tool',
    'aud',
    'org_id',
  ] as const) {
    if (typeof obj[req] !== 'string' || obj[req] === '') {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.SCOPE_FIELD_MISSING,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          `scope field "${req}" missing or not a non-empty string`,
        ),
      };
    }
  }

  const action = obj['action'];
  if (typeof action !== 'string' && !(Array.isArray(action) && action.every((x) => typeof x === 'string'))) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'action must be a string or string[]',
      ),
    };
  }

  if (typeof obj['delegation_depth'] !== 'number' || !Number.isInteger(obj['delegation_depth']) || (obj['delegation_depth'] as number) < 0) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'delegation_depth must be a non-negative integer',
      ),
    };
  }

  const tl = obj['trust_level'];
  if (tl !== 0 && tl !== 1 && tl !== 2 && tl !== 3) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'trust_level must be 0, 1, 2, or 3',
      ),
    };
  }

  if (typeof obj['human_confirmed_at'] !== 'number' || !Number.isInteger(obj['human_confirmed_at'])) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'human_confirmed_at must be an integer',
      ),
    };
  }
  const hca = obj['human_confirmed_at'] as number;
  if ((tl === 3 && hca === 0) || (tl !== 3 && hca !== 0)) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        tl === 3
          ? 'trust_level=3 requires non-zero human_confirmed_at'
          : 'human_confirmed_at MUST be 0 for trust_level in {0,1,2}',
      ),
    };
  }

  // §3.2 resource validation with version-gated r39 fallback (r40/r41)
  let resource: string;
  let r39FallbackUsed = false;
  const rawResource = obj['resource'];
  if (rawResource === undefined || rawResource === null) {
    const isR39Peer = opts.peerVersion === R39_VERSION;
    if (opts.acceptR39Tokens === true && isR39Peer) {
      resource = '*';
      r39FallbackUsed = true;
    } else {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.SCOPE_FIELD_MISSING,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          'resource is REQUIRED in scope JSON (§3.2, since r40)',
        ),
      };
    }
  } else if (typeof rawResource !== 'string' || rawResource === '') {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'resource must be a non-empty string',
      ),
    };
  } else {
    resource = rawResource;
  }

  // §3.2 conditional fields for T3 and intent-bearing tokens.
  // approval_digest: REQUIRED and 64 lowercase hex when trust_level=3;
  //                  MUST be absent when trust_level ∈ {0,1,2}.
  const rawApprovalDigest = obj['approval_digest'];
  if (tl === 3) {
    if (typeof rawApprovalDigest !== 'string' || !isLowerHex(rawApprovalDigest, 64)) {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.SCOPE_FIELD_MISSING,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          'trust_level=3 requires approval_digest as 64 lowercase hex chars (§3.2)',
        ),
      };
    }
  } else if (rawApprovalDigest !== undefined && rawApprovalDigest !== null) {
    return {
      ok: false,
      denial: denial(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'approval_digest MUST be absent when trust_level ∈ {0,1,2} (§3.2)',
      ),
    };
  }

  // user_raw_intent ↔ intent_hash coupling. When either is present both MUST
  // be present; intent_hash is SHA-256 hex (64 lowercase chars); user_raw_intent
  // MUST be ≤ 4096 bytes (§3.2).
  const rawIntent = obj['user_raw_intent'];
  const rawIntentHash = obj['intent_hash'];
  if (rawIntent !== undefined || rawIntentHash !== undefined) {
    if (typeof rawIntent !== 'string' || typeof rawIntentHash !== 'string') {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.SCOPE_FIELD_MISSING,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          'user_raw_intent and intent_hash MUST both be present or both absent (§3.2)',
        ),
      };
    }
    if (new TextEncoder().encode(rawIntent).length > 4096) {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.INTENT_PAYLOAD_TOO_LARGE,
          FAILED_CHECKS.INTENT_VALIDATION,
          'user_raw_intent exceeds 4096 UTF-8 bytes (§3.2)',
        ),
      };
    }
    if (!isLowerHex(rawIntentHash, 64)) {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.SCOPE_FIELD_MISSING,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          'intent_hash MUST be 64 lowercase hex chars (§3.2)',
        ),
      };
    }
  }

  // txn_id is a 16-byte CSPRNG value encoded as 32 lowercase hex chars (§3.2).
  const rawTxn = obj['txn_id'];
  if (rawTxn !== undefined && rawTxn !== null) {
    if (typeof rawTxn !== 'string' || !isLowerHex(rawTxn, 32)) {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.SCOPE_FIELD_MISSING,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          'txn_id MUST be 32 lowercase hex chars (16-byte CSPRNG value, §3.2)',
        ),
      };
    }
  }

  // §3.3: Unknown constraint fields MUST cause rejection unless `x-`-prefixed.
  // Known-field types MUST also match; silently dropping a wrong-typed field
  // at canonicalization would let a caller believe it minted a constrained
  // token while the encoder omitted the constraint.
  if (typeof obj['constraints'] === 'object' && obj['constraints'] !== null) {
    const cns = obj['constraints'] as Record<string, unknown>;
    for (const k of Object.keys(cns)) {
      if (!KNOWN_CONSTRAINT_KEYS.has(k) && !k.startsWith('x-')) {
        return {
          ok: false,
          denial: denial(
            DENIAL_CODES.MALFORMED_TOKEN,
            FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
            `unknown constraint field "${k}" — MUST be prefixed with "x-" for vendor extensions (§3.3)`,
          ),
        };
      }
    }
    const typeCheck = validateConstraintTypes(cns);
    if (typeCheck !== null) return { ok: false, denial: typeCheck };
  }

  const scope: ScopeJson = {
    iss: obj['iss'] as string,
    sub: obj['sub'] as string,
    agent_instance_id: obj['agent_instance_id'] as string,
    tool: obj['tool'] as string,
    action: action as string | readonly string[],
    aud: obj['aud'] as string,
    resource,
    delegation_depth: obj['delegation_depth'] as number,
    org_id: obj['org_id'] as string,
    trust_level: tl as 0 | 1 | 2 | 3,
    human_confirmed_at: hca,
    ...(typeof obj['constraints'] === 'object' && obj['constraints'] !== null
      ? { constraints: obj['constraints'] as Constraints }
      : {}),
    ...(typeof obj['parent_token_hash'] === 'string'
      ? { parent_token_hash: obj['parent_token_hash'] as string }
      : {}),
    ...(typeof obj['require_pop'] === 'boolean'
      ? { require_pop: obj['require_pop'] as boolean }
      : {}),
    ...(typeof obj['approval_digest'] === 'string'
      ? { approval_digest: obj['approval_digest'] as string }
      : {}),
    ...(typeof obj['purpose'] === 'string' ? { purpose: obj['purpose'] as string } : {}),
    ...(typeof obj['txn_id'] === 'string' ? { txn_id: obj['txn_id'] as string } : {}),
    ...(typeof obj['user_raw_intent'] === 'string'
      ? { user_raw_intent: obj['user_raw_intent'] as string }
      : {}),
    ...(typeof obj['intent_hash'] === 'string'
      ? { intent_hash: obj['intent_hash'] as string }
      : {}),
  };

  return { ok: true, value: { scope, r39FallbackUsed } };
}

function isLowerHex(s: string, expectedLen: number): boolean {
  if (s.length !== expectedLen) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66); // 0-9 or a-f
    if (!ok) return false;
  }
  return true;
}

function isNonNegativeInteger(x: unknown): x is number {
  return typeof x === 'number' && Number.isInteger(x) && x >= 0;
}

/**
 * §3.3 constraint type validation. Returns a Denial on the first type
 * mismatch, or null when every present known field has the correct type.
 * Vendor-extension (`x-`) keys are not type-checked here.
 */
function validateConstraintTypes(c: Record<string, unknown>): Denial | null {
  const typeFail = (msg: string): Denial =>
    denial(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.TBAC_SCOPE_EVALUATION, msg);

  if ('max_rows' in c && !isNonNegativeInteger(c['max_rows'])) {
    return typeFail('constraints.max_rows MUST be a non-negative integer (§3.3)');
  }
  if ('max_calls' in c && !isNonNegativeInteger(c['max_calls'])) {
    return typeFail('constraints.max_calls MUST be a non-negative integer (§3.3)');
  }
  if ('time_window_sec' in c && !isNonNegativeInteger(c['time_window_sec'])) {
    return typeFail('constraints.time_window_sec MUST be a non-negative integer (§3.3)');
  }
  if ('require_channel_encryption' in c && typeof c['require_channel_encryption'] !== 'boolean') {
    return typeFail('constraints.require_channel_encryption MUST be a boolean (§3.3)');
  }
  if ('data_classification' in c && typeof c['data_classification'] !== 'string') {
    return typeFail('constraints.data_classification MUST be a string (§3.3)');
  }
  if ('allowed_parameters' in c) {
    const ap = c['allowed_parameters'];
    if (ap === null || typeof ap !== 'object' || Array.isArray(ap)) {
      return typeFail('constraints.allowed_parameters MUST be a JSON object (§3.3)');
    }
    for (const [k, v] of Object.entries(ap as Record<string, unknown>)) {
      if (typeof v !== 'string') {
        return typeFail(`constraints.allowed_parameters["${k}"] MUST be a string pattern (§3.3)`);
      }
    }
  }
  return null;
}
