// SPDX-License-Identifier: Apache-2.0
//
// The 17-step enterprise verification cascade from §4.3. Tiered for DoS
// resilience: header-only → cryptographic → defense-in-depth+TBAC. Each step
// either advances to the next or short-circuits with a Denial.
//
// Verify-then-decrypt ordering is load-bearing: Step 6 (Schnorr verify) MUST
// complete before Step 7 (AES-GCM decrypt). The meta-test in
// `src/cascade/verify.order.test.ts` detects any reversal.

import { sha256 } from '@noble/hashes/sha2';
import {
  AeadAuthError,
  aesGcmDecrypt,
  constantTimeEqual,
  hkdfSha256,
  hmacSha256,
  scalarMulBase,
  schnorrVerify,
  scalarReduce64,
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  DOMAIN_PRIV_SIG,
  ZERO_SALT_32,
  concat,
  u8,
  u64be,
} from '../crypto/index.js';
import {
  DENIAL_CODES,
  FAILED_CHECKS,
  denial,
  type Denial,
} from '../denial/codes.js';
import { canonicalizeScope, decanonicalizeScope } from '../scope/canonical.js';
import { checkAttenuation } from '../scope/attenuation.js';
import { isSubset } from '../scope/glob.js';
import { emitR39Fallback, defaultFallbackSink, type FallbackSink } from '../scope/r39_fallback.js';
import { validateScope, type ScopeJson } from '../scope/schema.js';
import { approvalDigestHex } from '../scope/approval.js';
import type {
  ConsumedTokenLog,
  PolicyTemplateStore,
  ReplayStore,
  SessionStore,
} from '../stores/interfaces.js';
import {
  ALG_ID_0x01,
  MSG_TYPE_ENTERPRISE,
  REQUEST_FORMAT_DIRECT,
  REQUEST_FORMAT_ENVELOPED,
  TOKEN_VERSION_0x03,
  parseTokenBytes,
} from '../wire/framing.js';
import { decodeTokenBody } from '../wire/token.js';

export interface VerifyInputs {
  readonly token: Uint8Array;
  readonly now: number; // Unix seconds — injected for determinism in tests
  readonly clockSkewSec?: number; // default 60
  /**
   * Maximum allowed `exp - iat` (token lifetime) in seconds. §3.0 row for `exp`
   * says `"exp - iat MUST NOT exceed max_ttl (default 60 s). Validated by RS
   * before decryption (Step 3)."` Default 60s.
   */
  readonly maxTtlSec?: number;
  readonly expectedAud: string;
  /** The RS's own identifier, compared byte-exact to scope.aud after decryption. */
  readonly rsIdentifier: string;
  readonly rsCurrentEpoch: bigint;
  /**
   * The MCP tool the RS is about to execute (i.e. `tools/call` `name`). The
   * cascade enforces byte-equality against `scope.tool` at Step 13 — a token
   * scoped to one tool MUST NOT authorize another, even if action/resource
   * happen to coincide. See SEP §3.2 and §4.3 Step 13.
   */
  readonly requestedTool: string;
  readonly requestedAction: string;
  readonly requestedResource: string;
  /**
   * Decrypted tool arguments (MCP `params.arguments`), needed for Step 13's
   * `allowed_parameters` enforcement (§3.3). MAY be omitted when the scope
   * carries no `allowed_parameters` constraint.
   */
  readonly toolArguments?: Record<string, unknown>;
  /**
   * Whether the inbound request arrived with channel encryption applied (i.e.
   * `_meta["io.modelcontextprotocol/tbac"].enc` was present and decrypted).
   * Scopes with `constraints.require_channel_encryption = true` (§3.3) MUST be
   * rejected when this is false. Default false.
   */
  readonly requestHasEncryption?: boolean;
  /**
   * Maximum CIBA approval age in seconds for T3 tokens. The token is rejected
   * if `iat - human_confirmed_at > maxApprovalAgeSec`. [I] The SEP names the
   * freshness requirement but does not define a default window; 300 s matches
   * the OIDC CIBA default `backchannel_authentication_request_time` freshness.
   */
  readonly maxApprovalAgeSec?: number;
  /**
   * Step 13.7 intent verification mode (§4.3 Step 13.7). `log_only` is the
   * base-conformance default and performs only the hash-integrity check; the
   * other two modes are hook interfaces in this reference implementation and
   * fall through to `log_only` behavior when unset.
   */
  readonly intentVerificationMode?: 'log_only' | 'keyword_match' | 'classifier';
  readonly replayTtlSec?: number; // default 120
  readonly sessions: SessionStore;
  readonly replay: ReplayStore;
  readonly templates: PolicyTemplateStore;
  readonly consumedLog?: ConsumedTokenLog;
  /** Peer capability version, used to gate §3.2 r39 fallback. */
  readonly peerVersion?: string;
  readonly acceptR39Tokens?: boolean;
  readonly fallbackSink?: FallbackSink;
}

export interface VerifyOutcome {
  readonly ok: true;
  readonly scope: ScopeJson;
  readonly jti: string;
  readonly session_id: bigint;
}

export interface VerifyFailure {
  readonly ok: false;
  readonly denial: Denial;
}

/** 17-step enterprise cascade. Returns success or a Denial. */
export async function verifyToken(inp: VerifyInputs): Promise<VerifyOutcome | VerifyFailure> {
  const skew = inp.clockSkewSec ?? 60;
  const replayTtl = inp.replayTtlSec ?? 120;
  const maxTtl = inp.maxTtlSec ?? 60;
  const maxApprovalAge = inp.maxApprovalAgeSec ?? 300;
  const intentMode = inp.intentVerificationMode ?? 'log_only';

  // ----- Step 1: framing check (§3.0.2)
  let parsed;
  try {
    parsed = parseTokenBytes(inp.token);
  } catch {
    return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'token parse failed');
  }
  const h = parsed.header;
  if (h.version !== TOKEN_VERSION_0x03) return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'bad version');
  if (h.alg_id !== ALG_ID_0x01) return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'bad alg_id');
  if (h.msg_type !== MSG_TYPE_ENTERPRISE) {
    return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'only enterprise msg_type supported in base conformance');
  }
  if (h.request_format === REQUEST_FORMAT_ENVELOPED) {
    return fail(
      DENIAL_CODES.NON_JSON_POP_NOT_SUPPORTED,
      FAILED_CHECKS.CONFORMANCE_SCOPE,
      'request_format 0x01 (enveloped) is outside base v6.0.0 conformance (§3.6.1)',
    );
  }
  if (h.request_format !== REQUEST_FORMAT_DIRECT) {
    return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'unknown request_format');
  }

  // ----- Step 2: session lookup
  const session = await inp.sessions.getSession(h.session_id);
  if (session === null) return fail(DENIAL_CODES.SESSION_NOT_FOUND, FAILED_CHECKS.SESSION_LOOKUP);
  if (session.status !== 'active')
    return fail(DENIAL_CODES.SESSION_EXPIRED, FAILED_CHECKS.SESSION_VALIDITY);

  // ----- Step 3: temporal + audience (and max_ttl bound per §3.0 exp row)
  const now = BigInt(inp.now);
  if (now + BigInt(skew) < h.iat) return fail(DENIAL_CODES.STALE_TIMESTAMP, FAILED_CHECKS.TEMPORAL_VALIDATION, 'iat in the future');
  if (now > h.exp + BigInt(skew))
    return fail(DENIAL_CODES.STALE_TIMESTAMP, FAILED_CHECKS.TEMPORAL_VALIDATION, 'token expired');
  // `exp - iat` MUST NOT exceed max_ttl (default 60s). Enforced before
  // decryption per §3.0 to cap the lifetime of any token the RS accepts.
  if (h.exp < h.iat)
    return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.TEMPORAL_VALIDATION, 'exp precedes iat');
  if (h.exp - h.iat > BigInt(maxTtl))
    return fail(
      DENIAL_CODES.STALE_TIMESTAMP,
      FAILED_CHECKS.TEMPORAL_VALIDATION,
      `token lifetime (exp-iat) exceeds max_ttl ${maxTtl}s (§3.0)`,
    );
  const expectedAudHash = sha256(u8(inp.expectedAud));
  if (!constantTimeEqual(h.aud_hash, expectedAudHash))
    return fail(DENIAL_CODES.AUD_MISMATCH, FAILED_CHECKS.AUDIENCE_VALIDATION);

  // ----- Step 4: session validity window + token-minted-within-window
  // §4.3 Step 4: "the token was minted within an active session window."
  // Both `iat` and `now` MUST fall within [session_start, session_start +
  // max_session_duration]. A token minted after session expiry that is still
  // fresh at presentation time MUST be rejected.
  const sessionEnd = session.session_start + session.max_session_duration;
  if (inp.now > sessionEnd)
    return fail(DENIAL_CODES.SESSION_EXPIRED, FAILED_CHECKS.SESSION_VALIDITY);
  const iatNum = Number(h.iat);
  if (iatNum + skew < session.session_start || iatNum > sessionEnd)
    return fail(
      DENIAL_CODES.SESSION_EXPIRED,
      FAILED_CHECKS.SESSION_VALIDITY,
      'token iat outside session validity window (§4.3 Step 4)',
    );

  // ----- Step 5: key derivation
  const info_enc = concat(u8(DOMAIN_TOKEN_ENC), u8(h.jti));
  const K_tok_enc = hkdfSha256(session.K_session, ZERO_SALT_32, info_enc, 32);
  const info_sign = concat(u8(DOMAIN_TOKEN_SIGN), u8(h.jti));
  const tqsSkBytes = hkdfSha256(session.K_session, ZERO_SALT_32, info_sign, 64);
  const tqsSk = scalarReduce64(tqsSkBytes);
  const tqsPk = scalarMulBase(tqsSk);

  // ----- Step 6: Schnorr verify
  const schnorrMessage = concat(
    parsed.header.R_tok,
    tqsPk,
    session.SEK_PK,
    session.verifier_secret,
    parsed.header.GCM_tag,
    parsed.ctBody,
    parsed.aad,
  );
  if (!schnorrVerify(parsed.header.R_tok, parsed.header.sigma_tok, tqsPk, schnorrMessage))
    return fail(DENIAL_CODES.INVALID_SIGNATURE, FAILED_CHECKS.SCHNORR_VERIFICATION);

  // ----- Step 7: AEAD decrypt (ONLY AFTER Step 6 succeeds)
  let plaintext: Uint8Array;
  try {
    plaintext = aesGcmDecrypt({
      key: K_tok_enc,
      iv: parsed.header.token_iv,
      aad: parsed.aad,
      ciphertext: parsed.ctBody,
      tag: parsed.header.GCM_tag,
    });
  } catch (e) {
    if (e instanceof AeadAuthError)
      return fail(DENIAL_CODES.DECRYPTION_FAILED, FAILED_CHECKS.AEAD_DECRYPTION);
    throw e;
  }

  let body;
  try {
    body = decodeTokenBody(plaintext);
  } catch {
    return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'TokenBody malformed');
  }

  // ----- Step 8: mutual_auth
  if (!constantTimeEqual(body.mutual_auth, session.mutual_auth))
    return fail(DENIAL_CODES.MUTUAL_AUTH_MISMATCH, FAILED_CHECKS.MUTUAL_AUTH_CHECK);

  // ----- Step 9: verifier_secret + scope canonicalization
  if (!constantTimeEqual(body.verifier_secret, session.verifier_secret))
    return fail(DENIAL_CODES.VERIFIER_SECRET_MISMATCH, FAILED_CHECKS.VERIFIER_SECRET_CHECK);

  // Parse the canonical scope TLV bytes (§3.0.2 type 0x01) back into ScopeJson.
  let scopeJson: ScopeJson;
  let r39FallbackUsed = false;
  try {
    const fromTlv = decanonicalizeScope(body.scope_json);
    const valOpts = {
      ...(inp.peerVersion !== undefined ? { peerVersion: inp.peerVersion } : {}),
      ...(inp.acceptR39Tokens !== undefined ? { acceptR39Tokens: inp.acceptR39Tokens } : {}),
    };
    const vr = validateScope(fromTlv, valOpts);
    if (!vr.ok) return { ok: false, denial: vr.denial };
    scopeJson = vr.value.scope;
    r39FallbackUsed = vr.value.r39FallbackUsed;
  } catch {
    return fail(DENIAL_CODES.MALFORMED_TOKEN, FAILED_CHECKS.FRAMING_CHECK, 'scope_json decode failed');
  }

  if (r39FallbackUsed) {
    emitR39Fallback(inp.fallbackSink ?? defaultFallbackSink, h.jti, scopeJson.agent_instance_id);
  }

  // ----- Step 10: replay pre-check (non-destructive)
  if (await inp.replay.checkReplay(h.session_id, h.jti))
    return fail(DENIAL_CODES.TOKEN_REPLAYED, FAILED_CHECKS.REPLAY_CONSUME);

  // ----- Step 11: policy_epoch
  if (h.policy_epoch < inp.rsCurrentEpoch)
    return fail(DENIAL_CODES.EPOCH_EXPIRED, FAILED_CHECKS.POLICY_EPOCH_VALIDATION);

  // ----- Step 12: priv_sig HMAC
  const K_priv_info = concat(u8(DOMAIN_PRIV_SIG), u64be(h.session_id));
  const K_priv = hkdfSha256(session.K_session, u64be(h.policy_epoch), K_priv_info, 32);
  const scopeTlv = canonicalizeScope(scopeJson);
  const expectedPrivSig = hmacSha256(K_priv, scopeTlv);
  if (!constantTimeEqual(body.priv_sig, expectedPrivSig))
    return fail(DENIAL_CODES.PRIVILEGE_SIG_INVALID, FAILED_CHECKS.PRIVILEGE_SIGNATURE);

  // ----- Step 13: TBAC scope evaluation + org_id + (optional) §8.1 RS-side attenuation
  if (scopeJson.aud !== inp.rsIdentifier)
    return fail(DENIAL_CODES.AUD_MISMATCH, FAILED_CHECKS.AUDIENCE_VALIDATION, 'aud post-decrypt mismatch');
  if (scopeJson.org_id !== session.org_id)
    return fail(DENIAL_CODES.ORG_ID_MISMATCH, FAILED_CHECKS.ORG_ID_VALIDATION);
  // Tool-binding check: the token's `scope.tool` MUST match the tool the RS
  // is about to invoke. Without this, a token scoped to tool X could
  // authorize tool Y whenever action/resource happen to coincide.
  if (scopeJson.tool !== inp.requestedTool) {
    return fail(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      `scope.tool "${scopeJson.tool}" does not match requestedTool "${inp.requestedTool}"`,
    );
  }

  const tpl = await inp.templates.getTemplate(scopeJson.agent_instance_id, scopeJson.tool);
  if (tpl === null)
    return fail(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      'no policy template for (agent_instance_id, tool)',
    );

  const scopedActions = typeof scopeJson.action === 'string' ? [scopeJson.action] : scopeJson.action;
  for (const a of scopedActions) {
    if (!tpl.ceiling.allowed_actions.includes(a))
      return fail(
        DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        `action "${a}" not allowed by template`,
      );
  }
  if (
    !scopedActions.includes(inp.requestedAction) ||
    !requestedResourceIsAuthorized(inp.requestedResource, scopeJson.resource)
  ) {
    return fail(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      'scope does not authorize (requestedAction, requestedResource)',
    );
  }

  // ----- Step 13 — template ceilings (§7): min_trust_level, permitted_audiences, numeric bounds.
  if (
    tpl.ceiling.min_trust_level !== undefined &&
    scopeJson.trust_level < tpl.ceiling.min_trust_level
  ) {
    return fail(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      `trust_level ${scopeJson.trust_level} below template min ${tpl.ceiling.min_trust_level}`,
    );
  }
  if (
    tpl.ceiling.permitted_audiences !== undefined &&
    !tpl.ceiling.permitted_audiences.includes(scopeJson.aud)
  ) {
    return fail(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      `aud "${scopeJson.aud}" not in template's permitted_audiences`,
    );
  }
  const scopedCons = scopeJson.constraints;
  if (scopedCons !== undefined) {
    // §3.3: per-token `max_calls` MUST be 1 (single-use semantics). Template
    // `max_calls` is the mint-rate ceiling and is a different axis, already
    // checked below.
    if (scopedCons.max_calls !== undefined && scopedCons.max_calls !== 1) {
      return fail(
        DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        `per-token max_calls MUST be 1 (§3.3); got ${scopedCons.max_calls}`,
      );
    }
    if (
      tpl.ceiling.max_rows !== undefined &&
      typeof scopedCons.max_rows === 'number' &&
      scopedCons.max_rows > tpl.ceiling.max_rows
    ) {
      return fail(
        DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        `scope.max_rows ${scopedCons.max_rows} exceeds template ceiling ${tpl.ceiling.max_rows}`,
      );
    }
    if (
      tpl.ceiling.max_calls !== undefined &&
      typeof scopedCons.max_calls === 'number' &&
      scopedCons.max_calls > tpl.ceiling.max_calls
    ) {
      return fail(
        DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        `scope.max_calls ${scopedCons.max_calls} exceeds template ceiling ${tpl.ceiling.max_calls}`,
      );
    }
    if (
      tpl.ceiling.time_window_sec !== undefined &&
      typeof scopedCons.time_window_sec === 'number' &&
      scopedCons.time_window_sec > tpl.ceiling.time_window_sec
    ) {
      return fail(
        DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        `scope.time_window_sec ${scopedCons.time_window_sec} exceeds template ceiling ${tpl.ceiling.time_window_sec}`,
      );
    }
    // §3.3: `require_channel_encryption = true` MUST cause rejection when the
    // inbound request did not arrive encrypted via `_meta[...].enc` (§10.2).
    // The channel-encryption machinery itself is a hook interface in this
    // reference implementation; `requestHasEncryption` lets the host plumb
    // the "was `enc` decrypted?" bit into the cascade.
    if (scopedCons.require_channel_encryption === true && inp.requestHasEncryption !== true) {
      return fail(
        DENIAL_CODES.CHANNEL_ENCRYPTION_REQUIRED,
        FAILED_CHECKS.CHANNEL_ENCRYPTION_MISSING,
        'scope requires channel encryption but request arrived in plaintext (§3.3, §10.2)',
      );
    }
    // ----- Step 13 — allowed_parameters enforcement (§3.3)
    if (scopedCons.allowed_parameters !== undefined) {
      const argCheck = enforceAllowedParameters(
        scopedCons.allowed_parameters,
        inp.toolArguments ?? {},
      );
      if (argCheck !== null) return argCheck;
    }
  }

  // ----- Step 13 — T3 approval-digest recomputation (§3.2).
  // `approval_digest` is REQUIRED when `trust_level = 3` and binds the CIBA
  // approval to the exact scope (preventing approve-benign/execute-sensitive
  // substitution). The schema validator already asserts presence and format
  // (64 lowercase hex). Here we recompute from the scope and compare, and
  // enforce the approval-freshness window against `iat`.
  if (scopeJson.trust_level === 3) {
    const tokenDigest = scopeJson.approval_digest;
    if (tokenDigest === undefined) {
      // validateScope already enforces presence for T3; this is defense-in-depth.
      return fail(
        DENIAL_CODES.SCOPE_FIELD_MISSING,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'trust_level=3 requires approval_digest (§3.2)',
      );
    }
    const expected = approvalDigestHex(scopeJson);
    if (expected !== tokenDigest) {
      return fail(
        DENIAL_CODES.APPROVAL_DIGEST_MISMATCH,
        FAILED_CHECKS.CIBA_DIGEST_VALIDATION,
        'recomputed approval_digest does not match token value (§3.2)',
      );
    }
    const iatSec = Number(h.iat);
    const ageSec = iatSec - scopeJson.human_confirmed_at;
    if (ageSec < -skew || ageSec > maxApprovalAge) {
      return fail(
        DENIAL_CODES.CIBA_APPROVAL_EXPIRED,
        FAILED_CHECKS.CIBA_VALIDATION,
        `human_confirmed_at outside approval window (age=${ageSec}s, max=${maxApprovalAge}s)`,
      );
    }
  }

  // ----- Step 13.7 — intent verification (§4.3).
  // Hash-integrity check is MANDATORY whenever `user_raw_intent` and
  // `intent_hash` are both present, regardless of `intentVerificationMode`.
  // The mode only governs the action-comparison step that follows.
  if (scopeJson.user_raw_intent !== undefined && scopeJson.intent_hash !== undefined) {
    const computed = sha256(u8(scopeJson.user_raw_intent));
    const computedHex = Array.from(computed, (x) => x.toString(16).padStart(2, '0')).join('');
    if (computedHex !== scopeJson.intent_hash) {
      return fail(
        DENIAL_CODES.INTENT_INTEGRITY_FAILED,
        FAILED_CHECKS.INTENT_HASH_CHECK,
        'SHA-256(user_raw_intent) does not match intent_hash (§4.3 Step 13.7)',
      );
    }
    // `log_only` (base conformance): hash verified, no action comparison.
    // `keyword_match` / `classifier`: hook interfaces — not implemented in
    // base conformance; fall through to `log_only` behavior. Implementers
    // that wire these modes SHOULD call the action-comparison gate here.
    void intentMode;
  }

  // r40 §8.1 — RS-side delegation attenuation (defense-in-depth)
  if (scopeJson.parent_token_hash !== undefined && inp.consumedLog !== undefined) {
    const parent = await inp.consumedLog.lookupParent(scopeJson.parent_token_hash);
    if (parent === null)
      return fail(
        DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
        FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
        'parent_token_hash not in consumed log (§8)',
      );
    const dd = checkAttenuation(scopeJson, parent, 'rs');
    if (dd !== null) return { ok: false, denial: dd };
  }

  // ----- Step 14: PoP (hook interface — require_pop default false in base conformance)
  if (scopeJson.require_pop === true) {
    return fail(
      DENIAL_CODES.POP_REQUIRED,
      FAILED_CHECKS.POP_MISSING,
      'PoP is a hook interface in this reference impl; require_pop=false required',
    );
  }

  // ----- Step 15: replay commit (atomic SETNX)
  const won = await inp.replay.commitReplay(h.session_id, h.jti, replayTtl);
  if (!won) return fail(DENIAL_CODES.TOKEN_REPLAYED, FAILED_CHECKS.REPLAY_CONSUME);

  // ----- Steps 16-17: consumer / receipt hooks — no-ops in enterprise profile.

  // Record this consumption so subsequent delegated children can find us.
  if (inp.consumedLog !== undefined) {
    const scopeHash = sha256(scopeTlv);
    await inp.consumedLog.recordConsumption(h.jti, scopeHash, scopeJson);
  }

  return { ok: true, scope: scopeJson, jti: h.jti, session_id: h.session_id };
}

function requestedResourceIsAuthorized(requested: string, granted: string): boolean {
  // The scope is the grant; the request must fall within it under §8.1 semantics.
  return isSubset(requested, granted);
}

/**
 * §3.3 `allowed_parameters` pattern matching. Keys not present in the
 * constraint map are unconstrained (scope narrows via other axes); keys
 * present MUST match their pattern. An argument key in the tool call that is
 * NOT in `allowed_parameters` but also NOT prefixed with `x-` vendor-extension
 * prefix is rejected if the scope has an `allowed_parameters` constraint at
 * all — the presence of the constraint means "only these keys, please".
 *
 * Pattern syntax per §3.3: `*` matches any bytes except `/`, `**` matches any
 * bytes including `/`, `?` matches any single byte except `/`. Escapes: `\*`,
 * `\?`, `\\`. Matching is on raw UTF-8 byte sequences.
 */
function enforceAllowedParameters(
  allowed: Record<string, string>,
  actualArgs: Record<string, unknown>,
): VerifyFailure | null {
  for (const [argKey, argValue] of Object.entries(actualArgs)) {
    const pattern = allowed[argKey];
    if (pattern === undefined) {
      if (argKey.startsWith('x-')) continue; // vendor extension: advisory
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          `tool argument "${argKey}" not declared in allowed_parameters`,
        ),
      };
    }
    if (typeof argValue !== 'string') {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          `tool argument "${argKey}" is not a string — allowed_parameters only matches strings`,
        ),
      };
    }
    if (!globMatch(argValue, pattern)) {
      return {
        ok: false,
        denial: denial(
          DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
          FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
          `tool argument "${argKey}" does not match allowed_parameters pattern`,
        ),
      };
    }
  }
  return null;
}

/**
 * Byte-level glob matcher for §3.3 `allowed_parameters`:
 *   `*`  — any bytes except 0x2F ('/')
 *   `**` — any bytes including 0x2F
 *   `?`  — any single byte except 0x2F
 *   `\*` `\?` `\\` — literal escapes.
 */
function globMatch(value: string, pattern: string): boolean {
  const v = new TextEncoder().encode(value);
  const p = new TextEncoder().encode(pattern);
  return globMatchBytes(v, 0, p, 0);
}

function globMatchBytes(v: Uint8Array, vi: number, p: Uint8Array, pi: number): boolean {
  while (pi < p.length) {
    const pc = p[pi]!;
    if (pc === 0x5c /* \ */ && pi + 1 < p.length) {
      // escape
      if (vi >= v.length || v[vi] !== p[pi + 1]) return false;
      vi += 1;
      pi += 2;
      continue;
    }
    if (pc === 0x2a /* * */) {
      if (pi + 1 < p.length && p[pi + 1] === 0x2a) {
        // `**` — greedy match including '/'
        if (pi + 2 >= p.length) return true;
        for (let k = vi; k <= v.length; k++) {
          if (globMatchBytes(v, k, p, pi + 2)) return true;
        }
        return false;
      }
      // `*` — greedy match excluding '/'
      if (pi + 1 >= p.length) {
        for (let k = vi; k < v.length; k++) if (v[k] === 0x2f) return false;
        return true;
      }
      for (let k = vi; k <= v.length; k++) {
        if (globMatchBytes(v, k, p, pi + 1)) return true;
        if (k < v.length && v[k] === 0x2f) return false;
      }
      return false;
    }
    if (pc === 0x3f /* ? */) {
      if (vi >= v.length || v[vi] === 0x2f) return false;
      vi += 1;
      pi += 1;
      continue;
    }
    // literal byte
    if (vi >= v.length || v[vi] !== pc) return false;
    vi += 1;
    pi += 1;
  }
  return vi === v.length;
}

function fail(code: string, failedCheck: string, message?: string): VerifyFailure {
  return {
    ok: false,
    denial: denial(code as never, failedCheck as never, message),
  };
}
