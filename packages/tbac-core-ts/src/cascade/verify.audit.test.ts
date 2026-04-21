// SPDX-License-Identifier: Apache-2.0
//
// Regression coverage for the five external-audit findings (H1–H4 + M5):
// TTL bound, token-minted-within-session-window, require_channel_encryption
// enforcement, T3 approval-digest recomputation + CIBA freshness, intent-
// hash integrity, and per-token max_calls=1.
//
// If any of these tests ever pass with `ok: false` when they should be
// `ok: true` (or vice versa), the audit defense has regressed.

import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { mintToken } from './mint.js';
import { verifyToken, type VerifyInputs } from './verify.js';
import { scalarMulBase } from '../crypto/schnorr.js';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
} from '../stores/memory.js';
import { approvalDigestHex } from '../scope/approval.js';
import type { ScopeJson } from '../scope/schema.js';

const K_session = sha256(new TextEncoder().encode('audit-k-session'));
const SESSION_ID = 0xabcdn;
const EPOCH = 1n;
const JTI = 'AAECAwQFBgcICQoLDA0ODw';
const AUD = 'https://rs.example.com/mcp';
const IAT = 1_750_000_000;
const EXP = 1_750_000_060;
const TOKEN_IV = new Uint8Array(12);
const VS = sha256(new TextEncoder().encode('audit-vs'));
const MA = sha256(new TextEncoder().encode('audit-ma'));
const RK = sha256(new TextEncoder().encode('audit-rk'));
const SEK_PK = scalarMulBase(9n);

function baseScope(o: Partial<ScopeJson> = {}): ScopeJson {
  return {
    iss: 'policy',
    sub: 'IK:x',
    agent_instance_id: 'agent',
    tool: 'tool',
    action: 'read',
    aud: AUD,
    resource: 'r/*',
    delegation_depth: 0,
    org_id: 'org-1',
    trust_level: 1,
    human_confirmed_at: 0,
    ...o,
  };
}

function rTok(label: string): Uint8Array {
  const h = sha256(new TextEncoder().encode('audit-rtok:' + label));
  const out = new Uint8Array(64);
  out.set(h, 0);
  out.set(h, 32);
  return out;
}

function makeStores(scope: ScopeJson, sessionStart: number = IAT - 100, sessionDuration = 3600) {
  const sessions = new MemorySessionStore();
  sessions.put(SESSION_ID, {
    K_session,
    verifier_secret: VS,
    mutual_auth: MA,
    SEK_PK,
    profile: 'E',
    org_id: scope.org_id,
    status: 'active',
    session_start: sessionStart,
    max_session_duration: sessionDuration,
  });
  const replay = new MemoryReplayStore();
  const templates = new MemoryPolicyTemplateStore();
  templates.put(scope.agent_instance_id, scope.tool, {
    currentEpoch: EPOCH,
    ceiling: { allowed_actions: ['read'] },
  });
  return { sessions, replay, templates, consumedLog: new MemoryConsumedTokenLog() };
}

function mintAndVerify(
  scope: ScopeJson,
  rTokLabel: string,
  overrides: Partial<VerifyInputs> = {},
  mintIat: number = IAT,
  mintExp: number = EXP,
) {
  const minted = mintToken({
    K_session,
    verifier_secret: VS,
    mutual_auth: MA,
    SEK_PK,
    session_id: SESSION_ID,
    policy_epoch: EPOCH,
    iat: mintIat,
    exp: mintExp,
    token_iv: TOKEN_IV,
    jti: JTI,
    scope,
    response_key: RK,
    rTokSeed: rTok(rTokLabel),
  });
  const stores = makeStores(scope);
  return verifyToken({
    token: minted.token,
    now: mintIat + 5,
    expectedAud: AUD,
    rsIdentifier: AUD,
    rsCurrentEpoch: EPOCH,
    requestedTool: scope.tool,
    requestedAction: 'read',
    requestedResource: 'r/x',
    ...stores,
    ...overrides,
  });
}

describe('H1 — max_ttl enforcement (§3.0 exp row)', () => {
  it('rejects when exp - iat exceeds maxTtlSec (default 60)', async () => {
    const scope = baseScope();
    const r = await mintAndVerify(scope, 'ttl-overlong', {}, IAT, IAT + 120);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('STALE_TIMESTAMP');
      expect(r.denial.message).toMatch(/max_ttl/);
    }
  });

  it('rejects when exp precedes iat (malformed)', async () => {
    const scope = baseScope();
    const r = await mintAndVerify(scope, 'ttl-inverted', {}, IAT, IAT - 5);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('MALFORMED_TOKEN');
  });

  it('honors a caller-supplied maxTtlSec override', async () => {
    const scope = baseScope();
    const r = await mintAndVerify(scope, 'ttl-override', { maxTtlSec: 30 }, IAT, IAT + 45);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/max_ttl 30s/);
  });
});

describe('H1 — token minted within session validity window (§4.3 Step 4)', () => {
  it('rejects when iat precedes session_start', async () => {
    const scope = baseScope();
    const minted = mintToken({
      K_session,
      verifier_secret: VS,
      mutual_auth: MA,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope,
      response_key: RK,
      rTokSeed: rTok('session-before-start'),
    });
    // Session starts AFTER the token's iat — minted outside the window.
    const stores = makeStores(scope, IAT + 1000, 3600);
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedTool: scope.tool,
      requestedAction: 'read',
      requestedResource: 'r/x',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('SESSION_EXPIRED');
  });

  it('rejects when iat is after session end but still within clock-skew of now', async () => {
    // Scenario: session ended 30s before the token's iat. Clock skew (60s)
    // permits `now` to be within `iat-skew`. `now` is before sessionEnd so
    // the existing `now > sessionEnd` check does NOT fire; the new
    // iat-within-window check must catch the malicious/buggy mint.
    const scope = baseScope();
    const minted = mintToken({
      K_session,
      verifier_secret: VS,
      mutual_auth: MA,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: IAT + 60,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope,
      response_key: RK,
      rTokSeed: rTok('session-after-end-skew'),
    });
    // session_start = IAT - 100, duration = 70 → sessionEnd = IAT - 30
    const stores = makeStores(scope, IAT - 100, 70);
    const r = await verifyToken({
      token: minted.token,
      now: IAT - 40, // before sessionEnd (= IAT - 30), within skew of iat (IAT - 40 + 60 = IAT + 20 >= IAT)
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedTool: scope.tool,
      requestedAction: 'read',
      requestedResource: 'r/x',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('SESSION_EXPIRED');
      expect(r.denial.failedCheck).toBe('SESSION_VALIDITY');
    }
  });
});

describe('H2 — require_channel_encryption enforcement (§3.3)', () => {
  it('rejects when scope demands encryption and request arrived plaintext', async () => {
    const scope = baseScope({
      constraints: { require_channel_encryption: true, max_calls: 1 },
    });
    const r = await mintAndVerify(scope, 'h2-required-missing', {
      requestHasEncryption: false,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('CHANNEL_ENCRYPTION_REQUIRED');
      expect(r.denial.failedCheck).toBe('CHANNEL_ENCRYPTION_MISSING');
    }
  });

  it('accepts when scope demands encryption and request arrived encrypted', async () => {
    const scope = baseScope({
      constraints: { require_channel_encryption: true, max_calls: 1 },
    });
    const r = await mintAndVerify(scope, 'h2-required-present', {
      requestHasEncryption: true,
    });
    expect(r.ok).toBe(true);
  });

  it('does not require encryption when scope omits the constraint', async () => {
    const scope = baseScope();
    const r = await mintAndVerify(scope, 'h2-not-required', {
      requestHasEncryption: false,
    });
    expect(r.ok).toBe(true);
  });
});

describe('H3 — T3 approval_digest recomputation + CIBA freshness (§3.2)', () => {
  function t3Scope(overrides: Partial<ScopeJson> = {}): ScopeJson {
    // Separate caller-overridden approval_digest from everything else so the
    // caller can deliberately inject a wrong digest.
    const { approval_digest: callerDigest, ...rest } = overrides;
    const base = baseScope({
      trust_level: 3,
      human_confirmed_at: IAT - 30,
      purpose: 'do the thing',
      ...rest,
    });
    const digest = callerDigest ?? approvalDigestHex(base);
    return { ...base, approval_digest: digest };
  }

  it('accepts when approval_digest matches and human_confirmed_at is fresh', async () => {
    const r = await mintAndVerify(t3Scope(), 'h3-happy');
    expect(r.ok).toBe(true);
  });

  it('rejects when approval_digest does not match the scope', async () => {
    const scope = t3Scope({ approval_digest: 'a'.repeat(64) });
    const r = await mintAndVerify(scope, 'h3-digest-mismatch');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('APPROVAL_DIGEST_MISMATCH');
      expect(r.denial.failedCheck).toBe('CIBA_DIGEST_VALIDATION');
    }
  });

  it('rejects when human_confirmed_at is outside the approval window', async () => {
    // 600 s before iat > default maxApprovalAgeSec = 300.
    const stale = t3Scope({ human_confirmed_at: IAT - 600 });
    const r = await mintAndVerify(stale, 'h3-stale');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('CIBA_APPROVAL_EXPIRED');
      expect(r.denial.failedCheck).toBe('CIBA_VALIDATION');
    }
  });

  it('honors a caller-supplied maxApprovalAgeSec override', async () => {
    const scope = t3Scope({ human_confirmed_at: IAT - 120 }); // ok under default
    const r = await mintAndVerify(scope, 'h3-override', { maxApprovalAgeSec: 60 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('CIBA_APPROVAL_EXPIRED');
  });

  it('substitution attack: swapping an approved T3 scope into a different tool is rejected', async () => {
    // Mint approval for one scope shape, then try to verify a scope where
    // `tool` differs. approval_digest covers `tool`, so the recomputed hash
    // differs and the cascade rejects.
    const approvedScope = t3Scope({ tool: 'benign_read' });
    const malicious = { ...approvedScope, tool: 'sensitive_delete' };
    const r = await mintAndVerify(malicious, 'h3-substitution');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('APPROVAL_DIGEST_MISMATCH');
  });
});

describe('H4 — intent hash integrity (§4.3 Step 13.7)', () => {
  it('accepts when intent_hash equals SHA-256(user_raw_intent)', async () => {
    const intent = 'query the billing invoices';
    const hash = Array.from(sha256(new TextEncoder().encode(intent)), (x) =>
      x.toString(16).padStart(2, '0'),
    ).join('');
    const scope = baseScope({ user_raw_intent: intent, intent_hash: hash });
    const r = await mintAndVerify(scope, 'h4-happy');
    expect(r.ok).toBe(true);
  });

  it('rejects when intent_hash does not match SHA-256(user_raw_intent)', async () => {
    const scope = baseScope({
      user_raw_intent: 'query the billing invoices',
      intent_hash: 'f'.repeat(64),
    });
    const r = await mintAndVerify(scope, 'h4-mismatch');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('INTENT_HASH_MISMATCH');
      expect(r.denial.failedCheck).toBe('INTENT_VERIFICATION');
    }
  });

  it('rejects intent mismatch even when intentVerificationMode = log_only', async () => {
    // Hash integrity is mandatory regardless of mode — log_only only skips
    // the action-comparison step, not the hash check itself.
    const scope = baseScope({
      user_raw_intent: 'query the billing invoices',
      intent_hash: 'f'.repeat(64),
    });
    const r = await mintAndVerify(scope, 'h4-logonly', {
      intentVerificationMode: 'log_only',
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('INTENT_HASH_MISMATCH');
  });
});

describe('M5 — constraint type validation + per-token max_calls=1 (§3.3)', () => {
  it('rejects per-token max_calls other than 1', async () => {
    const scope = baseScope({ constraints: { max_calls: 5 } });
    const r = await mintAndVerify(scope, 'm5-max-calls-not-1');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/per-token max_calls MUST be 1/);
  });

  it('accepts per-token max_calls = 1', async () => {
    const scope = baseScope({ constraints: { max_calls: 1 } });
    const r = await mintAndVerify(scope, 'm5-max-calls-1');
    expect(r.ok).toBe(true);
  });

  it('accepts scope omitting max_calls entirely', async () => {
    const r = await mintAndVerify(baseScope(), 'm5-no-max-calls');
    expect(r.ok).toBe(true);
  });
});
