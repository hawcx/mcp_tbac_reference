// SPDX-License-Identifier: Apache-2.0
//
// Tests for the full Step 13 enforcement surface: template ceilings
// (min_trust_level, permitted_audiences, numeric bounds) and the §3.3
// allowed_parameters pattern matcher.

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
import type { PolicyTemplate } from '../stores/interfaces.js';
import type { ScopeJson } from '../scope/schema.js';

const K_session = new Uint8Array(32).fill(0x31);
const SESSION_ID = 0x77n;
const EPOCH = 1n;
const JTI = 'AAECAwQFBgcICQoLDA0ODw';
const AUD = 'https://rs.example.com/mcp';
const IAT = 1_750_000_000;
const EXP = 1_750_000_060;
const TOKEN_IV = new Uint8Array(12);
const VS = sha256(new TextEncoder().encode('step13-vs'));
const MA = sha256(new TextEncoder().encode('step13-ma'));
const RK = sha256(new TextEncoder().encode('step13-rk'));
const SEK_PK = scalarMulBase(7n);

function baseScope(overrides: Partial<ScopeJson> = {}): ScopeJson {
  return {
    iss: 'policy-engine',
    sub: 'IK:test',
    agent_instance_id: 'agent',
    tool: 'query_database',
    action: 'read',
    aud: AUD,
    resource: 'billing/*',
    delegation_depth: 0,
    org_id: 'org-a',
    trust_level: 1,
    human_confirmed_at: 0,
    ...overrides,
  };
}

function freshRTokSeed(label: string): Uint8Array {
  const s = sha256(new TextEncoder().encode('seed:' + label));
  const out = new Uint8Array(64);
  out.set(s, 0);
  out.set(s, 32);
  return out;
}

function makeStoresFor(scope: ScopeJson, tpl: PolicyTemplate) {
  const sessions = new MemorySessionStore();
  sessions.put(SESSION_ID, {
    K_session,
    verifier_secret: VS,
    mutual_auth: MA,
    SEK_PK,
    profile: 'E',
    org_id: scope.org_id,
    status: 'active',
    session_start: IAT - 100,
    max_session_duration: 3600,
  });
  const replay = new MemoryReplayStore();
  const templates = new MemoryPolicyTemplateStore();
  templates.put(scope.agent_instance_id, scope.tool, tpl);
  const consumedLog = new MemoryConsumedTokenLog();
  return { sessions, replay, templates, consumedLog };
}

function mintAndVerify(
  scope: ScopeJson,
  tpl: PolicyTemplate,
  extra: Partial<VerifyInputs> = {},
): ReturnType<typeof verifyToken> {
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
    rTokSeed: freshRTokSeed(scope.tool + ':' + scope.resource + ':' + JSON.stringify(scope.constraints ?? {})),
  });
  const stores = makeStoresFor(scope, tpl);
  return verifyToken({
    token: minted.token,
    now: IAT + 5,
    expectedAud: AUD,
    rsIdentifier: AUD,
    rsCurrentEpoch: EPOCH,
    requestedAction: 'read',
    requestedResource: 'billing/invoices',
    ...stores,
    ...extra,
  });
}

describe('Step 13 — template ceiling enforcement', () => {
  it('denies when scope trust_level below template min_trust_level', async () => {
    const r = await mintAndVerify(
      baseScope({ trust_level: 1 }),
      {
        currentEpoch: EPOCH,
        ceiling: { allowed_actions: ['read'], min_trust_level: 3 },
      },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('INSUFFICIENT_PRIVILEGE');
      expect(r.denial.message).toMatch(/trust_level/);
    }
  });

  it('denies when scope aud not in template permitted_audiences', async () => {
    const r = await mintAndVerify(baseScope(), {
      currentEpoch: EPOCH,
      ceiling: {
        allowed_actions: ['read'],
        permitted_audiences: ['https://other.example.com/mcp'],
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/permitted_audiences/);
  });

  it('denies when scope.max_rows exceeds template ceiling', async () => {
    const r = await mintAndVerify(
      baseScope({ constraints: { max_rows: 10_000 } }),
      {
        currentEpoch: EPOCH,
        ceiling: { allowed_actions: ['read'], max_rows: 100 },
      },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/max_rows/);
  });

  it('denies when scope.max_calls exceeds template ceiling', async () => {
    const r = await mintAndVerify(
      baseScope({ constraints: { max_calls: 9 } }),
      {
        currentEpoch: EPOCH,
        ceiling: { allowed_actions: ['read'], max_calls: 1 },
      },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/max_calls/);
  });

  it('denies when scope.time_window_sec exceeds template ceiling', async () => {
    const r = await mintAndVerify(
      baseScope({ constraints: { time_window_sec: 3600 } }),
      {
        currentEpoch: EPOCH,
        ceiling: { allowed_actions: ['read'], time_window_sec: 60 },
      },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/time_window_sec/);
  });

  it('accepts a scope strictly within all template ceilings', async () => {
    const r = await mintAndVerify(
      baseScope({
        trust_level: 3,
        human_confirmed_at: 1_700_000_000,
        approval_digest: 'a'.repeat(64),
        constraints: { max_rows: 10, max_calls: 1, time_window_sec: 30 },
      }),
      {
        currentEpoch: EPOCH,
        ceiling: {
          allowed_actions: ['read'],
          min_trust_level: 2,
          permitted_audiences: [AUD],
          max_rows: 100,
          max_calls: 5,
          time_window_sec: 60,
        },
      },
    );
    expect(r.ok).toBe(true);
  });
});

describe('Step 13 — allowed_parameters enforcement (§3.3)', () => {
  const tpl: PolicyTemplate = {
    currentEpoch: EPOCH,
    ceiling: { allowed_actions: ['read'] },
  };

  it('denies a non-matching argument value', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { file_path: '/reports/*' } },
      }),
      tpl,
      { toolArguments: { file_path: '/secrets/keys' } },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/does not match/);
  });

  it('accepts a matching argument value under `*` semantics', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { file_path: '/reports/*' } },
      }),
      tpl,
      { toolArguments: { file_path: '/reports/q3.pdf' } },
    );
    expect(r.ok).toBe(true);
  });

  it('`*` does NOT match paths containing `/` (single-segment)', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { file_path: '/reports/*' } },
      }),
      tpl,
      { toolArguments: { file_path: '/reports/q3/breakdown.pdf' } },
    );
    expect(r.ok).toBe(false);
  });

  it('`**` DOES match paths containing `/`', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { file_path: '/reports/**' } },
      }),
      tpl,
      { toolArguments: { file_path: '/reports/q3/breakdown.pdf' } },
    );
    expect(r.ok).toBe(true);
  });

  it('`?` matches exactly one non-slash byte', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { code: 'A?C' } },
      }),
      tpl,
      { toolArguments: { code: 'AXC' } },
    );
    expect(r.ok).toBe(true);
  });

  it('denies extra tool arguments not declared in allowed_parameters', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { file_path: '/reports/*' } },
      }),
      tpl,
      { toolArguments: { file_path: '/reports/q3.pdf', extra: 'stowaway' } },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/extra/);
  });

  it('allows x- vendor-extension arguments to pass through', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { file_path: '/reports/*' } },
      }),
      tpl,
      {
        toolArguments: {
          file_path: '/reports/q3.pdf',
          'x-trace-id': 'foo',
        },
      },
    );
    expect(r.ok).toBe(true);
  });

  it('literal escaped asterisk matches the byte *', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { tag: 'hello\\*world' } },
      }),
      tpl,
      { toolArguments: { tag: 'hello*world' } },
    );
    expect(r.ok).toBe(true);
  });

  it('rejects non-string arg values against allowed_parameters', async () => {
    const r = await mintAndVerify(
      baseScope({
        constraints: { allowed_parameters: { limit: '*' } },
      }),
      tpl,
      { toolArguments: { limit: 42 } },
    );
    expect(r.ok).toBe(false);
  });
});
