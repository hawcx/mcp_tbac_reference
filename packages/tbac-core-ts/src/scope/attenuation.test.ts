// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { checkAttenuation } from './attenuation.js';
import type { ScopeJson } from './schema.js';

function scope(overrides: Partial<ScopeJson>): ScopeJson {
  const base: ScopeJson = {
    iss: 'policy-engine-test',
    sub: 'IK:test',
    agent_instance_id: 'test-agent',
    tool: 'query_database',
    action: 'read',
    aud: 'https://rs.example.com/mcp',
    resource: 'public/*',
    delegation_depth: 1,
    org_id: 'org-a',
    trust_level: 2,
    human_confirmed_at: 0,
  };
  return { ...base, ...overrides };
}

describe('§8.1 attenuation — canonical widening attack', () => {
  it('child "*" under parent "public/*" is rejected at mint-gate', () => {
    const parent = scope({ resource: 'public/*', delegation_depth: 2 });
    const child = scope({ resource: '*', delegation_depth: 1 });
    const d = checkAttenuation(child, parent, 'mint');
    expect(d).not.toBeNull();
    expect(d!.internalTag).toBe('r40.8.1.mint_gate.widening_attack');
    expect(d!.code).toBe('INSUFFICIENT_PRIVILEGE');
    expect(d!.failedCheck).toBe('TBAC_SCOPE_EVALUATION');
  });

  it('child "*" under parent "public/*" is rejected at RS cascade', () => {
    const parent = scope({ resource: 'public/*', delegation_depth: 2 });
    const child = scope({ resource: '*', delegation_depth: 1 });
    const d = checkAttenuation(child, parent, 'rs');
    expect(d).not.toBeNull();
    expect(d!.internalTag).toBe('r40.8.1.rs_cascade.widening_attack');
  });

  it('public/docs under public/* passes', () => {
    const parent = scope({ resource: 'public/*', delegation_depth: 2 });
    const child = scope({ resource: 'public/docs', delegation_depth: 1 });
    expect(checkAttenuation(child, parent, 'rs')).toBeNull();
  });
});

describe('§8.1 attenuation — privilege-field monotonicity', () => {
  it('tool mismatch is rejected', () => {
    const parent = scope({ tool: 'read_file' });
    const child = scope({ tool: 'write_file', delegation_depth: 0 });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('tool_mismatch');
  });

  it('org_id mismatch is rejected', () => {
    const parent = scope({ org_id: 'org-a' });
    const child = scope({ org_id: 'org-b', delegation_depth: 0 });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('org_id_mismatch');
  });

  it('delegation_depth must strictly decrease', () => {
    const parent = scope({ delegation_depth: 2 });
    const child = scope({ delegation_depth: 2 });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain(
      'delegation_depth_not_decreasing',
    );
  });

  it('trust_level may not widen', () => {
    const parent = scope({ trust_level: 2 });
    const child = scope({ trust_level: 3, delegation_depth: 0, human_confirmed_at: 1_700_000_000 });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('trust_level_widened');
  });

  it('action set must narrow', () => {
    const parent = scope({ action: ['read'] });
    const child = scope({ action: ['read', 'write'], delegation_depth: 0 });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('action_widened');
  });

  it('list-action child that is a subset passes', () => {
    const parent = scope({ action: ['read', 'write'] });
    const child = scope({ action: ['read'], delegation_depth: 0 });
    expect(checkAttenuation(child, parent, 'mint')).toBeNull();
  });
});

describe('§8.1 attenuation — constraint monotonicity', () => {
  it('child max_rows may not exceed parent', () => {
    const parent = scope({ constraints: { max_rows: 100 } });
    const child = scope({
      constraints: { max_rows: 1000 },
      delegation_depth: 0,
    });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('max_rows_widened');
  });

  it('child max_calls may not exceed parent', () => {
    const parent = scope({ constraints: { max_calls: 1 } });
    const child = scope({
      constraints: { max_calls: 10 },
      delegation_depth: 0,
    });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('max_calls_widened');
  });

  it('child time_window_sec may not exceed parent', () => {
    const parent = scope({ constraints: { time_window_sec: 30 } });
    const child = scope({
      constraints: { time_window_sec: 3600 },
      delegation_depth: 0,
    });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('time_window_widened');
  });

  it('channel encryption may not be downgraded', () => {
    const parent = scope({ constraints: { require_channel_encryption: true } });
    const child = scope({
      constraints: { require_channel_encryption: false },
      delegation_depth: 0,
    });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('channel_enc_downgraded');
  });

  it('parent has constraints, child omits — rejected', () => {
    const parent = scope({ constraints: { max_rows: 100 } });
    const child = scope({ delegation_depth: 0 });
    expect(checkAttenuation(child, parent, 'mint')?.internalTag).toContain('constraints_missing');
  });
});

describe('§8.1 attenuation — happy path', () => {
  it('a strict-subset child passes every axis', () => {
    const parent = scope({
      resource: 'public/**',
      action: ['read', 'write'],
      delegation_depth: 3,
      trust_level: 3,
      human_confirmed_at: 1_700_000_000,
      constraints: { max_rows: 100, max_calls: 5, time_window_sec: 120, require_channel_encryption: true },
    });
    const child = scope({
      resource: 'public/reports/q3',
      action: ['read'],
      delegation_depth: 1,
      trust_level: 2,
      human_confirmed_at: 0,
      constraints: { max_rows: 10, max_calls: 1, time_window_sec: 30, require_channel_encryption: true },
    });
    expect(checkAttenuation(child, parent, 'rs')).toBeNull();
    expect(checkAttenuation(child, parent, 'mint')).toBeNull();
  });
});
