// SPDX-License-Identifier: Apache-2.0
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
  canonicalizeScope,
  scalarMulBase,
  verifyToken,
} from '@hawcx/tbac-core';
import { DemoOnlyStubTqsClient, InvocationRejected } from './DemoOnlyStubTqsClient.js';
import type { ScopeJson } from '@hawcx/tbac-core';

function makeTqs() {
  const K_session = new Uint8Array(32).fill(0x42);
  return new DemoOnlyStubTqsClient({
    K_session,
    session_id: 0x01n,
    policy_epoch: 1n,
    verifier_secret: sha256(new TextEncoder().encode('vs')),
    mutual_auth: sha256(new TextEncoder().encode('ma')),
    response_key: sha256(new TextEncoder().encode('rk')),
    SEK_PK: scalarMulBase(7n),
    now: () => 1_741_305_600,
  });
}

describe('DemoOnlyStubTqsClient', () => {
  it('mints a basic token end-to-end', async () => {
    const tqs = makeTqs();
    const r = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'billing/*',
      aud: 'https://rs.example.com/mcp',
      org_id: 'org-a',
      trust_level: 1,
    });
    expect(r.token.length).toBeGreaterThan(184);
    expect(r.scope.tool).toBe('query_database');
    expect(r.scope.resource).toBe('billing/*');
  });

  it('§8.1 mint-gate REJECTS canonical widening attack', async () => {
    const tqs = makeTqs();
    const parent: ScopeJson = {
      iss: 'stub-tqs',
      sub: 'IK:stub-client',
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      aud: 'https://rs.example.com/mcp',
      resource: 'public/*',
      delegation_depth: 2,
      org_id: 'org-a',
      trust_level: 1,
      human_confirmed_at: 0,
    };
    const parentHash = Buffer.from(sha256(canonicalizeScope(parent))).toString('base64url');
    await expect(
      tqs.dequeueToken({
        agent_instance_id: 'agent',
        tool: 'query_database',
        action: 'read',
        resource: '*', // widening attack
        aud: 'https://rs.example.com/mcp',
        org_id: 'org-a',
        trust_level: 1,
        delegation_depth: 1,
        parent: { scope: parent, hashB64u: parentHash },
      }),
    ).rejects.toBeInstanceOf(InvocationRejected);
  });

  it('§8.1 mint-gate ACCEPTS a properly attenuated child', async () => {
    const tqs = makeTqs();
    const parent: ScopeJson = {
      iss: 'stub-tqs',
      sub: 'IK:stub-client',
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      aud: 'https://rs.example.com/mcp',
      resource: 'public/*',
      delegation_depth: 2,
      org_id: 'org-a',
      trust_level: 1,
      human_confirmed_at: 0,
    };
    const parentHash = Buffer.from(sha256(canonicalizeScope(parent))).toString('base64url');
    const r = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'public/docs',
      aud: 'https://rs.example.com/mcp',
      org_id: 'org-a',
      trust_level: 1,
      delegation_depth: 1,
      parent: { scope: parent, hashB64u: parentHash },
    });
    expect(r.scope.resource).toBe('public/docs');
  });

  it('minted token verifies through the full cascade', async () => {
    const K_session = new Uint8Array(32).fill(0x42);
    const vs = sha256(new TextEncoder().encode('vs'));
    const ma = sha256(new TextEncoder().encode('ma'));
    const tqs = new DemoOnlyStubTqsClient({
      K_session,
      session_id: 0x01n,
      policy_epoch: 1n,
      verifier_secret: vs,
      mutual_auth: ma,
      response_key: sha256(new TextEncoder().encode('rk')),
      SEK_PK: scalarMulBase(7n),
      now: () => 1_741_305_600,
    });
    const r = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'billing/*',
      aud: 'https://rs.example.com/mcp',
      org_id: 'org-a',
      trust_level: 1,
    });

    const sessions = new MemorySessionStore();
    sessions.put(0x01n, {
      K_session,
      verifier_secret: vs,
      mutual_auth: ma,
      SEK_PK: scalarMulBase(7n),
      profile: 'E',
      org_id: 'org-a',
      status: 'active',
      session_start: 1_741_305_500,
      max_session_duration: 3600,
    });
    const replay = new MemoryReplayStore();
    const templates = new MemoryPolicyTemplateStore();
    templates.put('agent', 'query_database', {
      currentEpoch: 1n,
      ceiling: { allowed_actions: ['read'] },
    });
    const consumedLog = new MemoryConsumedTokenLog();

    const v = await verifyToken({
      token: r.token,
      now: 1_741_305_610,
      expectedAud: 'https://rs.example.com/mcp',
      rsIdentifier: 'https://rs.example.com/mcp',
      rsCurrentEpoch: 1n,
      requestedAction: 'read',
      requestedResource: 'billing/invoices',
      sessions,
      replay,
      templates,
      consumedLog,
    });
    expect(v.ok).toBe(true);
  });
});
