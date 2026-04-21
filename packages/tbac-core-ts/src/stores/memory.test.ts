// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
} from './memory.js';

describe('in-memory stores', () => {
  it('session store round-trips', async () => {
    const s = new MemorySessionStore();
    const rec = {
      K_session: new Uint8Array(32).fill(1),
      verifier_secret: new Uint8Array(32).fill(2),
      mutual_auth: new Uint8Array(32).fill(3),
      SEK_PK: new Uint8Array(32).fill(4),
      profile: 'E' as const,
      org_id: 'org-a',
      status: 'active' as const,
      session_start: 1_700_000_000,
      max_session_duration: 3600,
    };
    s.put(0xdeadbeefn, rec);
    expect(await s.getSession(0xdeadbeefn)).toBe(rec);
    expect(await s.getSession(0x1234n)).toBeNull();
  });

  it('replay commit wins once then loses', async () => {
    const r = new MemoryReplayStore();
    expect(await r.checkReplay(1n, 'j')).toBe(false);
    expect(await r.commitReplay(1n, 'j', 60)).toBe(true);
    expect(await r.commitReplay(1n, 'j', 60)).toBe(false);
    expect(await r.checkReplay(1n, 'j')).toBe(true);
  });

  it('replay commit is race-safe under concurrent calls', async () => {
    const r = new MemoryReplayStore();
    const results = await Promise.all([
      r.commitReplay(2n, 'j', 60),
      r.commitReplay(2n, 'j', 60),
      r.commitReplay(2n, 'j', 60),
    ]);
    const winners = results.filter((x) => x === true).length;
    expect(winners).toBe(1);
  });

  it('policy template store', async () => {
    const s = new MemoryPolicyTemplateStore();
    const tpl = { currentEpoch: 1n, ceiling: { allowed_actions: ['read'] } };
    s.put('agent', 'query_database', tpl);
    expect(await s.getTemplate('agent', 'query_database')).toBe(tpl);
    expect(await s.getTemplate('nope', 'query_database')).toBeNull();
  });

  it('consumed-token log record + lookup by hash', async () => {
    const log = new MemoryConsumedTokenLog();
    const scope = {
      iss: 'x',
      sub: 'IK:y',
      agent_instance_id: 'a',
      tool: 't',
      action: 'read',
      aud: 'z',
      resource: '*',
      delegation_depth: 0,
      org_id: 'org',
      trust_level: 1 as const,
      human_confirmed_at: 0,
    };
    const hash = new Uint8Array(32).fill(0xaa);
    await log.recordConsumption('jti', hash, scope);
    const b64 = Buffer.from(hash).toString('base64url');
    expect(await log.lookupParent(b64)).toBe(scope);
  });
});
