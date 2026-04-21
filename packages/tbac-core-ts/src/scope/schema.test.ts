// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest';
import { defaultFallbackSink, emitR39Fallback } from './r39_fallback.js';
import { validateScope } from './schema.js';

function baseScope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: 'policy-engine-test',
    sub: 'IK:test',
    agent_instance_id: 'test-agent',
    tool: 'query_database',
    action: 'read',
    aud: 'https://rs.example.com/mcp',
    resource: 'billing-api/invoices/2025-Q3',
    delegation_depth: 0,
    org_id: 'org-a-prod',
    trust_level: 2,
    human_confirmed_at: 0,
    ...overrides,
  };
}

describe('§3.2 scope validation — r40 resource REQUIRED', () => {
  it('accepts a valid r40 scope', () => {
    const r = validateScope(baseScope());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.scope.resource).toBe('billing-api/invoices/2025-Q3');
  });

  it('accepts explicit resource="*"', () => {
    const r = validateScope(baseScope({ resource: '*' }));
    expect(r.ok).toBe(true);
  });

  it('rejects resource=null', () => {
    const r = validateScope(baseScope({ resource: null }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('SCOPE_FIELD_MISSING');
  });

  it('rejects resource absent', () => {
    const obj = baseScope();
    delete obj['resource'];
    const r = validateScope(obj);
    expect(r.ok).toBe(false);
  });

  it('rejects empty-string resource', () => {
    const r = validateScope(baseScope({ resource: '' }));
    expect(r.ok).toBe(false);
  });
});

describe('§3.2 scope validation — r39 transition fallback', () => {
  it('coerces absent resource to "*" when peer is r39 and flag is on', () => {
    const obj = baseScope();
    delete obj['resource'];
    const r = validateScope(obj, {
      peerVersion: '2026-04-17-r39',
      acceptR39Tokens: true,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.scope.resource).toBe('*');
      expect(r.value.r39FallbackUsed).toBe(true);
    }
  });

  it('still rejects absent resource on r40 peer even with flag on', () => {
    const obj = baseScope();
    delete obj['resource'];
    const r = validateScope(obj, {
      peerVersion: '2026-04-20-r40',
      acceptR39Tokens: true,
    });
    expect(r.ok).toBe(false);
  });

  it('rejects absent resource when flag is off (even with r39 peer)', () => {
    const obj = baseScope();
    delete obj['resource'];
    const r = validateScope(obj, {
      peerVersion: '2026-04-17-r39',
      acceptR39Tokens: false,
    });
    expect(r.ok).toBe(false);
  });

  it('emits a single structured warning line when fallback is exercised', () => {
    const spy = vi.spyOn(defaultFallbackSink, 'warn').mockImplementation(() => undefined);
    try {
      emitR39Fallback(defaultFallbackSink, 'AAECAwQFBgcICQoLDA0ODw', 'test-agent');
      expect(spy).toHaveBeenCalledTimes(1);
      const record = spy.mock.calls[0]![0];
      expect(record.level).toBe('warn');
      expect(record.event).toBe('tbac.r39_resource_fallback');
      expect(record.jti).toBe('AAECAwQFBgcICQoLDA0ODw');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('§3.2 scope validation — header-field collisions', () => {
  for (const reserved of ['jti', 'aud_hash', 'iat', 'exp', 'policy_epoch']) {
    it(`rejects scope JSON containing header field "${reserved}"`, () => {
      const r = validateScope(baseScope({ [reserved]: 42 }));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.denial.code).toBe('MALFORMED_TOKEN');
    });
  }
});

describe('§3.2 scope validation — trust_level and human_confirmed_at', () => {
  it('trust_level 3 requires non-zero human_confirmed_at', () => {
    const r = validateScope(baseScope({ trust_level: 3, human_confirmed_at: 0 }));
    expect(r.ok).toBe(false);
  });
  it('trust_level 2 requires zero human_confirmed_at', () => {
    const r = validateScope(baseScope({ trust_level: 2, human_confirmed_at: 1_700_000_000 }));
    expect(r.ok).toBe(false);
  });
  it('trust_level 3 with timestamp + approval_digest passes', () => {
    const r = validateScope(
      baseScope({
        trust_level: 3,
        human_confirmed_at: 1_700_000_000,
        approval_digest: 'a'.repeat(64),
      }),
    );
    expect(r.ok).toBe(true);
  });
  it('rejects malformed trust_level', () => {
    const r = validateScope(baseScope({ trust_level: 5 }));
    expect(r.ok).toBe(false);
  });
});

describe('§3.2 scope validation — T3 approval_digest', () => {
  const hex64 = 'a'.repeat(64);

  it('trust_level=3 requires approval_digest', () => {
    const r = validateScope(baseScope({ trust_level: 3, human_confirmed_at: 1_700_000_000 }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/approval_digest/);
  });

  it('trust_level=3 with valid approval_digest passes', () => {
    const r = validateScope(
      baseScope({ trust_level: 3, human_confirmed_at: 1_700_000_000, approval_digest: hex64 }),
    );
    expect(r.ok).toBe(true);
  });

  it('trust_level=3 rejects non-hex approval_digest', () => {
    const r = validateScope(
      baseScope({
        trust_level: 3,
        human_confirmed_at: 1_700_000_000,
        approval_digest: 'Z'.repeat(64),
      }),
    );
    expect(r.ok).toBe(false);
  });

  it('trust_level=3 rejects uppercase hex (normative lowercase)', () => {
    const r = validateScope(
      baseScope({
        trust_level: 3,
        human_confirmed_at: 1_700_000_000,
        approval_digest: 'A'.repeat(64),
      }),
    );
    expect(r.ok).toBe(false);
  });

  it('trust_level=3 rejects wrong-length approval_digest', () => {
    const r = validateScope(
      baseScope({
        trust_level: 3,
        human_confirmed_at: 1_700_000_000,
        approval_digest: 'a'.repeat(63),
      }),
    );
    expect(r.ok).toBe(false);
  });

  it('trust_level<3 rejects stray approval_digest', () => {
    const r = validateScope(baseScope({ trust_level: 2, approval_digest: hex64 }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.message).toMatch(/approval_digest MUST be absent/);
  });
});

describe('§3.2 scope validation — intent coupling', () => {
  const hex64 = 'b'.repeat(64);

  it('user_raw_intent without intent_hash is rejected', () => {
    const r = validateScope(baseScope({ user_raw_intent: 'do X' }));
    expect(r.ok).toBe(false);
  });

  it('intent_hash without user_raw_intent is rejected', () => {
    const r = validateScope(baseScope({ intent_hash: hex64 }));
    expect(r.ok).toBe(false);
  });

  it('both present with valid hex passes', () => {
    const r = validateScope(
      baseScope({ user_raw_intent: 'do X', intent_hash: hex64 }),
    );
    expect(r.ok).toBe(true);
  });

  it('intent_hash non-hex is rejected', () => {
    const r = validateScope(
      baseScope({ user_raw_intent: 'do X', intent_hash: 'not-hex'.padEnd(64, 'z') }),
    );
    expect(r.ok).toBe(false);
  });

  it('user_raw_intent over 4096 UTF-8 bytes is rejected', () => {
    const r = validateScope(
      baseScope({ user_raw_intent: 'x'.repeat(4097), intent_hash: hex64 }),
    );
    expect(r.ok).toBe(false);
  });
});

describe('§3.2 scope validation — txn_id format', () => {
  const hex32 = '0123456789abcdef'.repeat(2);

  it('accepts 32 lowercase hex chars', () => {
    const r = validateScope(baseScope({ txn_id: hex32 }));
    expect(r.ok).toBe(true);
  });

  it('rejects wrong-length txn_id', () => {
    const r = validateScope(baseScope({ txn_id: 'abc' }));
    expect(r.ok).toBe(false);
  });

  it('rejects non-hex txn_id', () => {
    const r = validateScope(baseScope({ txn_id: 'z'.repeat(32) }));
    expect(r.ok).toBe(false);
  });
});

describe('§3.2 scope validation — misc invariants', () => {
  it('rejects non-object inputs', () => {
    expect(validateScope('string').ok).toBe(false);
    expect(validateScope(42).ok).toBe(false);
    expect(validateScope(null).ok).toBe(false);
    expect(validateScope(['an', 'array']).ok).toBe(false);
  });
  it('rejects non-string iss', () => {
    expect(validateScope(baseScope({ iss: 42 })).ok).toBe(false);
  });
  it('rejects negative delegation_depth', () => {
    expect(validateScope(baseScope({ delegation_depth: -1 })).ok).toBe(false);
  });
  it('accepts action as list', () => {
    const r = validateScope(baseScope({ action: ['read', 'write'] }));
    expect(r.ok).toBe(true);
  });
  it('rejects action with non-string elements', () => {
    const r = validateScope(baseScope({ action: ['read', 7] }));
    expect(r.ok).toBe(false);
  });
});
