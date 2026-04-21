// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { canonicalizeScope, decanonicalizeScope } from './canonical.js';
import type { ScopeJson } from './schema.js';

function base(overrides: Partial<ScopeJson> = {}): ScopeJson {
  return {
    iss: 'iss',
    sub: 'IK:test',
    agent_instance_id: 'agent',
    tool: 'tool',
    action: 'read',
    aud: 'https://rs.example.com/mcp',
    resource: '*',
    delegation_depth: 0,
    org_id: 'org',
    trust_level: 1,
    human_confirmed_at: 0,
    ...overrides,
  };
}

describe('scope canonicalization — allowed_parameters (§A.3.1)', () => {
  it('round-trips a simple allowed_parameters map', () => {
    const scope = base({
      constraints: {
        allowed_parameters: { file_path: '/reports/*', mode: 'read-only' },
      },
    });
    const tlv = canonicalizeScope(scope);
    const back = decanonicalizeScope(tlv);
    expect(back.constraints?.allowed_parameters).toEqual({
      file_path: '/reports/*',
      mode: 'read-only',
    });
  });

  it('sorts entries by UTF-8 byte-order of keys (deterministic)', () => {
    const a = canonicalizeScope(
      base({ constraints: { allowed_parameters: { b: 'B', a: 'A' } } }),
    );
    const b = canonicalizeScope(
      base({ constraints: { allowed_parameters: { a: 'A', b: 'B' } } }),
    );
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });

  it('handles escaped wildcards in patterns byte-exactly', () => {
    const scope = base({
      constraints: { allowed_parameters: { path: 'alpha/\\*literal' } },
    });
    const tlv = canonicalizeScope(scope);
    const back = decanonicalizeScope(tlv);
    expect(back.constraints?.allowed_parameters).toEqual({
      path: 'alpha/\\*literal',
    });
  });

  it('round-trips an empty allowed_parameters map as an absent field', () => {
    const scope = base({ constraints: { allowed_parameters: {} } });
    const back = decanonicalizeScope(canonicalizeScope(scope));
    // Empty map has no entries, so the field is absent or empty either way —
    // both representations are semantically empty. Accept either.
    const ap = back.constraints?.allowed_parameters;
    expect(ap === undefined || Object.keys(ap).length === 0).toBe(true);
  });

  it('combines with other constraint sub-fields deterministically', () => {
    const scope = base({
      constraints: {
        max_rows: 50,
        max_calls: 1,
        allowed_parameters: { zzz: 'last', aaa: 'first' },
        require_channel_encryption: true,
      },
    });
    const back = decanonicalizeScope(canonicalizeScope(scope));
    expect(back.constraints?.max_rows).toBe(50);
    expect(back.constraints?.max_calls).toBe(1);
    expect(back.constraints?.require_channel_encryption).toBe(true);
    expect(back.constraints?.allowed_parameters).toEqual({
      zzz: 'last',
      aaa: 'first',
    });
  });
});
