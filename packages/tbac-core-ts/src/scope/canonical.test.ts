// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { canonicalizeScope, decanonicalizeScope } from './canonical.js';
import { encodeTlv } from '../wire/tlv.js';
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

describe('scope canonicalization — §3.3 unknown-constraint-tag rejection', () => {
  it('canonicalize throws on unknown normative constraint key', () => {
    expect(() =>
      canonicalizeScope(
        base({
          constraints: { max_rows: 10, bogus_field: 42 } as never,
        }),
      ),
    ).toThrow(/bogus_field/);
  });

  it('canonicalize permits x-prefixed vendor extension keys at mint time', () => {
    expect(() =>
      canonicalizeScope(
        base({
          constraints: { max_rows: 10, 'x-audit-tag': 'foo' } as never,
        }),
      ),
    ).not.toThrow();
  });

  it('decanonicalize throws on unknown normative-range tag (0x07-0x7F)', () => {
    // Hand-craft a constraint TLV with tag 0x07 (unknown, normative range).
    // Framing: [outer scope TLV ... constraints field tag 0x07 pointing to
    // inner TLV { tag 0x07, length 1, value 0x01 }].
    // Easier: just construct a minimal scope TLV and then tack on the
    // unknown constraint tag by decanonicalizing the constraint sub-TLV
    // directly.
    const badConstraintTlv = new Uint8Array([0x07, 0x01, 0xff]); // tag 0x07, len 1, val 0xff
    // We can't easily invoke decanonicalizeConstraints without going through
    // decanonicalizeScope. Construct a scope TLV whose constraint sub-field
    // carries the bad tag.
    const utf8 = new TextEncoder();
    const scopeTlvBytes = encodeTlv([
      { tag: 0x01, value: utf8.encode('iss') }, // iss
      { tag: 0x02, value: utf8.encode('IK') }, // sub
      { tag: 0x03, value: utf8.encode('agent') }, // agent_instance_id
      { tag: 0x04, value: utf8.encode('tool') }, // tool
      { tag: 0x05, value: utf8.encode('read') }, // action
      { tag: 0x06, value: utf8.encode('*') }, // resource
      { tag: 0x07, value: badConstraintTlv }, // constraints w/ unknown inner tag
      { tag: 0x08, value: new Uint8Array(8) }, // delegation_depth = 0
      { tag: 0x0a, value: new Uint8Array([0x00]) }, // require_pop = false
      { tag: 0x0b, value: utf8.encode('aud') }, // aud
      { tag: 0x0c, value: utf8.encode('org') }, // org_id
      { tag: 0x0d, value: new Uint8Array(8) }, // trust_level = 0
      { tag: 0x0e, value: new Uint8Array(8) }, // human_confirmed_at = 0
    ]);
    expect(() => decanonicalizeScope(scopeTlvBytes)).toThrow(/unknown normative-range tag/);
  });

  it('decanonicalize ignores unknown vendor-range tag (0x80+)', () => {
    const vendorConstraintTlv = new Uint8Array([0x80, 0x01, 0xff]); // tag 0x80, len 1, val 0xff
    const utf8 = new TextEncoder();
    const scopeTlvBytes = encodeTlv([
      { tag: 0x01, value: utf8.encode('iss') },
      { tag: 0x02, value: utf8.encode('IK') },
      { tag: 0x03, value: utf8.encode('agent') },
      { tag: 0x04, value: utf8.encode('tool') },
      { tag: 0x05, value: utf8.encode('read') },
      { tag: 0x06, value: utf8.encode('*') },
      { tag: 0x07, value: vendorConstraintTlv },
      { tag: 0x08, value: new Uint8Array(8) },
      { tag: 0x0a, value: new Uint8Array([0x00]) },
      { tag: 0x0b, value: utf8.encode('aud') },
      { tag: 0x0c, value: utf8.encode('org') },
      { tag: 0x0d, value: new Uint8Array(8) },
      { tag: 0x0e, value: new Uint8Array(8) },
    ]);
    expect(() => decanonicalizeScope(scopeTlvBytes)).not.toThrow();
  });
});

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

  it('decanonicalize rejects duplicate inner keys in allowed_parameters (§A.3.1)', () => {
    const utf8 = new TextEncoder();
    // Two consecutive entries for the same key "foo".
    const entry1 = encodeTlv([
      { tag: 0x01, value: utf8.encode('foo') },
      { tag: 0x02, value: utf8.encode('a') },
    ]);
    const entry2 = encodeTlv([
      { tag: 0x01, value: utf8.encode('foo') },
      { tag: 0x02, value: utf8.encode('b') },
    ]);
    const apBytes = new Uint8Array(entry1.length + entry2.length);
    apBytes.set(entry1, 0);
    apBytes.set(entry2, entry1.length);
    const constraintsTlv = encodeTlv([{ tag: 0x06, value: apBytes }]);
    const scopeTlvBytes = encodeTlv([
      { tag: 0x01, value: utf8.encode('iss') },
      { tag: 0x02, value: utf8.encode('IK') },
      { tag: 0x03, value: utf8.encode('agent') },
      { tag: 0x04, value: utf8.encode('tool') },
      { tag: 0x05, value: utf8.encode('read') },
      { tag: 0x06, value: utf8.encode('*') },
      { tag: 0x07, value: constraintsTlv },
      { tag: 0x08, value: new Uint8Array(8) },
      { tag: 0x0a, value: new Uint8Array([0x00]) },
      { tag: 0x0b, value: utf8.encode('aud') },
      { tag: 0x0c, value: utf8.encode('org') },
      { tag: 0x0d, value: new Uint8Array(8) },
      { tag: 0x0e, value: new Uint8Array(8) },
    ]);
    expect(() => decanonicalizeScope(scopeTlvBytes)).toThrow(/duplicate key/);
  });

  it('decanonicalize rejects unknown inner tag in allowed_parameters', () => {
    const utf8 = new TextEncoder();
    // Entry with an unexpected inner tag 0x03 instead of 0x02 (pattern).
    const badEntry = encodeTlv([
      { tag: 0x01, value: utf8.encode('foo') },
      { tag: 0x03, value: utf8.encode('bar') },
    ]);
    const constraintsTlv = encodeTlv([{ tag: 0x06, value: badEntry }]);
    const scopeTlvBytes = encodeTlv([
      { tag: 0x01, value: utf8.encode('iss') },
      { tag: 0x02, value: utf8.encode('IK') },
      { tag: 0x03, value: utf8.encode('agent') },
      { tag: 0x04, value: utf8.encode('tool') },
      { tag: 0x05, value: utf8.encode('read') },
      { tag: 0x06, value: utf8.encode('*') },
      { tag: 0x07, value: constraintsTlv },
      { tag: 0x08, value: new Uint8Array(8) },
      { tag: 0x0a, value: new Uint8Array([0x00]) },
      { tag: 0x0b, value: utf8.encode('aud') },
      { tag: 0x0c, value: utf8.encode('org') },
      { tag: 0x0d, value: new Uint8Array(8) },
      { tag: 0x0e, value: new Uint8Array(8) },
    ]);
    expect(() => decanonicalizeScope(scopeTlvBytes)).toThrow(/pattern tag 0x02/);
  });
});

describe('§A.4 clause 4 — unknown-tag partition policy', () => {
  const utf8 = new TextEncoder();
  function scopeWithExtra(extras: { tag: number; value: Uint8Array }[]): Uint8Array {
    return encodeTlv([
      { tag: 0x01, value: utf8.encode('iss') },
      { tag: 0x02, value: utf8.encode('IK') },
      { tag: 0x03, value: utf8.encode('agent') },
      { tag: 0x04, value: utf8.encode('tool') },
      { tag: 0x05, value: utf8.encode('read') },
      { tag: 0x06, value: utf8.encode('*') },
      { tag: 0x08, value: new Uint8Array(8) },
      { tag: 0x0a, value: new Uint8Array([0x00]) },
      { tag: 0x0b, value: utf8.encode('aud') },
      { tag: 0x0c, value: utf8.encode('org') },
      { tag: 0x0d, value: new Uint8Array(8) },
      { tag: 0x0e, value: new Uint8Array(8) },
      ...extras,
    ]);
  }

  it('scope-level: unknown normative-range tag 0x20 MUST be rejected', () => {
    const bytes = scopeWithExtra([{ tag: 0x20, value: new Uint8Array([0x01]) }]);
    expect(() => decanonicalizeScope(bytes)).toThrow(/0x20/);
  });

  it('scope-level: unknown vendor-range tag 0x90 MUST be silent-skipped', () => {
    const bytes = scopeWithExtra([{ tag: 0x90, value: new Uint8Array([0xaa]) }]);
    expect(() => decanonicalizeScope(bytes)).not.toThrow();
  });

  it('scope-level: reserved tag 0xFF MUST be rejected at any nesting level', () => {
    const bytes = scopeWithExtra([{ tag: 0xff, value: new Uint8Array(0) }]);
    expect(() => decanonicalizeScope(bytes)).toThrow(/0xFF/);
  });

  it('constraints-level: reserved tag 0xFF MUST be rejected (not silent-skipped)', () => {
    const constraintsTlv = encodeTlv([
      { tag: 0x01, value: new Uint8Array(8) }, // max_rows
      { tag: 0xff, value: new Uint8Array(0) }, // reserved — MUST reject
    ]);
    const scopeTlvBytes = encodeTlv([
      { tag: 0x01, value: utf8.encode('iss') },
      { tag: 0x02, value: utf8.encode('IK') },
      { tag: 0x03, value: utf8.encode('agent') },
      { tag: 0x04, value: utf8.encode('tool') },
      { tag: 0x05, value: utf8.encode('read') },
      { tag: 0x06, value: utf8.encode('*') },
      { tag: 0x07, value: constraintsTlv },
      { tag: 0x08, value: new Uint8Array(8) },
      { tag: 0x0a, value: new Uint8Array([0x00]) },
      { tag: 0x0b, value: utf8.encode('aud') },
      { tag: 0x0c, value: utf8.encode('org') },
      { tag: 0x0d, value: new Uint8Array(8) },
      { tag: 0x0e, value: new Uint8Array(8) },
    ]);
    expect(() => decanonicalizeScope(scopeTlvBytes)).toThrow(/0xFF/);
  });
});
