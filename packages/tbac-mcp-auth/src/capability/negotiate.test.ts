// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  buildClientCapability,
  buildServerCapability,
  negotiatePeer,
} from './negotiate.js';

describe('capability advertisements', () => {
  it('server advertises SEP r41 version', () => {
    const cap = buildServerCapability();
    expect(cap.capabilities.extensions?.['io.modelcontextprotocol/tbac']?.version).toBe(
      '2026-04-21-r41',
    );
  });
  it('client advertises SEP r41 version', () => {
    const cap = buildClientCapability();
    expect(cap.capabilities.extensions?.['io.modelcontextprotocol/tbac']?.version).toBe(
      '2026-04-21-r41',
    );
  });
});

describe('negotiatePeer', () => {
  it('enables TBAC when peer advertises exact r41 version', () => {
    const r = negotiatePeer(buildServerCapability());
    expect(r.enabled).toBe(true);
    expect(r.acceptR39Tokens).toBe(false);
  });

  it('enables TBAC when peer advertises r40 (wire-compatible per §Preamble P2.1)', () => {
    const r = negotiatePeer({
      capabilities: {
        extensions: {
          'io.modelcontextprotocol/tbac': { version: '2026-04-20-r40', tokenFormats: ['opaque'] },
        },
      },
    });
    expect(r.enabled).toBe(true);
    expect(r.peerVersion).toBe('2026-04-20-r40');
    expect(r.acceptR39Tokens).toBe(false);
    expect(r.why).toMatch(/r40 peer/);
  });

  it('enables r39 fallback when peer advertises r39 version', () => {
    const r = negotiatePeer({
      capabilities: {
        extensions: {
          'io.modelcontextprotocol/tbac': { version: '2026-04-17-r39', tokenFormats: ['opaque'] },
        },
      },
    });
    expect(r.enabled).toBe(true);
    expect(r.acceptR39Tokens).toBe(true);
    expect(r.usedExperimentalFallback).toBe(false);
  });

  it('disables TBAC for unrecognized versions (§2.1)', () => {
    const r = negotiatePeer({
      capabilities: {
        extensions: {
          'io.modelcontextprotocol/tbac': { version: '2027-01-01-r99', tokenFormats: ['opaque'] },
        },
      },
    });
    expect(r.enabled).toBe(false);
    expect(r.why).toMatch(/unrecognized/);
  });

  it('disables TBAC when peer does not advertise the extension', () => {
    const r = negotiatePeer({ capabilities: {} });
    expect(r.enabled).toBe(false);
    expect(r.acceptR39Tokens).toBe(false);
  });

  it('uses experimental fallback when extensions key is absent', () => {
    const r = negotiatePeer({
      capabilities: {
        experimental: {
          'io.modelcontextprotocol/tbac': { version: '2026-04-21-r41', tokenFormats: ['opaque'] },
        },
      },
    });
    expect(r.enabled).toBe(true);
    expect(r.usedExperimentalFallback).toBe(true);
  });

  it('prefers extensions over experimental when both are present', () => {
    const r = negotiatePeer({
      capabilities: {
        extensions: {
          'io.modelcontextprotocol/tbac': { version: '2026-04-21-r41', tokenFormats: ['opaque'] },
        },
        experimental: {
          'io.modelcontextprotocol/tbac': { version: '2026-04-17-r39', tokenFormats: ['opaque'] },
        },
      },
    });
    expect(r.enabled).toBe(true);
    expect(r.peerVersion).toBe('2026-04-21-r41');
    expect(r.usedExperimentalFallback).toBe(false);
  });
});
