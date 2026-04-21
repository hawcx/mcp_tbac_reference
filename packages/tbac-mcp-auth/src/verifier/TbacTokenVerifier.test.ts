// SPDX-License-Identifier: Apache-2.0
//
// Regression coverage for end-to-end H2 plumbing: the `_meta[...].enc`
// presence bit MUST flow through `extractTbacMeta` into the core cascade's
// `requestHasEncryption` input, so the §3.3 `require_channel_encryption`
// gate fires correctly for SDK consumers without each caller having to
// wire the bit manually.

import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
  scalarMulBase,
} from 'tbac-core';
import { DemoOnlyStubTqsClient } from '../provider/DemoOnlyStubTqsClient.js';
import { embedToken } from '../meta/embed.js';
import { TbacTokenVerifier } from './TbacTokenVerifier.js';

const K_session = new Uint8Array(32).fill(0x42);
const SESSION_ID = 0x01n;
const EPOCH = 1n;
const VS = sha256(new TextEncoder().encode('vs'));
const MA = sha256(new TextEncoder().encode('ma'));
const RK = sha256(new TextEncoder().encode('rk'));
const SEK = scalarMulBase(7n);
const NOW = 1_741_305_600;
const AUD = 'https://rs.example.com/mcp';

function makeTqs() {
  return new DemoOnlyStubTqsClient({
    K_session,
    session_id: SESSION_ID,
    policy_epoch: EPOCH,
    verifier_secret: VS,
    mutual_auth: MA,
    response_key: RK,
    SEK_PK: SEK,
    now: () => NOW,
  });
}

function makeVerifier() {
  const sessions = new MemorySessionStore();
  sessions.put(SESSION_ID, {
    K_session,
    verifier_secret: VS,
    mutual_auth: MA,
    SEK_PK: SEK,
    profile: 'E',
    org_id: 'org-a',
    status: 'active',
    session_start: NOW - 100,
    max_session_duration: 3600,
  });
  const templates = new MemoryPolicyTemplateStore();
  templates.put('agent', 'query_database', {
    currentEpoch: EPOCH,
    ceiling: { allowed_actions: ['read'] },
  });
  return new TbacTokenVerifier({
    rsIdentifier: AUD,
    rsCurrentEpoch: EPOCH,
    sessions,
    replay: new MemoryReplayStore(),
    templates,
    consumedLog: new MemoryConsumedTokenLog(),
    now: () => NOW + 5,
  });
}

describe('TbacTokenVerifier — H2 end-to-end plumbing of _meta[...].enc', () => {
  it('accepts a token with no channel-encryption constraint when enc is absent', async () => {
    const tqs = makeTqs();
    const { token } = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'billing/*',
      aud: AUD,
      org_id: 'org-a',
      trust_level: 1,
    });
    const meta = embedToken(token);
    const v = await makeVerifier().verify({
      meta,
      requestedTool: 'query_database',
      requestedAction: 'read',
      requestedResource: 'billing/invoices',
    });
    expect(v.ok).toBe(true);
  });

  it('rejects a require_channel_encryption=true token when enc is absent from _meta', async () => {
    const tqs = makeTqs();
    const { token } = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'billing/*',
      aud: AUD,
      org_id: 'org-a',
      trust_level: 1,
      constraints: { require_channel_encryption: true, max_calls: 1 },
    });
    const meta = embedToken(token); // no `enc` field
    const v = await makeVerifier().verify({
      meta,
      requestedTool: 'query_database',
      requestedAction: 'read',
      requestedResource: 'billing/invoices',
    });
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.denial.code).toBe('CHANNEL_ENCRYPTION_REQUIRED');
      expect(v.denial.failedCheck).toBe('CHANNEL_ENCRYPTION_MISSING');
      expect(v.denialEnvelope.result._meta['io.modelcontextprotocol/tbac'].reason).toBe(
        'CHANNEL_ENCRYPTION_REQUIRED',
      );
    }
  });

  it('accepts a require_channel_encryption=true token when enc is present in _meta', async () => {
    const tqs = makeTqs();
    const { token } = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'billing/*',
      aud: AUD,
      org_id: 'org-a',
      trust_level: 1,
      constraints: { require_channel_encryption: true, max_calls: 1 },
    });
    const meta = embedToken(token);
    (meta['io.modelcontextprotocol/tbac'] as unknown as Record<string, unknown>)['enc'] = {
      ct: 'base64url-opaque-ciphertext',
    };
    const v = await makeVerifier().verify({
      meta,
      requestedTool: 'query_database',
      requestedAction: 'read',
      requestedResource: 'billing/invoices',
    });
    expect(v.ok).toBe(true);
  });

  it('requestHasEncryption override on VerificationRequest takes precedence over _meta', async () => {
    // Simulates an edge proxy that terminated channel encryption before the
    // verifier ran — `enc` is not on the wire but the request was encrypted.
    const tqs = makeTqs();
    const { token } = await tqs.dequeueToken({
      agent_instance_id: 'agent',
      tool: 'query_database',
      action: 'read',
      resource: 'billing/*',
      aud: AUD,
      org_id: 'org-a',
      trust_level: 1,
      constraints: { require_channel_encryption: true, max_calls: 1 },
    });
    const meta = embedToken(token); // no enc on the wire
    const v = await makeVerifier().verify({
      meta,
      requestedTool: 'query_database',
      requestedAction: 'read',
      requestedResource: 'billing/invoices',
      requestHasEncryption: true,
    });
    expect(v.ok).toBe(true);
  });
});
