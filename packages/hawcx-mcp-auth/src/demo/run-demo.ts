// SPDX-License-Identifier: Apache-2.0
//
// Demo 1: happy path + scope denial + replay denial.
// `pnpm demo` from the repo root invokes this.
//
// Exits 0 iff all three outcomes match expectations.

import { sha256 } from '@noble/hashes/sha2';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
  SEP_VERSION,
  scalarMulBase,
} from '@hawcx/tbac-core';
import { DemoOnlyStubTqsClient } from '../provider/DemoOnlyStubTqsClient.js';
import { TbacAuthProvider } from '../provider/TbacAuthProvider.js';
import { TbacTokenVerifier } from '../verifier/TbacTokenVerifier.js';

async function main(): Promise<number> {
  console.log(`[demo] TBAC reference implementation (SEP ${SEP_VERSION})`);

  // --- Shared session material (in production, bootstrapped via X3DH).
  const K_session = new Uint8Array(32).fill(0x77);
  const verifier_secret = sha256(new TextEncoder().encode('demo-vs'));
  const mutual_auth = sha256(new TextEncoder().encode('demo-ma'));
  const response_key = sha256(new TextEncoder().encode('demo-rk'));
  const SEK_PK = scalarMulBase(7n);
  const session_id = 0xcafebabe1234n;
  const policy_epoch = 1n;
  const RS_URL = 'https://rs.example.com/mcp';

  // --- Client side: TQS + AuthProvider
  const clock = () => 1_750_000_000;
  const tqs = new DemoOnlyStubTqsClient({
    K_session,
    session_id,
    policy_epoch,
    verifier_secret,
    mutual_auth,
    response_key,
    SEK_PK,
    now: clock,
  });
  const provider = new TbacAuthProvider(tqs);

  // --- Server side: cascade stores
  const sessions = new MemorySessionStore();
  sessions.put(session_id, {
    K_session,
    verifier_secret,
    mutual_auth,
    SEK_PK,
    profile: 'E',
    org_id: 'org-demo',
    status: 'active',
    session_start: clock() - 60,
    max_session_duration: 3600,
  });
  const replay = new MemoryReplayStore();
  const templates = new MemoryPolicyTemplateStore();
  templates.put('demo-agent', 'query_database', {
    currentEpoch: policy_epoch,
    ceiling: { allowed_actions: ['read'], max_rows: 1000 },
  });
  const consumedLog = new MemoryConsumedTokenLog();
  const verifier = new TbacTokenVerifier({
    rsIdentifier: RS_URL,
    rsCurrentEpoch: policy_epoch,
    sessions,
    replay,
    templates,
    consumedLog,
    now: clock,
  });

  // --- Case 1: happy path
  const attached1 = await provider.attachToken({
    agent_instance_id: 'demo-agent',
    tool: 'query_database',
    action: 'read',
    resource: 'billing-api/*',
    aud: RS_URL,
    org_id: 'org-demo',
    trust_level: 1,
    request: { params: {} },
  });
  const happy = await verifier.verify({
    meta: (attached1.request.params as Record<string, unknown>)?.['_meta'],
    requestedAction: 'read',
    requestedResource: 'billing-api/invoices',
  });
  if (!happy.ok) {
    console.error('[demo] case 1 FAILED — expected success, got denial:', happy.denial);
    return 1;
  }
  console.log(`[demo] case 1 PASS — valid token, scope resource="${happy.scope.resource}"`);

  // --- Case 2: scope-evaluation denial — ask for something outside the granted scope
  const attached2 = await provider.attachToken({
    agent_instance_id: 'demo-agent',
    tool: 'query_database',
    action: 'read',
    resource: 'accounting/*', // narrow scope
    aud: RS_URL,
    org_id: 'org-demo',
    trust_level: 1,
    request: { params: {} },
  });
  const denied = await verifier.verify({
    meta: (attached2.request.params as Record<string, unknown>)?.['_meta'],
    requestedAction: 'read',
    requestedResource: 'billing-api/invoices', // outside scope
  });
  if (denied.ok || denied.denial.failedCheck !== 'TBAC_SCOPE_EVALUATION') {
    console.error('[demo] case 2 FAILED — expected TBAC_SCOPE_EVALUATION, got:', denied);
    return 1;
  }
  console.log(
    `[demo] case 2 PASS — denial code=${denied.denial.code} failed_check=${denied.denial.failedCheck}`,
  );

  // --- Case 3: replay denial — submit the same token twice
  const replayed = await verifier.verify({
    meta: (attached1.request.params as Record<string, unknown>)?.['_meta'],
    requestedAction: 'read',
    requestedResource: 'billing-api/invoices',
  });
  if (replayed.ok || replayed.denial.code !== 'TOKEN_REPLAYED') {
    console.error('[demo] case 3 FAILED — expected TOKEN_REPLAYED, got:', replayed);
    return 1;
  }
  console.log(
    `[demo] case 3 PASS — replay of jti="${attached1.jti}" denied: ${replayed.denial.code}`,
  );

  console.log('[demo] ALL CASES PASS');
  return 0;
}

main().then((code) => process.exit(code));
