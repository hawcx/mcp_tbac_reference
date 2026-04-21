// SPDX-License-Identifier: Apache-2.0
//
// r40 §8.1 delegation widening-attack demo. Exits 0 iff BOTH layers (TQS
// mint-gate AND RS cascade Step 13) reject the canonical widening pattern:
//   parent.resource = "public/*"
//   child.resource  = "*"
//
// Two layers independently refusing is the defense-in-depth property r40
// introduced. If either becomes silently permissive in a future refactor,
// this demo fails — it's the ground-truth regression signal.

import { sha256 } from '@noble/hashes/sha2';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
  SEP_VERSION,
  canonicalizeScope,
  mintToken,
  scalarMulBase,
  verifyToken,
  type ScopeJson,
} from '@hawcx/tbac-core';
import { InvocationRejected, StubTqsClient } from '../provider/TqsClient.js';

async function main(): Promise<number> {
  console.log(`[widening-demo] TBAC §8.1 defense-in-depth (SEP ${SEP_VERSION})`);

  const K_session = new Uint8Array(32).fill(0x55);
  const verifier_secret = sha256(new TextEncoder().encode('wd-vs'));
  const mutual_auth = sha256(new TextEncoder().encode('wd-ma'));
  const response_key = sha256(new TextEncoder().encode('wd-rk'));
  const SEK_PK = scalarMulBase(7n);
  const session_id = 0xabcdef0102n;
  const policy_epoch = 1n;
  const RS_URL = 'https://rs.example.com/mcp';
  const clock = () => 1_760_000_000;

  const tqs = new StubTqsClient({
    K_session,
    session_id,
    policy_epoch,
    verifier_secret,
    mutual_auth,
    response_key,
    SEK_PK,
    now: clock,
  });

  // ----- LAYER 1: TQS mint-gate rejection
  const parentScope: ScopeJson = {
    iss: 'stub-tqs',
    sub: 'IK:stub-client',
    agent_instance_id: 'agent-A',
    tool: 'query_database',
    action: 'read',
    aud: RS_URL,
    resource: 'public/*',
    delegation_depth: 2,
    org_id: 'org-demo',
    trust_level: 1,
    human_confirmed_at: 0,
  };
  const parentHash = Buffer.from(sha256(canonicalizeScope(parentScope))).toString('base64url');

  let mintGateRejected = false;
  try {
    await tqs.dequeueToken({
      agent_instance_id: 'agent-A',
      tool: 'query_database',
      action: 'read',
      resource: '*', // canonical widening
      aud: RS_URL,
      org_id: 'org-demo',
      trust_level: 1,
      delegation_depth: 1,
      parent: { scope: parentScope, hashB64u: parentHash },
    });
  } catch (e) {
    if (e instanceof InvocationRejected) {
      mintGateRejected = true;
      console.log(`[widening-demo] layer-1 TQS mint-gate REJECTED: ${e.reason}`);
    } else {
      throw e;
    }
  }

  if (!mintGateRejected) {
    console.error('[widening-demo] LAYER 1 FAILED — stub TQS accepted the widened child.');
    return 1;
  }

  // ----- LAYER 2: RS cascade rejection (simulate a malicious TQS that skips the mint-gate)
  //
  // We bypass the stub and call mintToken directly to fabricate the token.
  const childScope: ScopeJson = {
    iss: 'malicious-tqs',
    sub: 'IK:stub-client',
    agent_instance_id: 'agent-A',
    tool: 'query_database',
    action: 'read',
    aud: RS_URL,
    resource: '*', // widened
    delegation_depth: 1,
    org_id: 'org-demo',
    trust_level: 1,
    human_confirmed_at: 0,
    parent_token_hash: parentHash,
  };

  const rTokSeed = new Uint8Array(64).fill(0xaa);
  const minted = mintToken({
    K_session,
    verifier_secret,
    mutual_auth,
    SEK_PK,
    session_id,
    policy_epoch,
    iat: clock(),
    exp: clock() + 60,
    token_iv: new Uint8Array(12),
    jti: 'WIDENINGx1234567890YZ0',
    scope: childScope,
    response_key,
    rTokSeed,
  });

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
  templates.put('agent-A', 'query_database', {
    currentEpoch: policy_epoch,
    ceiling: { allowed_actions: ['read'] },
  });
  const consumedLog = new MemoryConsumedTokenLog();
  // Seed the parent so the RS-side attenuation lookup finds it.
  consumedLog.seed(parentHash, parentScope);

  const r = await verifyToken({
    token: minted.token,
    now: clock() + 5,
    expectedAud: RS_URL,
    rsIdentifier: RS_URL,
    rsCurrentEpoch: policy_epoch,
    requestedAction: 'read',
    // Pick a single-segment resource that falls within child `*` but
    // OUTSIDE parent `public/*` — this forces the cascade to run
    // attenuation (step 13) rather than short-circuit on the scope
    // check. That is the test §8.1 is describing.
    requestedResource: 'secret',
    sessions,
    replay,
    templates,
    consumedLog,
  });

  if (r.ok || r.denial.failedCheck !== 'TBAC_SCOPE_EVALUATION' ||
      (r.denial.internalTag !== undefined && !r.denial.internalTag.includes('r40.8.1.rs_cascade'))) {
    console.error('[widening-demo] LAYER 2 FAILED — malicious-TQS token not rejected by RS §8.1:', r);
    return 1;
  }
  console.log(
    `[widening-demo] layer-2 RS cascade REJECTED: code=${r.denial.code} failed_check=${r.denial.failedCheck}` +
      (r.denial.internalTag !== undefined ? ` tag=${r.denial.internalTag}` : ''),
  );

  console.log('[widening-demo] BOTH LAYERS REJECTED — §8.1 defense-in-depth verified');
  return 0;
}

main().then((code) => process.exit(code));
