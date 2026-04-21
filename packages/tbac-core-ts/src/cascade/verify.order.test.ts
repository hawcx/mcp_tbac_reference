// SPDX-License-Identifier: Apache-2.0
//
// Meta-test: verify-then-decrypt ordering is load-bearing (§4.3 cascade
// rationale). If a future refactor accidentally swaps Step 6 and Step 7,
// this test fails: a token whose GCM tag is intact but whose Schnorr
// signature is wrong MUST be rejected with INVALID_SIGNATURE, NOT with
// DECRYPTION_FAILED.

import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2';
import { mintToken } from './mint.js';
import { verifyToken } from './verify.js';
import { scalarMulBase } from '../crypto/schnorr.js';
import {
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
} from '../stores/memory.js';
import type { ScopeJson } from '../scope/schema.js';
import { OFFSETS } from '../wire/framing.js';

const K_session = new Uint8Array(32).fill(0x11);
const SESSION_ID = 0x42n;
const EPOCH = 1n;
const JTI = 'AAECAwQFBgcICQoLDA0ODw';
const AUD = 'https://rs.example.com/mcp';
const IAT = 1_741_305_600;
const EXP = 1_741_305_660;
const TOKEN_IV = new Uint8Array(12);
const VS = sha256(new TextEncoder().encode('vs-order'));
const MA = sha256(new TextEncoder().encode('ma-order'));
const RESP = sha256(new TextEncoder().encode('resp-order'));
const SEK_PK = scalarMulBase(7n);

const SCOPE: ScopeJson = {
  iss: 'iss',
  sub: 'sub',
  agent_instance_id: 'a',
  tool: 't',
  action: 'read',
  aud: AUD,
  resource: '*',
  delegation_depth: 0,
  org_id: 'org',
  trust_level: 1,
  human_confirmed_at: 0,
};

function stores() {
  const sessions = new MemorySessionStore();
  sessions.put(SESSION_ID, {
    K_session,
    verifier_secret: VS,
    mutual_auth: MA,
    SEK_PK,
    profile: 'E',
    org_id: SCOPE.org_id,
    status: 'active',
    session_start: IAT - 100,
    max_session_duration: 3600,
  });
  const replay = new MemoryReplayStore();
  const templates = new MemoryPolicyTemplateStore();
  templates.put(SCOPE.agent_instance_id, SCOPE.tool, {
    currentEpoch: EPOCH,
    ceiling: { allowed_actions: ['read'] },
  });
  return { sessions, replay, templates };
}

describe('verify-then-decrypt ordering (§4.3)', () => {
  it('a token with tampered sigma_tok is rejected with INVALID_SIGNATURE, not DECRYPTION_FAILED', async () => {
    const rTokSeed = new Uint8Array(64).fill(0xaa);
    const minted = mintToken({
      K_session,
      verifier_secret: VS,
      mutual_auth: MA,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE,
      response_key: RESP,
      rTokSeed,
    });
    // Flip one byte inside sigma_tok. GCM tag and ciphertext remain intact.
    const tampered = new Uint8Array(minted.token);
    tampered[OFFSETS.sigma_tok] = (tampered[OFFSETS.sigma_tok]! ^ 0x01) & 0xff;

    const r = await verifyToken({
      token: tampered,
      now: IAT + 1,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedTool: 't',
      requestedAction: 'read',
      requestedResource: '*',
      ...stores(),
    });

    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('INVALID_SIGNATURE');
      expect(r.denial.failedCheck).toBe('SCHNORR_VERIFICATION');
      // The key property: DECRYPTION_FAILED would indicate Step 7 ran before Step 6.
      expect(r.denial.code).not.toBe('DECRYPTION_FAILED');
    }
  });
});
