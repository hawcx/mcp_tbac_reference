// SPDX-License-Identifier: Apache-2.0
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { mintToken } from './mint.js';
import { verifyToken } from './verify.js';
import { scalarMulBase, scalarReduce64 } from '../crypto/schnorr.js';
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
} from '../stores/memory.js';
import type { ScopeJson } from '../scope/schema.js';

// Fixed test inputs mirroring SEP §A.5.1 (byte-identical scope JSON).
const K_session = hexToBytes(
  'a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f10',
);
const SESSION_ID = 0x00000000deadbeefn;
const EPOCH = 1n;
const JTI = 'AAECAwQFBgcICQoLDA0ODw';
const AUD = 'https://rs.example.com/mcp';
const IAT = 1741305600;
const EXP = 1741305660;
const TOKEN_IV = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0x01]);
const VERIFIER_SECRET = sha256(new TextEncoder().encode('test-verifier-secret'));
const MUTUAL_AUTH = sha256(new TextEncoder().encode('test-mutual-auth'));
const RESPONSE_KEY = sha256(new TextEncoder().encode('test-response-key'));

// SEK_PK as (scalar=7)*G
const SEK_PK = scalarMulBase(7n);

const SCOPE_A5: ScopeJson = {
  iss: 'policy-engine-test',
  sub: 'IK:test-client-fingerprint',
  aud: AUD,
  agent_instance_id: 'test-agent',
  tool: 'query_database',
  action: 'read',
  resource: 'billing-api/invoices/2025-Q3',
  constraints: {
    max_rows: 100,
    time_window_sec: 30,
    max_calls: 1,
    require_channel_encryption: true,
  },
  delegation_depth: 0,
  require_pop: false,
  org_id: 'org-a-prod',
  trust_level: 2,
  human_confirmed_at: 0,
};

function makeStores(scope: ScopeJson) {
  const sessions = new MemorySessionStore();
  sessions.put(SESSION_ID, {
    K_session,
    verifier_secret: VERIFIER_SECRET,
    mutual_auth: MUTUAL_AUTH,
    SEK_PK,
    profile: 'E',
    org_id: scope.org_id,
    status: 'active',
    session_start: IAT - 100,
    max_session_duration: 3600,
    response_key_seed: RESPONSE_KEY,
  });
  const replay = new MemoryReplayStore();
  const templates = new MemoryPolicyTemplateStore();
  templates.put(scope.agent_instance_id, scope.tool, {
    currentEpoch: EPOCH,
    ceiling: {
      allowed_actions: typeof scope.action === 'string' ? [scope.action] : [...scope.action],
      max_rows: 1000,
      max_calls: 10,
      time_window_sec: 60,
    },
  });
  const consumedLog = new MemoryConsumedTokenLog();
  return { sessions, replay, templates, consumedLog };
}

function rTokSeed(label: string): Uint8Array {
  const base = sha256(new TextEncoder().encode('rtok-seed:' + label));
  const out = new Uint8Array(64);
  out.set(base, 0);
  out.set(base, 32);
  return out;
}

describe('17-step verification cascade (§4.3)', () => {
  it('accepts a valid r40 token end-to-end', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('happy'),
    });
    const stores = makeStores(SCOPE_A5);
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.scope.resource).toBe('billing-api/invoices/2025-Q3');
      expect(r.jti).toBe(JTI);
    }
  });

  it('rejects a token after its expiration', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('expired'),
    });
    const stores = makeStores(SCOPE_A5);
    const r = await verifyToken({
      token: minted.token,
      now: EXP + 1000,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('STALE_TIMESTAMP');
  });

  it('rejects a token with wrong audience', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('wrongaud'),
    });
    const stores = makeStores(SCOPE_A5);
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: 'https://different.example.com/mcp',
      rsIdentifier: 'https://different.example.com/mcp',
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('AUD_MISMATCH');
  });

  it('rejects on session not found', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('nosession'),
    });
    const stores = makeStores(SCOPE_A5);
    // Replace session store with empty one
    const emptySessions = new MemorySessionStore();
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
      sessions: emptySessions,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('SESSION_NOT_FOUND');
  });

  it('rejects on stale policy_epoch', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('staleepoch'),
    });
    const stores = makeStores(SCOPE_A5);
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: 10n, // much higher than token's 1
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('EPOCH_EXPIRED');
  });

  it('rejects on replay (second verification of same token)', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('replay'),
    });
    const stores = makeStores(SCOPE_A5);
    const first = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(first.ok).toBe(true);
    const second = await verifyToken({
      token: minted.token,
      now: IAT + 6,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.denial.code).toBe('TOKEN_REPLAYED');
  });

  it('rejects a scope-evaluation widening: request outside granted resource', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: { ...SCOPE_A5, resource: 'public/*' },
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('narrow'),
    });
    const stores = makeStores({ ...SCOPE_A5, resource: 'public/*' });
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'private/secret',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('INSUFFICIENT_PRIVILEGE');
      expect(r.denial.failedCheck).toBe('TBAC_SCOPE_EVALUATION');
    }
  });

  it('rejects request_format 0x01 per §3.6.1', async () => {
    // Craft a token with request_format = 0x01 by editing a minted token byte 3.
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: SCOPE_A5,
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('envelope'),
    });
    const tampered = new Uint8Array(minted.token);
    tampered[3] = 0x01;
    const stores = makeStores(SCOPE_A5);
    const r = await verifyToken({
      token: tampered,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('NON_JSON_POP_NOT_SUPPORTED');
      expect(r.denial.failedCheck).toBe('CONFORMANCE_SCOPE');
    }
  });

  it('rejects require_pop=true in base conformance (hook interface)', async () => {
    const minted = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: { ...SCOPE_A5, require_pop: true },
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('pop'),
    });
    const stores = makeStores({ ...SCOPE_A5, require_pop: true });
    const r = await verifyToken({
      token: minted.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      requestedResource: 'billing-api/invoices/2025-Q3',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denial.code).toBe('POP_REQUIRED');
  });
});

describe('17-step cascade — r40 §8.1 delegation defense (RS-side)', () => {
  it('rejects a widened delegated child at RS Step 13', async () => {
    // Parent: resource=public/*, delegation_depth=2
    // Child:  resource=*,         delegation_depth=1  ← widening attack
    const parentScope: ScopeJson = {
      ...SCOPE_A5,
      resource: 'public/*',
      delegation_depth: 2,
    };
    const childScope: ScopeJson = {
      ...SCOPE_A5,
      resource: '*',
      delegation_depth: 1,
      parent_token_hash: 'PARENTHASH_PLACEHOLDER',
    };
    const parentTlvHash = sha256(
      new TextEncoder().encode('fake but stable'),
    );
    const parentHashB64u = Buffer.from(parentTlvHash).toString('base64url');

    // Mint the child token with a parent_token_hash set to our fake parent digest
    const child = mintToken({
      K_session,
      verifier_secret: VERIFIER_SECRET,
      mutual_auth: MUTUAL_AUTH,
      SEK_PK,
      session_id: SESSION_ID,
      policy_epoch: EPOCH,
      iat: IAT,
      exp: EXP,
      token_iv: TOKEN_IV,
      jti: JTI,
      scope: { ...childScope, parent_token_hash: parentHashB64u },
      response_key: RESPONSE_KEY,
      rTokSeed: rTokSeed('delegated-widen'),
    });

    const stores = makeStores(childScope);
    // Seed the parent in the consumed-token log under our fake hash
    stores.consumedLog.seed(parentHashB64u, parentScope);
    // Template allows the action for the child
    const r = await verifyToken({
      token: child.token,
      now: IAT + 5,
      expectedAud: AUD,
      rsIdentifier: AUD,
      rsCurrentEpoch: EPOCH,
      requestedAction: 'read',
      // Single segment → falls within child `*` (widened) but outside parent `public/*`.
      // Cascade must pass the scope check (step 13), then §8.1 attenuation fires.
      requestedResource: 'secret',
      ...stores,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denial.code).toBe('INSUFFICIENT_PRIVILEGE');
      expect(r.denial.failedCheck).toBe('TBAC_SCOPE_EVALUATION');
      expect(r.denial.internalTag).toContain('r40.8.1.rs_cascade.widening_attack');
    }
  });
});

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  return out;
}
