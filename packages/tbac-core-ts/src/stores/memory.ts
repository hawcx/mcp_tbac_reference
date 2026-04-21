// SPDX-License-Identifier: Apache-2.0
//
// In-memory stores. Production deployments swap these with Redis / PostgreSQL
// / whatever. The MemoryReplayStore uses a simple promise chain to provide
// atomic SETNX semantics for the unit tests.

import type { ScopeJson } from '../scope/schema.js';
import type {
  ConsumedTokenLog,
  PolicyTemplate,
  PolicyTemplateStore,
  ReplayStore,
  SessionRecord,
  SessionStore,
} from './interfaces.js';

export class MemorySessionStore implements SessionStore {
  private readonly map = new Map<string, SessionRecord>();
  put(session_id: bigint, record: SessionRecord): void {
    this.map.set(session_id.toString(), record);
  }
  async getSession(session_id: bigint): Promise<SessionRecord | null> {
    return this.map.get(session_id.toString()) ?? null;
  }
}

export class MemoryReplayStore implements ReplayStore {
  private readonly set = new Set<string>();
  private chain: Promise<unknown> = Promise.resolve();
  async checkReplay(session_id: bigint, jti: string): Promise<boolean> {
    return this.set.has(`${session_id}:${jti}`);
  }
  async commitReplay(session_id: bigint, jti: string, _ttlSec: number): Promise<boolean> {
    // Serialise all commits to emulate single-node atomic SETNX.
    const priorChain = this.chain;
    const done: { ok: boolean } = { ok: false };
    this.chain = priorChain.then(async () => {
      await priorChain;
      const key = `${session_id}:${jti}`;
      if (this.set.has(key)) {
        done.ok = false;
        return;
      }
      this.set.add(key);
      done.ok = true;
    });
    await this.chain;
    return done.ok;
  }
}

export class MemoryPolicyTemplateStore implements PolicyTemplateStore {
  private readonly map = new Map<string, PolicyTemplate>();
  put(agent_instance_id: string, tool: string, tpl: PolicyTemplate): void {
    this.map.set(`${agent_instance_id}|${tool}`, tpl);
  }
  async getTemplate(agent_instance_id: string, tool: string): Promise<PolicyTemplate | null> {
    return this.map.get(`${agent_instance_id}|${tool}`) ?? null;
  }
}

export class MemoryConsumedTokenLog implements ConsumedTokenLog {
  private readonly byJti = new Map<string, ScopeJson>();
  private readonly byHash = new Map<string, ScopeJson>();
  async recordConsumption(
    jti: string,
    scope_hash: Uint8Array,
    scope: ScopeJson,
  ): Promise<void> {
    this.byJti.set(jti, scope);
    this.byHash.set(bytesToB64Url(scope_hash), scope);
  }
  async lookupParent(parent_token_hash_b64u: string): Promise<ScopeJson | null> {
    return this.byHash.get(parent_token_hash_b64u) ?? null;
  }
  /** Test-only helper to seed a delegated-parent relationship. */
  seed(scope_hash_b64u: string, scope: ScopeJson): void {
    this.byHash.set(scope_hash_b64u, scope);
  }
}

function bytesToB64Url(b: Uint8Array): string {
  const bin = Array.from(b, (x) => String.fromCharCode(x)).join('');
  const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
