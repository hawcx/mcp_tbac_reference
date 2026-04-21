// SPDX-License-Identifier: Apache-2.0
import type { ScopeJson } from '../scope/schema.js';

/** Session record retrieved at cascade Step 2 (§3.0.2). */
export interface SessionRecord {
  readonly K_session: Uint8Array; // 32 bytes
  readonly verifier_secret: Uint8Array; // 32 bytes
  readonly mutual_auth: Uint8Array; // 32 bytes
  readonly SEK_PK: Uint8Array; // 32 bytes (compressed Ristretto255)
  readonly response_key_seed?: Uint8Array;
  readonly profile: 'E' | 'S';
  readonly org_id: string;
  readonly status: 'active' | 'suspended' | 'expired';
  readonly session_start: number; // Unix seconds
  readonly max_session_duration: number; // seconds
  readonly pop_pub?: Uint8Array;
}

export interface SessionStore {
  getSession(session_id: bigint): Promise<SessionRecord | null>;
}

/** Two-phase replay reserve/commit per §4.3 Steps 10+15. */
export interface ReplayStore {
  /** Non-destructive check — returns true iff jti already consumed. */
  checkReplay(session_id: bigint, jti: string): Promise<boolean>;
  /** Atomic SETNX-equivalent commit. Returns true iff this caller won the race. */
  commitReplay(session_id: bigint, jti: string, ttlSec: number): Promise<boolean>;
}

export interface PolicyTemplate {
  readonly currentEpoch: bigint;
  /** Per-tool ceiling applied at Step 13 authorization. */
  readonly ceiling: {
    readonly allowed_actions: readonly string[];
    readonly max_rows?: number;
    readonly max_calls?: number;
    readonly time_window_sec?: number;
    readonly permitted_audiences?: readonly string[];
    readonly min_trust_level?: 0 | 1 | 2 | 3;
  };
}

export interface PolicyTemplateStore {
  getTemplate(agent_instance_id: string, tool: string): Promise<PolicyTemplate | null>;
}

/** Records consumed-token metadata for §8 same-RS delegation verification. */
export interface ConsumedTokenLog {
  recordConsumption(jti: string, scope_hash: Uint8Array, scope: ScopeJson): Promise<void>;
  /** Returns the parent scope JSON for a given base64url(parent_token_hash). */
  lookupParent(parent_token_hash_b64u: string): Promise<ScopeJson | null>;
}
