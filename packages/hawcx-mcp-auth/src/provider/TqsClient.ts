// SPDX-License-Identifier: Apache-2.0
//
// Stub TQS for demos and tests. This is NOT a production TQS — it has no
// real session-bootstrap path, no CIBA, no intent verification. What it
// DOES have that IS load-bearing: the §8.1 mint-gate attenuation check.
// When minting a delegated token, the stub invokes `checkAttenuation(child,
// parent, 'mint')` and throws `InvocationRejected` on violation. This is
// the r40 defense-in-depth mint side.

import {
  checkAttenuation,
  mintToken,
  scalarMulBase,
  type ScopeJson,
  type MintedToken,
} from '@hawcx/tbac-core';
import { sha256 } from '@noble/hashes/sha2';

export interface DequeueArgs {
  readonly agent_instance_id: string;
  readonly tool: string;
  readonly action: string;
  readonly resource: string;
  readonly aud: string;
  readonly org_id: string;
  readonly trust_level: 0 | 1 | 2 | 3;
  readonly constraints?: ScopeJson['constraints'];
  readonly human_confirmed_at?: number;
  readonly delegation_depth?: number;
  readonly parent?: { readonly scope: ScopeJson; readonly hashB64u: string };
}

export interface TqsClient {
  /** Mint a fresh opaque token. */
  dequeueToken(args: DequeueArgs): Promise<{ token: Uint8Array; scope: ScopeJson; minted: MintedToken }>;
}

export class InvocationRejected extends Error {
  constructor(
    public readonly reason: string,
    public readonly detail?: string,
  ) {
    super(`InvocationRejected: ${reason}${detail !== undefined ? ' — ' + detail : ''}`);
    this.name = 'InvocationRejected';
  }
}

export interface StubTqsOpts {
  readonly K_session: Uint8Array;
  readonly session_id: bigint;
  readonly policy_epoch: bigint;
  readonly verifier_secret: Uint8Array;
  readonly mutual_auth: Uint8Array;
  readonly response_key: Uint8Array;
  readonly SEK_PK?: Uint8Array; // defaults to (scalar=7)*G for §A.5 compat
  /** Returns Unix-seconds "now". Test injectable. */
  readonly now?: () => number;
  /** Mutable counter for deterministic jti generation in tests. */
  readonly jtiPrefix?: string;
}

export class StubTqsClient implements TqsClient {
  private jtiCounter = 0;
  private readonly sekPk: Uint8Array;

  constructor(private readonly opts: StubTqsOpts) {
    this.sekPk = opts.SEK_PK ?? scalarMulBase(7n);
  }

  async dequeueToken(args: DequeueArgs): Promise<{ token: Uint8Array; scope: ScopeJson; minted: MintedToken }> {
    const now = (this.opts.now ?? (() => Math.floor(Date.now() / 1000)))();
    const scope: ScopeJson = {
      iss: 'stub-tqs',
      sub: 'IK:stub-client',
      agent_instance_id: args.agent_instance_id,
      tool: args.tool,
      action: args.action,
      aud: args.aud,
      resource: args.resource,
      delegation_depth: args.delegation_depth ?? 0,
      org_id: args.org_id,
      trust_level: args.trust_level,
      human_confirmed_at: args.human_confirmed_at ?? 0,
      ...(args.constraints !== undefined ? { constraints: args.constraints } : {}),
      ...(args.parent !== undefined ? { parent_token_hash: args.parent.hashB64u } : {}),
    };

    if (args.parent !== undefined) {
      const d = checkAttenuation(scope, args.parent.scope, 'mint');
      if (d !== null) {
        throw new InvocationRejected(
          'ScopeCeilingExceeded',
          d.message ?? d.internalTag,
        );
      }
    }

    const jti = this.generateJti();
    const token_iv = this.generateIv();
    const rTokSeed = sha256(
      new TextEncoder().encode(
        `stub-tqs-rtok:${jti}:${this.opts.session_id}:${Math.random()}`,
      ),
    );
    const rTokSeed64 = new Uint8Array(64);
    rTokSeed64.set(rTokSeed, 0);
    rTokSeed64.set(rTokSeed, 32);

    const minted = mintToken({
      K_session: this.opts.K_session,
      verifier_secret: this.opts.verifier_secret,
      mutual_auth: this.opts.mutual_auth,
      SEK_PK: this.sekPk,
      session_id: this.opts.session_id,
      policy_epoch: this.opts.policy_epoch,
      iat: now,
      exp: now + 60,
      token_iv,
      jti,
      scope,
      response_key: this.opts.response_key,
      rTokSeed: rTokSeed64,
    });
    return { token: minted.token, scope, minted };
  }

  private generateJti(): string {
    // 16 bytes → 22 b64url chars (no padding). We use a deterministic source
    // so tests can mint repeatable tokens.
    const seed = new Uint8Array(16);
    const c = ++this.jtiCounter;
    seed[0] = (c >> 8) & 0xff;
    seed[1] = c & 0xff;
    const prefix = new TextEncoder().encode(this.opts.jtiPrefix ?? 'stub');
    for (let i = 0; i < Math.min(seed.length - 2, prefix.length); i++) {
      seed[2 + i] = prefix[i]!;
    }
    return Buffer.from(seed).toString('base64url');
  }

  private generateIv(): Uint8Array {
    const iv = new Uint8Array(12);
    iv[0] = 0x01;
    iv[1] = 0x02;
    iv[2] = 0x03;
    iv[3] = 0x04;
    const c = ++this.ivCounter;
    for (let i = 0; i < 8; i++) iv[11 - i] = (c >> (i * 8)) & 0xff;
    return iv;
  }
  private ivCounter = 0;
}
