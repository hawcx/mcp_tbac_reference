// SPDX-License-Identifier: Apache-2.0
//
// DEMO-ONLY stub TQS.
//
// This class is explicitly NOT a production TQS. It exists to:
//   (1) make `pnpm demo` runnable end-to-end,
//   (2) exercise the §8.1 mint-gate attenuation check (which IS normative and
//       lives in tbac-core — this class only calls it),
//   (3) give integrators a working minimal example of the `TqsClient`
//       interface shape.
//
// DO NOT USE THIS IN PRODUCTION. It lacks:
//   - a real X3DH session bootstrap (session keys are injected by the caller
//     rather than negotiated)
//   - CIBA, intent verification, and PoP
//   - token pre-minting / queueing, rate-limit budgets, and mint policy
//     enforcement
//   - destination-binding validation against `SetDestinationPolicy`
//   - the Authenticator IPC channel and IPC type codes (§11.3)
//   - zeroization of derived key material (MUST per §3.0.3 Step 8)
//   - side-channel resistance (nonce-reuse audit, constant-time code paths)
//
// The randomness primitives it DOES use — `jti`, `token_iv`, and the Schnorr
// nonce seed — are all drawn from `node:crypto`'s `randomBytes`, which is
// the platform CSPRNG. This satisfies §3.0 (128-bit CSPRNG `jti`), §3.0.1
// (per-token unique IV), and §3.0.1 Step 6(a) (randomized Schnorr nonce).
// A test-only `_testRandom` hook is provided for deterministic fixtures;
// production implementations of `TqsClient` MUST NOT expose such a hook.

import {
  checkAttenuation,
  mintToken,
  scalarMulBase,
  type ScopeJson,
  type MintedToken,
} from 'tbac-core';
import { randomBytes } from 'node:crypto';

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
  /**
   * Test-only CSPRNG override. If provided, supplies the bytes used for
   * `jti`, `token_iv`, and `r_tok` seeds. Do NOT use in production; the
   * whole point of `randomBytes` is to use the platform CSPRNG. Production
   * implementations of this interface should NEVER expose such a hook.
   */
  readonly _testRandom?: (n: number) => Uint8Array;
}

let demoWarningEmitted = false;

export class DemoOnlyStubTqsClient implements TqsClient {
  private readonly sekPk: Uint8Array;
  private readonly rand: (n: number) => Uint8Array;

  constructor(private readonly opts: StubTqsOpts) {
    this.sekPk = opts.SEK_PK ?? scalarMulBase(7n);
    this.rand = opts._testRandom ?? ((n) => new Uint8Array(randomBytes(n).buffer));
    if (!demoWarningEmitted && process.env['TBAC_SUPPRESS_DEMO_WARNING'] !== '1') {
      demoWarningEmitted = true;
      // eslint-disable-next-line no-console
      console.warn(
        '[tbac] DemoOnlyStubTqsClient instantiated — this is NOT a production TQS. ' +
          'See the module docstring. Set TBAC_SUPPRESS_DEMO_WARNING=1 to silence.',
      );
    }
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

    // All three sources use CSPRNG (node's crypto.randomBytes by default).
    // §3.0.3 requires 128-bit CSPRNG for jti, globally-unique IV, and
    // CSPRNG for the Schnorr nonce (reuse of r_tok with the same tqs_sk
    // leaks the signing key).
    const jti = Buffer.from(this.rand(16)).toString('base64url');
    const token_iv = this.rand(12);
    const rTokSeed64 = this.rand(64);

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

}
