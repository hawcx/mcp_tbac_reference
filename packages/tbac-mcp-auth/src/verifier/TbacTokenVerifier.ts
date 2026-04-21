// SPDX-License-Identifier: Apache-2.0
//
// Server-side cascade orchestration. Wraps tbac-core's verifyToken
// with an MCP-flavoured API: extracts the token from `_meta`, runs the
// cascade, and returns either a structured denial envelope or a success
// with `req.tbacScope` attached.

import {
  verifyToken,
  type ConsumedTokenLog,
  type PolicyTemplateStore,
  type ReplayStore,
  type ScopeJson,
  type SessionStore,
  type VerifyFailure,
  type VerifyOutcome,
  type FallbackSink,
} from 'tbac-core';
import { extractTbacMeta } from '../meta/embed.js';

export interface VerifierConfig {
  readonly rsIdentifier: string;
  readonly expectedAud?: string;
  readonly rsCurrentEpoch: bigint;
  readonly sessions: SessionStore;
  readonly replay: ReplayStore;
  readonly templates: PolicyTemplateStore;
  readonly consumedLog?: ConsumedTokenLog;
  /** Toggles r39 transition-window fallback; defaults to true. */
  readonly acceptR39Tokens?: boolean;
  readonly clockSkewSec?: number;
  readonly now?: () => number;
  readonly fallbackSink?: FallbackSink;
}

export interface VerificationRequest {
  readonly meta: unknown;
  /** The MCP tool name the RS is about to execute (i.e. `tools/call` `name`). */
  readonly requestedTool: string;
  readonly requestedAction: string;
  readonly requestedResource: string;
  /** Decrypted tool arguments, used for §3.3 `allowed_parameters` enforcement. */
  readonly toolArguments?: Record<string, unknown>;
  /** Peer-advertised capability version (from the capability-negotiation handshake). */
  readonly peerVersion?: string;
  /**
   * Overrides the value inferred from `_meta[...].enc` presence. Useful when
   * an upstream component (e.g. an edge proxy) terminates the confidential
   * channel before the verifier runs, so the `enc` envelope is no longer on
   * the wire but the request was in fact encrypted end-to-end.
   */
  readonly requestHasEncryption?: boolean;
}

export type VerificationResult =
  | (VerifyOutcome & { readonly denialEnvelope?: undefined })
  | (VerifyFailure & { readonly denialEnvelope: DenialEnvelope });

export interface DenialEnvelope {
  readonly result: {
    readonly isError: true;
    readonly content: readonly [{ readonly type: 'text'; readonly text: string }];
    readonly _meta: {
      readonly 'io.modelcontextprotocol/tbac': {
        readonly denied: true;
        readonly reason: string;
        readonly failed_check: string;
      };
    };
  };
}

export class TbacTokenVerifier {
  constructor(private readonly cfg: VerifierConfig) {}

  async verify(req: VerificationRequest): Promise<VerificationResult> {
    const extracted = extractTbacMeta(req.meta);
    if (extracted === null) {
      return failureEnvelope({
        ok: false,
        denial: {
          code: 'TBAC_REQUIRED',
          failedCheck: 'TOKEN_ABSENT',
          message: 'no TBAC token present in _meta',
        },
      });
    }
    const now = (this.cfg.now ?? (() => Math.floor(Date.now() / 1000)))();
    // `requestHasEncryption` is sourced from the on-wire `_meta[...].enc`
    // presence bit; the §3.3 `require_channel_encryption` gate in the core
    // cascade consumes it. Callers that terminate channel encryption before
    // reaching this verifier can override via VerificationRequest.
    const requestHasEncryption =
      req.requestHasEncryption !== undefined
        ? req.requestHasEncryption
        : extracted.hasEncryption;
    const verifyInputs = {
      token: extracted.token,
      now,
      expectedAud: this.cfg.expectedAud ?? this.cfg.rsIdentifier,
      rsIdentifier: this.cfg.rsIdentifier,
      rsCurrentEpoch: this.cfg.rsCurrentEpoch,
      requestedTool: req.requestedTool,
      requestedAction: req.requestedAction,
      requestedResource: req.requestedResource,
      sessions: this.cfg.sessions,
      replay: this.cfg.replay,
      templates: this.cfg.templates,
      acceptR39Tokens: this.cfg.acceptR39Tokens ?? true,
      requestHasEncryption,
      ...(req.toolArguments !== undefined ? { toolArguments: req.toolArguments } : {}),
      ...(this.cfg.consumedLog !== undefined ? { consumedLog: this.cfg.consumedLog } : {}),
      ...(this.cfg.clockSkewSec !== undefined ? { clockSkewSec: this.cfg.clockSkewSec } : {}),
      ...(req.peerVersion !== undefined ? { peerVersion: req.peerVersion } : {}),
      ...(this.cfg.fallbackSink !== undefined ? { fallbackSink: this.cfg.fallbackSink } : {}),
    };
    const result = await verifyToken(verifyInputs);
    if (result.ok) return result;
    return failureEnvelope(result);
  }
}

function failureEnvelope(fail: VerifyFailure): VerificationResult {
  return {
    ...fail,
    denialEnvelope: {
      result: {
        isError: true as const,
        content: [{ type: 'text' as const, text: `TBAC denial: ${fail.denial.code}` }] as const,
        _meta: {
          'io.modelcontextprotocol/tbac': {
            denied: true as const,
            reason: fail.denial.code,
            failed_check: fail.denial.failedCheck,
          },
        },
      },
    },
  };
}

export function _dummyExport(_x: ScopeJson): void {
  void _x;
}
