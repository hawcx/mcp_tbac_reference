// SPDX-License-Identifier: Apache-2.0
//
// Client-side AuthProvider. On each tool call, calls the injected TqsClient
// to acquire a token and embeds it into the request's `_meta`. This is the
// minimal wire adapter — the real heavy lifting is in the TQS. The provider
// has no crypto material of its own.

import { SEP_VERSION } from '@hawcx/tbac-core';
import { embedToken } from '../meta/embed.js';
import type { TqsClient, DequeueArgs } from './DemoOnlyStubTqsClient.js';

export interface AttachOptions extends DequeueArgs {
  /** MCP JSON-RPC request object to decorate. */
  readonly request: {
    readonly params?: Record<string, unknown>;
  };
}

export class TbacAuthProvider {
  readonly version = SEP_VERSION;
  constructor(private readonly tqs: TqsClient) {}

  /** Attach a fresh TBAC token to the given MCP request's `_meta`. */
  async attachToken(opts: AttachOptions): Promise<{
    request: Record<string, unknown>;
    jti: string;
    tokenBytes: Uint8Array;
  }> {
    const { token, minted, scope } = await this.tqs.dequeueToken(opts);
    const params = opts.request.params ?? {};
    const meta = (params['_meta'] as Record<string, unknown> | undefined) ?? {};
    const decorated = {
      ...opts.request,
      params: {
        ...params,
        _meta: {
          ...meta,
          ...embedToken(token),
        },
      },
    };
    // minted.scope_tlv is available for testing — we only return what the caller needs.
    void minted;
    void scope;
    return {
      request: decorated,
      jti: this.extractJti(token),
      tokenBytes: token,
    };
  }

  private extractJti(token: Uint8Array): string {
    // jti lives at offsets 80–101 in the wire format (§3.0).
    return new TextDecoder('utf-8').decode(token.slice(80, 102));
  }
}
