// SPDX-License-Identifier: Apache-2.0
//
// Hono adapter. Typed via structural duck-types to avoid a hard dep.

import type { TbacTokenVerifier } from './TbacTokenVerifier.js';

export interface HonoContextLike {
  req: {
    json(): Promise<unknown>;
    header(name: string): string | undefined;
  };
  json(body: unknown, status?: number): Response;
  set(key: string, value: unknown): void;
}
export type HonoNextLike = () => Promise<void>;

export interface TbacHonoOptions {
  readonly getRequestedTool: (body: unknown) => string;
  readonly getRequestedAction: (body: unknown) => string;
  readonly getRequestedResource: (body: unknown) => string;
  readonly getToolArguments?: (body: unknown) => Record<string, unknown> | undefined;
  readonly getMeta: (body: unknown) => unknown;
  readonly getPeerVersion?: (c: HonoContextLike) => string | undefined;
}

export function tbacHono(verifier: TbacTokenVerifier, opts: TbacHonoOptions) {
  return async (c: HonoContextLike, next: HonoNextLike): Promise<Response | undefined> => {
    const body = await c.req.json();
    const toolArgs = opts.getToolArguments?.(body);
    const r = await verifier.verify({
      meta: opts.getMeta(body),
      requestedTool: opts.getRequestedTool(body),
      requestedAction: opts.getRequestedAction(body),
      requestedResource: opts.getRequestedResource(body),
      ...(toolArgs !== undefined ? { toolArguments: toolArgs } : {}),
      ...(opts.getPeerVersion?.(c) !== undefined ? { peerVersion: opts.getPeerVersion!(c)! } : {}),
    });
    if (!r.ok) return c.json({ jsonrpc: '2.0', id: null, ...r.denialEnvelope });
    c.set('tbacScope', r.scope);
    await next();
    return undefined;
  };
}
