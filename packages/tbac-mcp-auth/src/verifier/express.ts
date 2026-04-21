// SPDX-License-Identifier: Apache-2.0
//
// Express adapter. We avoid a hard dependency on express by typing via
// structural duck-types — any (req, res, next) trio with matching shape works.

import type { TbacTokenVerifier } from './TbacTokenVerifier.js';

export interface ExpressReqLike {
  body?: unknown;
  [k: string]: unknown;
}
export interface ExpressResLike {
  status(code: number): this;
  json(body: unknown): this;
}
export type ExpressNextLike = (err?: unknown) => void;

export interface TbacExpressOptions {
  readonly getRequestedAction: (req: ExpressReqLike) => string;
  readonly getRequestedResource: (req: ExpressReqLike) => string;
  readonly getMeta: (req: ExpressReqLike) => unknown;
  readonly getPeerVersion?: (req: ExpressReqLike) => string | undefined;
}

export function tbacExpress(verifier: TbacTokenVerifier, opts: TbacExpressOptions) {
  return async (req: ExpressReqLike, res: ExpressResLike, next: ExpressNextLike): Promise<void> => {
    const r = await verifier.verify({
      meta: opts.getMeta(req),
      requestedAction: opts.getRequestedAction(req),
      requestedResource: opts.getRequestedResource(req),
      ...(opts.getPeerVersion?.(req) !== undefined
        ? { peerVersion: opts.getPeerVersion!(req)! }
        : {}),
    });
    if (!r.ok) {
      res.status(200).json({ jsonrpc: '2.0', id: null, ...r.denialEnvelope });
      return;
    }
    (req as ExpressReqLike)['tbacScope'] = r.scope;
    next();
  };
}
