// SPDX-License-Identifier: Apache-2.0
//
// Structured deprecation-warning emission for the r39→r40 transition window.
// The caller pairs this with a `validateScope({ acceptR39Tokens: true,
// peerVersion: '2026-04-17-r39' })` invocation; when the fallback coercion
// is exercised, this helper emits a single structured log line and returns.

export interface FallbackWarning {
  readonly level: 'warn';
  readonly event: 'tbac.r39_resource_fallback';
  readonly jti: string;
  readonly agent_instance_id: string;
  readonly message: string;
}

export interface FallbackSink {
  warn(record: FallbackWarning): void;
}

/** Default sink writes a JSON line to `console.warn`. */
export const defaultFallbackSink: FallbackSink = {
  warn(record) {
    // eslint-disable-next-line no-console
    console.warn(JSON.stringify(record));
  },
};

export function emitR39Fallback(
  sink: FallbackSink,
  jti: string,
  agent_instance_id: string,
): void {
  sink.warn({
    level: 'warn',
    event: 'tbac.r39_resource_fallback',
    jti,
    agent_instance_id,
    message: "r39-format token with absent resource coerced to '*'; update producer to r40",
  });
}
