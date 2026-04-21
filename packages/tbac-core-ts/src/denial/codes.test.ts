// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { DENIAL_CODES, FAILED_CHECKS, denial } from './codes.js';

describe('denial codes', () => {
  it('exposes the r40 NON_JSON_POP_NOT_SUPPORTED code', () => {
    expect(DENIAL_CODES.NON_JSON_POP_NOT_SUPPORTED).toBe('NON_JSON_POP_NOT_SUPPORTED');
  });

  it('exposes the CONFORMANCE_SCOPE failed-check string', () => {
    expect(FAILED_CHECKS.CONFORMANCE_SCOPE).toBe('CONFORMANCE_SCOPE');
  });

  it('builds a denial with just code + failed check', () => {
    const d = denial(DENIAL_CODES.TOKEN_REPLAYED, FAILED_CHECKS.REPLAY_CONSUME);
    expect(d.code).toBe('TOKEN_REPLAYED');
    expect(d.failedCheck).toBe('REPLAY_CONSUME');
    expect(d.message).toBeUndefined();
    expect(d.internalTag).toBeUndefined();
  });

  it('carries internalTag without leaking into message', () => {
    const d = denial(
      DENIAL_CODES.INSUFFICIENT_PRIVILEGE,
      FAILED_CHECKS.TBAC_SCOPE_EVALUATION,
      undefined,
      'r40.8.1.widening_attack',
    );
    expect(d.internalTag).toBe('r40.8.1.widening_attack');
    expect(d.message).toBeUndefined();
  });
});
