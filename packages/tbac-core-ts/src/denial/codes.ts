// SPDX-License-Identifier: Apache-2.0
//
// Denial codes normative to SEP r40 §6. This implementation is base-conformance
// (Profile E + Profile S, enterprise `msg_type = 0x03`). Consumer and T0
// cascades are hook interfaces only, so consumer-only codes (16–17) and
// intent codes are defined here for completeness but only a subset is driven
// by this library's default cascade.

/** The eleven normative denial codes this library's cascade can emit. */
export const DENIAL_CODES = {
  TBAC_REQUIRED: 'TBAC_REQUIRED',
  MALFORMED_TOKEN: 'MALFORMED_TOKEN',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  STALE_TIMESTAMP: 'STALE_TIMESTAMP',
  AUD_MISMATCH: 'AUD_MISMATCH',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  MUTUAL_AUTH_MISMATCH: 'MUTUAL_AUTH_MISMATCH',
  VERIFIER_SECRET_MISMATCH: 'VERIFIER_SECRET_MISMATCH',
  TOKEN_REPLAYED: 'TOKEN_REPLAYED',
  EPOCH_EXPIRED: 'EPOCH_EXPIRED',
  PRIVILEGE_SIG_INVALID: 'PRIVILEGE_SIG_INVALID',
  INSUFFICIENT_PRIVILEGE: 'INSUFFICIENT_PRIVILEGE',
  ORG_ID_MISMATCH: 'ORG_ID_MISMATCH',
  POP_REQUIRED: 'POP_REQUIRED',
  POP_FAILED: 'POP_FAILED',
  CHANNEL_ENCRYPTION_REQUIRED: 'CHANNEL_ENCRYPTION_REQUIRED',
  MALFORMED_REQUEST: 'MALFORMED_REQUEST',
  SCOPE_FIELD_MISSING: 'SCOPE_FIELD_MISSING',
  SCOPE_NON_CANONICAL: 'SCOPE_NON_CANONICAL',
  NON_JSON_POP_NOT_SUPPORTED: 'NON_JSON_POP_NOT_SUPPORTED',
} as const;

export type DenialCode = (typeof DENIAL_CODES)[keyof typeof DENIAL_CODES];

/**
 * The stable `failed_check` identifier attached to denial responses. Step
 * numbers are an implementation detail per §6; clients depend on these
 * strings.
 */
export const FAILED_CHECKS = {
  TOKEN_ABSENT: 'TOKEN_ABSENT',
  FRAMING_CHECK: 'FRAMING_CHECK',
  SESSION_LOOKUP: 'SESSION_LOOKUP',
  TEMPORAL_VALIDATION: 'TEMPORAL_VALIDATION',
  AUDIENCE_VALIDATION: 'AUDIENCE_VALIDATION',
  SESSION_VALIDITY: 'SESSION_VALIDITY',
  SCHNORR_VERIFICATION: 'SCHNORR_VERIFICATION',
  AEAD_DECRYPTION: 'AEAD_DECRYPTION',
  MUTUAL_AUTH_CHECK: 'MUTUAL_AUTH_CHECK',
  VERIFIER_SECRET_CHECK: 'VERIFIER_SECRET_CHECK',
  REPLAY_CONSUME: 'REPLAY_CONSUME',
  POLICY_EPOCH_VALIDATION: 'POLICY_EPOCH_VALIDATION',
  PRIVILEGE_SIGNATURE: 'PRIVILEGE_SIGNATURE',
  TBAC_SCOPE_EVALUATION: 'TBAC_SCOPE_EVALUATION',
  ORG_ID_VALIDATION: 'ORG_ID_VALIDATION',
  POP_MISSING: 'POP_MISSING',
  POP_VERIFICATION: 'POP_VERIFICATION',
  REQUEST_FRAMING: 'REQUEST_FRAMING',
  CHANNEL_ENCRYPTION_MISSING: 'CHANNEL_ENCRYPTION_MISSING',
  CONFORMANCE_SCOPE: 'CONFORMANCE_SCOPE',
} as const;

export type FailedCheck = (typeof FAILED_CHECKS)[keyof typeof FAILED_CHECKS];

/**
 * Distinguishes the two §8.1 attenuation sites. Public denial output maps
 * both to TBAC_SCOPE_EVALUATION / INSUFFICIENT_PRIVILEGE; the internal tag
 * is emitted to telemetry only.
 */
export type AttenuationSite = 'mint' | 'rs';

export interface Denial {
  readonly code: DenialCode;
  readonly failedCheck: FailedCheck;
  readonly message?: string;
  /** For §8.1 distinguishing internal telemetry. Not exposed publicly. */
  readonly internalTag?: string;
}

/** Build a normative-shape denial object. */
export function denial(
  code: DenialCode,
  failedCheck: FailedCheck,
  message?: string,
  internalTag?: string,
): Denial {
  return message !== undefined && internalTag !== undefined
    ? { code, failedCheck, message, internalTag }
    : message !== undefined
      ? { code, failedCheck, message }
      : internalTag !== undefined
        ? { code, failedCheck, internalTag }
        : { code, failedCheck };
}
