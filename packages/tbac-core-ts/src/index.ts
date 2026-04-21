// SPDX-License-Identifier: Apache-2.0
export { SEP_VERSION, SEP_VERSION_R40, R39_VERSION, EXTENSION_KEY } from './version.js';
export * as wire from './wire/index.js';
export * as crypto from './crypto/index.js';
export * as scope from './scope/index.js';
export * from './denial/codes.js';
export * from './stores/interfaces.js';
export * from './stores/memory.js';
export { verifyToken, type VerifyInputs, type VerifyOutcome, type VerifyFailure } from './cascade/verify.js';
export { mintToken, type MintInputs, type MintedToken } from './cascade/mint.js';
export {
  scalarMulBase,
  scalarReduce64,
  hashToScalar,
  GROUP_ORDER,
} from './crypto/schnorr.js';
export {
  hkdfSha256,
  u8,
  u64be,
  concat,
  ZERO_SALT_32,
  DOMAIN_TOKEN_ENC,
  DOMAIN_TOKEN_SIGN,
  DOMAIN_REQ_ENC,
  DOMAIN_RESP_ENC,
  DOMAIN_RESP_IV,
  DOMAIN_PRIV_SIG,
  DOMAIN_POP,
  DOMAIN_SCHNORR_NONCE,
  DOMAIN_REQ_AAD,
  DOMAIN_RESP_AAD,
  ALL_DOMAINS,
} from './crypto/hkdf.js';
export { hmacSha256, constantTimeEqual } from './crypto/hmac.js';
export { sha256 } from './crypto/sha256.js';
export { canonicalizeScope, decanonicalizeScope, canonicalizeConstraints } from './scope/canonical.js';
export { computeApprovalDigest, approvalDigestHex } from './scope/approval.js';
export {
  checkAttenuation,
  type AttenuationSite,
} from './scope/attenuation.js';
export { isSubset, parsePattern } from './scope/glob.js';
export {
  validateScope,
  type ScopeJson,
  type Constraints,
} from './scope/schema.js';
export { emitR39Fallback, defaultFallbackSink, type FallbackSink, type FallbackWarning } from './scope/r39_fallback.js';
export { type Denial, DENIAL_CODES, FAILED_CHECKS, denial } from './denial/codes.js';
