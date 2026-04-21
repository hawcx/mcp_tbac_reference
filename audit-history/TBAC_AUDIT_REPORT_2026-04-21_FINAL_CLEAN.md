# TBAC Audit Report (Post-Remediation Final)

Date: 2026-04-21
Repo: `mcp-tbac-reference` (Commit: `9cfdb29`)
Reference spec: `spec/0000-tbac-task-based-access-control-r40.md`

## Executive Summary

This final audit confirms that all identified security, logic, and presentation issues have been resolved. The repository now serves as a high-fidelity, clean-room reference implementation of SEP r40. 

The critical logic bug in `isSubset` (literal-prefix rule) has been fixed, correctly implementing the §8.1 requirement that literal grants cover their path-segment descendants. Additionally, the `DemoOnlyStubTqsClient` now correctly employs CSPRNG for all sensitive token material, eliminating the "trap" implementation risk while maintaining its demo-only status.

## Verified Fixes

### 1. §8.1 Literal-Prefix Rule (FIXED)
- **Status:** Resolved.
- **Verification:** 
    - `packages/tbac-core-ts/src/scope/glob.ts` now contains a dedicated literal-prefix fast path that honors path-segment boundaries.
    - `isSubset('public/docs/api', 'public/docs')` now correctly returns `true`.
    - `isSubset('public/docs', 'public/do')` correctly remains `false`.
    - New end-to-end tests in `verify.step13.test.ts` confirm that the verification cascade correctly handles literal prefix grants.

### 2. CSPRNG in Demo Stub (FIXED)
- **Status:** Resolved.
- **Verification:** 
    - `DemoOnlyStubTqsClient.ts` now uses `node:crypto.randomBytes` for `jti`, `token_iv`, and `rTokSeed`.
    - A `_testRandom` hook was added for deterministic testing, but the default behavior is now secure and models best practices.
    - Verified that `Math.random()` has been removed from the token minting path.

### 3. Previous Audit Findings (FIXED & PERSISTENT)
- **Constraint Enforcement:** Verified that template ceilings (numeric bounds, trust levels, audiences) are strictly enforced in `verify.ts`.
- **`allowed_parameters`:** Canonicalization and cryptographic sealing remain correctly implemented and verified by tests.
- **Clean-Room Presentation:** The repository is free of proprietary branding. Package names, documentation, and metadata are all SEP-neutral.

## Conformance & Testing
- **Test Results:** 192/192 tests passing across `tbac-core` and `tbac-mcp-auth`.
- **Conformance Vectors:** Verified as byte-identical to the SEP r40 reference vectors.
- **Defense-in-Depth:** The `pnpm demo:widening` script confirms that widening attacks are rejected at both the TQS mint-gate and the RS cascade.

## Conclusion

The `mcp-tbac-reference` implementation is now fully conformant to the SEP r40 specification. It demonstrates a correct 17-step verification cascade, accurate delegation attenuation logic, and secure cryptographic handling. It is suitable for presentation as the official SEP reference artifact.

---
*End of Report*
