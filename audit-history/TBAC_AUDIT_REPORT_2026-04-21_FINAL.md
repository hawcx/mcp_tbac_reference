# TBAC Audit Report (Final)

Date: 2026-04-21
Repo: `hx_mcp_tbac`
Reference spec: `spec/0000-tbac-task-based-access-control-r40.md`

## Executive Summary

This audit confirms that the repository has been significantly updated to address previously reported implementation gaps. The 17-step verification cascade now correctly enforces all policy-template ceilings, constraint validations, and conditional field requirements for T3 (trust_level 3) and intent-bearing tokens. Proprietary branding (Hawcx/HAAP) has been removed from the public API surface and primary documentation, supporting the clean-room implementation goal.

However, I identified one **new critical logic bug** in the core `resource` attenuation logic that violates the normative requirements of SEP r40 §8.1. This bug causes the verifier to incorrectly deny access to legitimate resource sub-paths when a literal prefix grant is used.

## Findings

### 1. Critical: `isSubset` logic violates SEP §8.1 literal prefix rule

**Severity: Critical (Conformance & Logic Bug)**

**Description:**
SEP r40 §8.1 explicitly states: *"Two literal patterns are in a subset relationship only when one is an exact prefix of the other at a path-segment boundary (`'public/docs/api'` is a subset of `'public/docs'`)".*

The current implementation in `packages/tbac-core-ts/src/scope/glob.ts` and its accompanying tests in `glob.test.ts` incorrectly treat literal-vs-literal comparisons as requiring exact byte-equality for the entire segment list. This causes `isSubset('public/docs/api', 'public/docs')` to return `false`.

**Impact:**
- **Broken Delegation:** A client holding a token for `public/docs` cannot mint a delegated token for `public/docs/api`, even though this is a valid attenuation.
- **Incorrect Denial:** The Resource Server (RS) will reject requests for `public/docs/api` when the token grant is `public/docs`, violating the "prefix-grant" semantics intended by the spec.

**Evidence:**
- [`packages/tbac-core-ts/src/scope/glob.ts`](packages/tbac-core-ts/src/scope/glob.ts:98): Literal vs literal comparison requires `cs.value === ps.value` AND identical segment counts.
- [`packages/tbac-core-ts/src/scope/glob.test.ts`](packages/tbac-core-ts/src/scope/glob.test.ts:74): The test explicitly asserts that `isSubset('public/docs/api', 'public/docs')` should be `false`, citing a misunderstanding of §8.1.

**Recommendation:**
- Update `segmentsSubset` in `glob.ts` to allow the child to have more segments than the parent if the parent segments are exhausted and matched the child's prefix.
- Update `glob.test.ts` to reflect the correct SEP r40 §8.1 expectations.

---

### 2. High: Verified fixes for previous Audit findings (2026-04-21 v1)

**Severity: Resolved / Verified**

I have verified that the following critical/high issues from the earlier audit have been **resolved**:

- **Constraint Enforcement:** `verify.ts` now correctly checks `min_trust_level`, `permitted_audiences`, `max_rows`, `max_calls`, and `time_window_sec`.
- **`allowed_parameters` Integrity:** `canonical.ts` now correctly canonicalizes the `allowed_parameters` map (sorting keys and using nested TLV tags), ensuring it is cryptographically bound by `priv_sig`.
- **T3 / Intent Validation:** `schema.ts` now enforces `approval_digest` requirements for `trust_level: 3` and ensures coupling between `user_raw_intent` and `intent_hash`.

---

### 3. Medium: Clean-room presentation significantly improved

**Severity: Low/Medium (Presentation)**

**Assessment:**
The repository has been successfully scrubbed of proprietary Hawcx/HAAP branding. `package.json` names, script names, and primary `README.md` text now use SEP-neutral terminology (`mcp-tbac-reference`).

**Residual items:**
- `DemoOnlyStubTqsClient` still uses `Math.random()` and predictable counters for JTI/IV generation. While correctly renamed and documented with warnings, these remain "trap" implementations if copied into production.
- *Recommendation:* Replace `Math.random()` with `crypto.getRandomValues()` even in the demo client to model best practices, or move the entire client into the `test/` or `demo/` directory of the package.

## Clean-Room Assessment

**Posturing:** Strong.
The implementation follows the SEP structure (17-step cascade, TLV appendices) rather than any known proprietary API. The removal of the `haap-` prefix and Hawcx-specific documentation confirms a diligent effort to provide a neutral reference implementation.

## Conclusion

The implementation is high-quality and structurally sound, but **non-conformant to SEP r40** due to the `isSubset` prefix-rule bug. Fixing this logic bug and the associated tests is the final requirement for a presentation-ready SEP reference implementation.

---
*End of Report*
