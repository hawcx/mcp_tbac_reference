# TBAC Audit Report

Date: 2026-04-21
Repo: `hx_mcp_tbac`
Reference spec: `spec/0000-tbac-task-based-access-control-r40.md`
External reference reviewed: `/Users/raviramaraju/Downloads/0000-tbac-task-based-access-control-r40.md`

## Scope

This audit covered:

- Clean-room implementation posture
- Security bugs
- Logic / SEP-conformance bugs
- Test and documentation coverage relevant to the above

## Executive Summary

I did not find direct evidence of proprietary source-code contamination. The repository is structurally consistent with a clean-room effort built around the SEP text, and the cryptographic / wire-format core is reasonably well tested.

I did find several material implementation gaps:

1. The verifier does not bind authorization to the actual requested tool, and it does not enforce most `constraints` or several policy-template ceilings at authorization time.
2. `constraints.allowed_parameters` is not included in canonical TLV encoding, so it is not cryptographically bound by `priv_sig` or `parent_token_hash`.
3. Scope validation does not enforce several conditional SEP requirements for T3 / intent-bearing tokens.
4. The repo is not presentation-clean for an SEP submission yet: package names, docs, and public-facing text still prominently carry Hawcx / HAAP branding and comparison material.

## Findings

### 1. Critical: verifier does not bind authorization to the actual requested tool and skips most Step 13 checks

Severity: Critical

Why it matters:
SEP r40 says Step 13 validates `tool`, `action`, `resource`, and `constraints`, and the repo’s own template interface exposes `max_rows`, `max_calls`, `time_window_sec`, `permitted_audiences`, and `min_trust_level`. In the implementation, the verifier has no `requestedTool` input at all, and only checks action membership and resource subset.

Evidence:

- [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:56) exposes only `requestedAction` and `requestedResource` as request-time authorization inputs; there is no `requestedTool`.
- [`packages/hawcx-mcp-auth/src/verifier/TbacTokenVerifier.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/hawcx-mcp-auth/src/verifier/TbacTokenVerifier.ts:32) also only accepts `requestedAction` and `requestedResource`.
- [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:227) begins Step 13.
- [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:241) only checks `allowed_actions`.
- [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:250) only checks `requestedAction` and `requestedResource`.
- [`packages/tbac-core-ts/src/stores/interfaces.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/stores/interfaces.ts:31) defines unused ceilings: `max_rows`, `max_calls`, `time_window_sec`, `permitted_audiences`, `min_trust_level`.

Impact:

- A token can be presented against the wrong tool and the verifier has no direct way to detect that mismatch.
- A token carrying `constraints.allowed_parameters` is accepted without any argument binding.
- A tool template that requires `min_trust_level: 3` can still be used by a `trust_level: 0/1/2` token.
- Template `permitted_audiences` is not consulted.
- Numeric ceilings in the template are not enforced at verification time.

Recommendation:

- Extend `VerifyInputs` with the request fields Step 13 actually needs: `requestedTool`, tool arguments, selected audience, and any execution metadata needed for numeric guardrails.
- Enforce all Step 13 constraint checks explicitly.
- Add tests that prove denial on tool mismatch, `min_trust_level`, `permitted_audiences`, and `allowed_parameters` violations.

### 2. High: `allowed_parameters` is not canonicalized, so it is not cryptographically sealed

Severity: High

Why it matters:
SEP r40 explicitly defines `constraints.allowed_parameters` as part of the authorization scope and Appendix A assigns it a TLV tag. This implementation defines the tag, but then omits the field from canonicalization and decoding. That means parameter constraints are not included in the bytes protected by `priv_sig`, and are also absent from `parent_token_hash`.

Evidence:

- [`packages/tbac-core-ts/src/scope/canonical.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/canonical.ts:37) defines `allowed_parameters: 0x06`.
- [`packages/tbac-core-ts/src/scope/canonical.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/canonical.ts:124) canonicalizes constraints.
- [`packages/tbac-core-ts/src/scope/canonical.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/canonical.ts:134) explicitly says `allowed_parameters omitted from canonical form in this revision`.
- [`packages/tbac-core-ts/src/scope/canonical.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/canonical.ts:214) does not decode `allowed_parameters` either.
- [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:222) recomputes `priv_sig` from this incomplete canonical form.

Impact:

- The implementation claims parameter-bound authorization, but the cryptographic binding excludes the parameter constraint object.
- Delegation-chain hashes also ignore that field, which weakens attenuation integrity if parameter constraints are introduced later.
- Unknown constraint fields are also effectively treated leniently at the schema/canonicalization layer instead of being rejected unless `x-`-prefixed, contrary to SEP §3.3.

Recommendation:

- Implement canonical TLV encoding/decoding for `allowed_parameters` exactly per Appendix A.
- Reject unknown constraint keys unless they begin with `x-`.
- Add conformance vectors and round-trip tests that include escaped wildcard patterns.
- Treat current behavior as non-conformant rather than “deferred”, because the field is already in the schema and registry.

### 3. High: scope validation misses required conditional fields for T3 and intent-bearing tokens

Severity: High

Why it matters:
The schema validator enforces `trust_level` and `human_confirmed_at`, but not the rest of the conditional SEP rules. In particular, a T3 token can be accepted without `approval_digest`, and a scope carrying `user_raw_intent` can be accepted without `intent_hash`.

Evidence:

- [`packages/tbac-core-ts/src/scope/schema.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/schema.ts:152) validates `human_confirmed_at`.
- [`packages/tbac-core-ts/src/scope/schema.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/schema.ts:229) only copies `approval_digest` if present; it is never required or format-checked.
- [`packages/tbac-core-ts/src/scope/schema.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/schema.ts:234) only copies `user_raw_intent` / `intent_hash` if present; coupling is never enforced.

Impact:

- T3 scopes can bypass the approval-binding invariant.
- Intent-bearing scopes can bypass the integrity precondition for Step 13.7.
- Malformed hex fields can reach canonicalization and fail late or inconsistently.

Recommendation:

- Require `approval_digest` for `trust_level = 3`, forbid it for lower trust levels, and validate it as 64 lowercase hex chars.
- Require `intent_hash` when `user_raw_intent` is present, and validate it as 64 lowercase hex chars.
- Validate `txn_id` length/format as 16 raw bytes encoded as 32 lowercase hex chars.
- Add negative tests for each conditional field rule.

### 4. Medium: clean-room presentation is weaker than the code posture

Severity: Medium

Why it matters:
I did not see evidence of copied proprietary implementation code. However, if this repo is going to be presented as an SEP-oriented clean-room implementation, the public presentation is still tightly coupled to Hawcx / HAAP naming and comparison material.

Evidence:

- [`package.json`](/Users/raviramaraju/Projects/hx_mcp_tbac/package.json:13) uses `hawcx-mcp-auth` in scripts.
- [`README.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/README.md:26) advertises packages as `@hawcx/tbac-core` and `hawcx-mcp-auth`.
- [`README.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/README.md:39) links a `relationship-to-haap` explainer as standard documentation.
- [`SECURITY.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/SECURITY.md:7) routes vulnerability reports to a Hawcx address.
- [`docs/relationship-to-haap.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/docs/relationship-to-haap.md:1) is explicitly framed around the proprietary product boundary.

Assessment:

- This is a presentation / review-risk issue, not proof of contamination.
- The repo currently reads more like “Hawcx’s public reference implementation of its SEP proposal” than like a neutral SEP implementation artifact.

Recommendation:

- Rename packages and scripts to SEP-neutral names before presentation.
- Move HAAP-comparison material into a separate maintainer note or archival doc.
- Keep the clean-room policy, but reduce proprietary branding in the public API surface.

### 5. Medium: demo TQS uses non-CSPRNG token material and could be misused outside tests

Severity: Medium

Why it matters:
The file correctly says it is not production, but it still exposes a `TqsClient` implementation that mints real tokens. It derives `rTokSeed` from `Math.random()` and uses a predictable counter-based JTI / IV scheme intended for demos. If copied into real usage, it would undercut replay and nonce guarantees.

Evidence:

- [`packages/hawcx-mcp-auth/src/provider/TqsClient.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/hawcx-mcp-auth/src/provider/TqsClient.ts:3) says this is not production.
- [`packages/hawcx-mcp-auth/src/provider/TqsClient.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/hawcx-mcp-auth/src/provider/TqsClient.ts:100) uses `Math.random()` in `rTokSeed` generation.
- [`packages/hawcx-mcp-auth/src/provider/TqsClient.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/hawcx-mcp-auth/src/provider/TqsClient.ts:127) generates deterministic JTIs from a counter and prefix.
- [`packages/hawcx-mcp-auth/src/provider/TqsClient.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/hawcx-mcp-auth/src/provider/TqsClient.ts:141) generates IVs from a fixed prefix and local counter.

Assessment:

- Acceptable for test/demo code.
- Risky because the type is named as a normal client and lives in the main package, so integrators may treat it as a starter implementation.

Recommendation:

- Rename it to something unmistakably non-production, for example `DemoOnlyStubTqsClient`.
- Add runtime warnings or move it under a `demo/` path.

## Clean-Room Assessment

Positive signals:

- The repo contains an explicit clean-room policy and an anti-`haap-` guard.
- The cryptographic code uses third-party libraries, not embedded proprietary primitives.
- The implementation tracks the SEP structure closely rather than mirroring an obviously separate internal API layout.

Reservations:

- The repo still carries substantial Hawcx / HAAP naming and provenance material in package names, docs, and support channels.
- That weakens the neutrality of the artifact even if the implementation itself appears clean-room.

Conclusion:

No direct code-copy red flags found. Presentation and packaging should still be cleaned up before using this as a neutral SEP submission artifact.

## Test / Review Notes

Checks run:

- Read the external reference markdown from `/Users/raviramaraju/Downloads/0000-tbac-task-based-access-control-r40.md`
- Reviewed core files under `packages/tbac-core-ts` and `packages/hawcx-mcp-auth`
- Ran `pnpm test` at repo root
- Ran `CI=1 pnpm --filter hawcx-mcp-auth test`

Observed:

- Existing tests pass.
- Current test coverage is strong for wire format, crypto vectors, and the r40 `resource` attenuation fix.
- Current test coverage does not exercise the missing Step 13 checks or the conditional T3 / intent field rules.

## Recommended Next Actions

1. Fix `allowed_parameters` canonicalization and add conformance vectors for it.
2. Expand Step 13 verifier inputs and enforce `constraints`, `min_trust_level`, and `permitted_audiences`.
3. Tighten schema validation for `approval_digest`, `txn_id`, and `intent_hash`.
4. Add regression tests for all of the above before presenting this as SEP-quality reference code.
5. Remove or downscope Hawcx / HAAP branding from package names and default docs if the goal is a neutral SEP presentation artifact.
