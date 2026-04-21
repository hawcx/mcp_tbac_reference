# TBAC Audit Rerun Addendum

Date: 2026-04-21
Commit audited: `9cfdb29`
Purpose: verify whether the earlier audit findings remain open at current `HEAD`

## Summary

The previously reported critical findings are closed in the current tree.

Validated fixes present in code:

- `§8.1` literal-prefix rule is implemented in [`packages/tbac-core-ts/src/scope/glob.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/glob.ts:67).
- Requested-tool binding is enforced in [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:245).
- Step 13 template ceilings and `allowed_parameters` enforcement are present in [`packages/tbac-core-ts/src/cascade/verify.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/cascade/verify.ts:284).
- Conditional scope validation and unknown-constraint rejection are present in [`packages/tbac-core-ts/src/scope/schema.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/schema.ts:197).
- `allowed_parameters` canonicalization is present in [`packages/tbac-core-ts/src/scope/canonical.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/scope/canonical.ts:126).

Verification run results:

- `pnpm test`: passed
  - core: 177 tests
  - MCP package: 15 tests
- `pnpm typecheck`: passed
- `pnpm guard:no-haap`: passed

## New Finding

### Low: stale demo-stub module docstring contradicts current implementation

The implementation now uses CSPRNG-backed generation for `jti`, `token_iv`, and `rTokSeed`, but the module docstring still says the class uses predictable counter-based values and `Math.random()`.

Evidence:

- Stale comment: [`packages/tbac-mcp-auth/src/provider/DemoOnlyStubTqsClient.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-mcp-auth/src/provider/DemoOnlyStubTqsClient.ts:12)
- Current implementation: [`packages/tbac-mcp-auth/src/provider/DemoOnlyStubTqsClient.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-mcp-auth/src/provider/DemoOnlyStubTqsClient.ts:127)

Assessment:

- This is documentation drift, not a remaining conformance or security defect in the audited code path.
- The earlier “demo stub CSPRNG” residual concern is closed in implementation.

Recommendation:

- Update the module docstring so it matches the current behavior and only warns about the demo-only limitations that still remain.

## Environment Note

I could not independently confirm the claim that `pnpm demo` and `pnpm demo:widening` exit `0` in this sandbox, because `tsx` failed before app code ran with a local IPC pipe permission error (`listen EPERM .../tsx-...pipe`). That appears to be an execution-environment limitation, not an application failure.

## Conclusion

Against `HEAD 9cfdb29`, the earlier critical audit findings do not reproduce. The only new issue found in this rerun is low-severity documentation drift in the demo stub.
