# Clean-Room Audit Report

Date: 2026-04-21
Repo: `hx_mcp_tbac`
Audit scope: clean-room contamination risk only
Excluded: runtime security, protocol correctness, and logic-bug review

## Executive Summary

On the current workspace state, I did not find direct evidence that the implementation source under `packages/` was copied or ported from a proprietary HAAP codebase. The strongest positive signals are:

- the repo has an explicit clean-room contribution policy,
- there is an automated guard against `haap-*` leakage into clean-room source,
- the current package names and public package manifests are SEP-neutral,
- the cryptographic constants in code use SEP-side `tbac-*` labels rather than Hawcx / HAAP labels.

The remaining risks are mostly presentation and provenance risks, not code-copy signals. The repo still carries Hawcx ownership and HAAP relationship material in documentation, notices, support channels, and bundled spec artifacts. That weakens how neutral the artifact looks when presented as an SEP implementation, even though it does not by itself prove contamination.

## Overall Assessment

Conclusion: low direct code-copy risk, medium presentation/provenance risk.

## Findings

### 1. Low: no direct contamination indicators found in clean-room source

Why this is a positive finding:

- [`CONTRIBUTING.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/CONTRIBUTING.md:7) defines a clean-room boundary and instructs contributors to work from the SEP only.
- [`scripts/no-haap-prefix.sh`](/Users/raviramaraju/Projects/hx_mcp_tbac/scripts/no-haap-prefix.sh:4) enforces a source-level guard against `haap-` strings in clean-room code.
- `pnpm guard:no-haap` passed in the current workspace.
- [`packages/tbac-core-ts/src/crypto/hkdf.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/crypto/hkdf.ts:16) uses SEP-side `tbac-*` / MCP namespaced strings, not Hawcx-branded domain strings.
- [`packages/tbac-core-ts/src/crypto/hkdf.test.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/crypto/hkdf.test.ts:40) explicitly tests against use of the forbidden proprietary prefix.
- [`packages/tbac-core-ts/package.json`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/package.json:2) and [`packages/tbac-mcp-auth/package.json`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-mcp-auth/package.json:2) are now neutrally named.

Assessment:

- This is what a SEP-derived clean-room implementation is expected to look like.
- I do not see code-level naming or constant choices that suggest a direct port from proprietary source.

### 2. Medium: public provenance still centers Hawcx ownership and patent posture

Why it matters:

An implementation can be clean-room in substance but still present itself in a way that makes reviewers question neutrality. The current repo still visibly ties the artifact to Hawcx as a company and to Hawcx patent posture.

Evidence:

- [`NOTICE`](/Users/raviramaraju/Projects/hx_mcp_tbac/NOTICE:2) identifies `Copyright 2026 Hawcx Inc.`
- [`NOTICE`](/Users/raviramaraju/Projects/hx_mcp_tbac/NOTICE:4) says the product includes software developed at Hawcx Inc.
- [`NOTICE`](/Users/raviramaraju/Projects/hx_mcp_tbac/NOTICE:21) contains Hawcx patent-application language.
- [`SECURITY.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/SECURITY.md:7) routes vulnerability reports to `security@hawcx.com`.

Assessment:

- This does not indicate source contamination.
- It does make the repo read as a vendor-owned reference implementation rather than a neutral SEP artifact.

Recommendation:

- If the goal is SEP presentation neutrality, keep legal ownership text where required but move vendor-specific operational language out of primary docs where possible.
- Consider whether `NOTICE` and `SECURITY.md` should be framed more as repository-maintainer metadata and less as part of the protocol story.

### 3. Medium: HAAP relationship material remains intentionally bundled with the implementation

Why it matters:

The repo still contains explicit HAAP alignment material. That can be valid and even necessary because SEP §12 references HAAP, but it increases the amount of proprietary-adjacent context living next to the implementation.

Evidence:

- [`docs/haap-alignment-note.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/docs/haap-alignment-note.md:1) is a dedicated HAAP alignment document.
- [`packages/tbac-core-ts/src/crypto/hkdf.ts`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/src/crypto/hkdf.ts:5) contains the one allowed comment referencing `haap-*` strings.
- [`CONTRIBUTING.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/CONTRIBUTING.md:11) explicitly documents which files are allowed to discuss HAAP.

Assessment:

- The repo is handling this boundary consciously, which is good.
- The remaining risk is review optics: the implementation is not isolated from the proprietary-comparison narrative.

Recommendation:

- Keep HAAP comparison material in one clearly non-source note, which the current tree mostly does.
- Avoid adding any more HAAP relationship commentary inside implementation files beyond the one existing migration note.

### 4. Medium: bundled spec artifacts include extensive proprietary-reference context

Why it matters:

The implementation says the SEP file is the sole normative input. That is consistent with a clean-room process. But the bundled spec files themselves contain extensive HAAP and Hawcx references, including non-normative implementation and patent context. That is a documentation-source risk, not a code-copy indicator.

Evidence:

- [`spec/0000-tbac-task-based-access-control-r40.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/spec/0000-tbac-task-based-access-control-r40.md:8) names Hawcx and the author.
- [`spec/0000-tbac-task-based-access-control-r40.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/spec/0000-tbac-task-based-access-control-r40.md:1308) contains a full HAAP alignment section.
- [`spec/0000-tbac-task-based-access-control-r40.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/spec/0000-tbac-task-based-access-control-r40.md:1728) contains patent notice language.
- The repo also contains a second bundled copy, [`spec/0000-tbac-task-based-access-control-r40-ref.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/spec/0000-tbac-task-based-access-control-r40-ref.md:1), which appears to be a duplicate reference artifact.

Assessment:

- Using the SEP as the sole normative source is the right clean-room rule.
- The SEP itself is not a “neutralized” source document; it carries vendor/proprietary context by design.
- That means the clean-room claim is credible at the code level, but not fully separable from the SEP author’s proprietary context.

Recommendation:

- For presentation, be explicit that clean-room means “implemented from the published SEP text only,” not “implemented from a vendor-neutral source document.”
- Decide whether the extra `-ref.md` copy is necessary in the presentation repo; if not, removing it would reduce noise.

### 5. Low: the current public package surface is materially cleaner than before

Why this matters:

The current workspace already reflects cleanup work that reduces clean-room presentation risk.

Evidence:

- Root package name is neutral: [`package.json`](/Users/raviramaraju/Projects/hx_mcp_tbac/package.json:2) uses `mcp-tbac-reference`.
- Public package names are neutral: [`packages/tbac-core-ts/package.json`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-core-ts/package.json:2) and [`packages/tbac-mcp-auth/package.json`](/Users/raviramaraju/Projects/hx_mcp_tbac/packages/tbac-mcp-auth/package.json:2).
- README package references are neutral: [`README.md`](/Users/raviramaraju/Projects/hx_mcp_tbac/README.md:26).
- The demo-only stub has been renamed accordingly in the current tree.

Assessment:

- These changes materially improve clean-room presentation.
- They also mean any earlier audit comments about Hawcx-branded package names are stale for the current workspace.

## Residual Risk Summary

- Code contamination risk: Low
- Documentation/provenance risk: Medium
- SEP-presentation neutrality risk: Medium

## Recommended Next Actions

1. Keep the current neutral package naming and do not reintroduce vendor-branded package IDs.
2. Keep HAAP references isolated to `docs/haap-alignment-note.md`, the SEP itself, and the single HKDF migration comment.
3. Consider trimming or clearly labeling `NOTICE`, `SECURITY.md`, and other vendor-owned operational docs if the repo will be shown as a neutral SEP artifact.
4. Decide whether `spec/0000-tbac-task-based-access-control-r40-ref.md` is needed; if not, remove it to reduce proprietary-reference duplication.
5. When presenting the repo, phrase the claim precisely: “clean-room implementation from the published SEP text only.”

## Checks Performed

- Reviewed clean-room policy documents and provenance files.
- Reviewed current package names and README/doc surface.
- Reviewed the clean-room guard script and the HKDF domain-string code/comments.
- Ran `pnpm guard:no-haap` successfully.
