# Implementation Summary

**Repository:** `mcp-tbac-reference`
**SEP version:** `2026-04-20-r40`
**License:** Apache 2.0 (SPDX headers on every source file)
**Spec source:** [`spec/0000-tbac-task-based-access-control-r40.md`](spec/0000-tbac-task-based-access-control-r40.md) — the single normative input

A clean-room TypeScript reference implementation of MCP Task-Based Access Control (SEP r40). Two workspace packages, no runtime dependency on any vendor-proprietary code, language-neutral conformance vectors, and a CI guard that forbids the `haap-` prefix in library source.

## Status

| Axis | State |
|---|---|
| Tests | **192 passing** (177 core + 15 MCP) across 19 test files |
| Typecheck | Clean (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) |
| Coverage | ≥96% lines/statements on core; `glob.ts` and `attenuation.ts` at 100% branch |
| Conformance vectors | Byte-identical regeneration; CI diff guard |
| `aud_hash` for §A.5.1 inputs | `e4b259de5352880ebf7d058d3ce2787a7d7b68ec9fc71e94d8b2f8ae98298e3a` — matches §A.5.4 exactly |
| Clean-room guard | Three rounds of audit, no code-copy findings |
| Audit iterations | 3 rounds of security/conformance audit, all findings resolved (see [`audit-history/`](audit-history/)) |

## Package layout

| Package | Purpose |
|---|---|
| [`tbac-core`](packages/tbac-core-ts) | Wire format, crypto primitives, 17-step verification cascade, scope canonicalization, §8.1 glob-subset attenuation, 11 denial codes, pluggable stores |
| [`tbac-mcp-auth`](packages/tbac-mcp-auth) | MCP SDK integration: `TbacAuthProvider` (client), `TbacTokenVerifier` (server, Express + Hono adapters), capability negotiation with experimental fallback, demo-only stub TQS, two demos |

## Coverage by SEP section

| Section | Status | Code anchor |
|---|---|---|
| §2.1/§2.2 Capability negotiation | ✓ with `experimental` fallback | [`capability/negotiate.ts`](packages/tbac-mcp-auth/src/capability/negotiate.ts) |
| §3.0 Wire format (184-byte prefix) | ✓ byte-exact | [`wire/framing.ts`](packages/tbac-core-ts/src/wire/framing.ts) |
| §3.0.1 Key schedule | ✓ HKDF with 10 domain strings from §12.2 | [`crypto/hkdf.ts`](packages/tbac-core-ts/src/crypto/hkdf.ts) |
| §3.0.2 TokenBody | ✓ TLV encode/decode | [`wire/token.ts`](packages/tbac-core-ts/src/wire/token.ts) |
| §3.0.3 Mint algorithm | ✓ (test/demo helper; production TQS substitutes its own) | [`cascade/mint.ts`](packages/tbac-core-ts/src/cascade/mint.ts) |
| §3.2 Scope fields + r40 `resource` REQUIRED | ✓ with r39 transition-window fallback | [`scope/schema.ts`](packages/tbac-core-ts/src/scope/schema.ts) |
| §3.3 Constraints object + unknown-field rejection | ✓ at both canonicalize and decanonicalize layers | [`scope/canonical.ts`](packages/tbac-core-ts/src/scope/canonical.ts) |
| §3.4 `priv_sig` HMAC | ✓ under `io.modelcontextprotocol/tbac:priv-sig:v1` | cascade Step 12 |
| §3.6.1 Non-JSON PoP rejection | ✓ at framing Step 1 with `NON_JSON_POP_NOT_SUPPORTED` | cascade Step 1 |
| §4.3 17-step verification cascade | ✓ verify-then-decrypt ordering meta-tested | [`cascade/verify.ts`](packages/tbac-core-ts/src/cascade/verify.ts) |
| §6 Structured denial responses | ✓ 11 normative codes + stable `failed_check` identifiers | [`denial/codes.ts`](packages/tbac-core-ts/src/denial/codes.ts) |
| §7 Policy template ceiling enforcement | ✓ `min_trust_level`, `permitted_audiences`, numeric bounds, action set | cascade Step 13 |
| §8 Delegation chains | ✓ attenuation + `parent_token_hash` verification | [`scope/attenuation.ts`](packages/tbac-core-ts/src/scope/attenuation.ts) |
| §8.1 Glob-subset predicate + widening-attack defense | ✓ at TQS mint-gate AND RS Step 13 (defense-in-depth) | [`scope/glob.ts`](packages/tbac-core-ts/src/scope/glob.ts), [`scope/attenuation.ts`](packages/tbac-core-ts/src/scope/attenuation.ts) |
| §10.1 `_meta["io.modelcontextprotocol/tbac"]` transport | ✓ | [`meta/embed.ts`](packages/tbac-mcp-auth/src/meta/embed.ts) |
| §A TLV canonical encoding | ✓ including `allowed_parameters` per §A.3.1 | [`scope/canonical.ts`](packages/tbac-core-ts/src/scope/canonical.ts) |
| §A.5 Test inputs | ✓ conformance vectors under `test-vectors/v1/` | [`test-vectors/v1/`](test-vectors/v1/) |

## Deliberately deferred (hook interfaces only)

Per the SEP submission plan, these are interface stubs with default no-op behavior. Each can be wired without a normative change.

- **Consumer profile** (`msg_type = 0x08`) — cascade Steps 16–17 are no-op hooks.
- **T0 ephemeral profile** (`msg_type = 0x09`) — framing-gated at Step 1.
- **Response encryption** (`K_req`/`K_resp`) — hook interface; the demo uses plaintext.
- **Intent verification** (Step 13.7) — default `log_only`.
- **Non-JSON PoP** (`request_format = 0x01`) — **rejected** at mint-gate per §3.6.1.
- **HAAPI billing** — not referenced.
- **Rust implementation** — deferred, rationale in [`RUST_DEFERRED.md`](RUST_DEFERRED.md).

## Key architectural decisions and `[I]` deviations

Where SEP r40 is silent or internally inconsistent, the implementation made the smallest defensible choice and flagged it in code. Summary for SEP r41 review:

1. **`§A.3.1` sub-tag assignment for `allowed_parameters`.** §A.3 references §A.3.1 but the subsection is not present in r40. Implementation uses inner TLV tag 0x01 for parameter keys and 0x02 for patterns; entries sorted by ascending UTF-8 byte-order of keys per §A.3. Comment in [`scope/canonical.ts`](packages/tbac-core-ts/src/scope/canonical.ts). Flag for r41 to confirm or override.

2. **§8.1 version-string typo.** The §8.1 transition paragraph says `"2026-04-17-r40"`; the Preamble, §2.1, and §2.2 say `"2026-04-20-r40"`. Implementation treats Preamble form as normative. Recommend §8.1 be corrected in r41. Documented in [`version.ts`](packages/tbac-core-ts/src/version.ts) and [`R40_MIGRATION.md`](R40_MIGRATION.md).

3. **TLV unknown-tag policy.** §A.4 is silent on how to treat unknown tags. Implementation rejects unknown normative-range constraint tags (`0x07-0x7F`) at decode; tolerates vendor-range (`0x80+`) per §A.1. Symmetric at mint time: unknown non-`x-`-prefixed constraint keys throw. Flag for r41 clarification.

4. **Literal-prefix subset rule (§8.1).** The SEP's canonical example `"public/docs/api" ⊆ "public/docs"` is unambiguous, but the rule interacts non-trivially with wildcard parents (literal `"public/docs"` covers `"public/docs/api"` but wildcard `"public/*"` does NOT, because `*` is single-segment). Implementation honors this asymmetry. Worked examples in [`docs/resource-attenuation.md`](docs/resource-attenuation.md).

## Demos as regression signals

Two demo scripts double as ground-truth regression tests:

- **`pnpm demo`** — three-case smoke test: valid token (PASS), scope-mismatch denial (`TBAC_SCOPE_EVALUATION`), replay denial (`TOKEN_REPLAYED`). Exit 0 required.
- **`pnpm demo:widening`** — r40 §8.1 canonical widening attack: child `resource: "*"` under parent `resource: "public/*"`. MUST reject at BOTH the TQS mint-gate AND the RS cascade Step 13. Exit 0 only if both layers reject independently. If this demo fails, the r40 defense-in-depth invariant has been broken.

## Reviewer reproduction

```bash
cd mcp-tbac-reference
pnpm install
pnpm typecheck
pnpm -r test -- --run
pnpm vectors:regen && git diff --exit-code test-vectors/v1/expected.json
TBAC_SUPPRESS_DEMO_WARNING=1 pnpm demo
TBAC_SUPPRESS_DEMO_WARNING=1 pnpm demo:widening
bash scripts/no-haap-prefix.sh
```

Expected: 192 tests pass, zero diff on `expected.json`, both demos exit 0, guard reports "OK: no 'haap-' prefix leaks in source."

## Submission checklist

- [x] Apache 2.0 licensed, SPDX headers, `NOTICE` with patent non-assertion mirror
- [x] Package names neutral (`tbac-core`, `tbac-mcp-auth`)
- [x] No Hawcx/HAAP branding on the public surface
- [x] SEP line 1447 reference matches package name
- [x] Conformance vectors under `test-vectors/v1/` with CI drift guard
- [x] Three rounds of independent audit passed
- [x] 192 tests passing
- [x] Clean-room CI guard enforced
- [ ] GitHub repo renamed to `mcp-tbac-reference` (user action, one click)
- [ ] Publish packages to npm (user action, optional pre-acceptance)
- [ ] Open PR against `modelcontextprotocol/ext-auth` (user action)

## Commit trail

```
92e56bb spec(r40): rename reference impl package hawcx-mcp-auth → tbac-mcp-auth
12aa5fa chore: archive audit reports under audit-history/ for SEP-submission posture
49aeaff docs(DemoOnlyStubTqsClient): reconcile docstring with CSPRNG implementation
9cfdb29 fix(audit-final): §8.1 literal-prefix rule, CSPRNG demo stub
3e178e2 fix(audit-rerun): tool-binding + §3.3 unknown-constraint rejection
1232b60 docs: neutral-framing pass for SEP submission
52934f0 refactor: rename packages to neutral names
9e5fa12 fix(audit): schema conditional validation, demo-only TQS rename,
        allowed_parameters canon, Step 13 template+arg enforcement
f7abe9b chore: expose domain-string constants; final vector regeneration
599636c feat: conformance vectors, 131 core tests, full docs set
48fb3c3 feat: provider, verifier, capability, demos (both pass)
cdda581 feat: provider, verifier, capability, demos (both pass)
875de63 feat(tbac-core): wire, crypto, cascade, §8.1 attenuation, 124 tests
714edc3 chore: repo scaffold for hx_mcp_tbac (SEP r40)
```
