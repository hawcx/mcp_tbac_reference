# SEP-0000: Task-Based Access Control (TBAC) for MCP Authorization

## Preamble

| Field | Value |
|-------|-------|
| Title | Task-Based Access Control (TBAC) for MCP Authorization |
| Authors | Ravi Ramaraju ([@ravi-hawcx](https://github.com/ravi-hawcx)), Hawcx Inc. |
| Status | Proposal |
| Type | Extensions Track |
| Created | 2026-03-01 |
| Updated | 2026-04-20 (r40) |
| PR | TBD — to be assigned on submission to ext-auth repository |
| Extension Repository | [ext-auth](https://github.com/modelcontextprotocol/ext-auth) |
| Extension Identifier | `io.modelcontextprotocol/tbac` |

> **Governance note:** This SEP proposes TBAC as an official MCP extension. The `io.modelcontextprotocol/` prefix reflects this intent per SEP-2133 (the definitive MCP extension governance specification; historical context in SEP-1724 — see References). If the proposal is not accepted into the official `ext-auth` repository, implementations SHOULD use a vendor-specific prefix (e.g., `com.hawcx/tbac`).

> **Pre-review stability note:** Revisions r26–r40 are pre-review drafts and are NOT stable compatibility points. The extension identifier `io.modelcontextprotocol/tbac` is reserved for the eventual accepted revision. Breaking changes between pre-review revisions (e.g., `msg_type` renumbering from `0x04` to `0x08`, version field format change from `YYYY-MM-DD` to `YYYY-MM-DD-rNN`) are permitted during this pre-review phase without requiring a new extension identifier per SEP-2133's breaking-change rule. The identifier stability guarantee and SEP-2133 breaking-change governance BEGIN at the first officially accepted extension revision. Implementations of pre-review revisions MUST use exact `version` string matching (§2.1) to ensure they negotiate with compatible peers; lexicographic or numeric ordering of version strings is NOT defined and MUST NOT be used.

> **Revision note (r40).** Review-driven semantic fix from external security audit (2026-04-20). **P0.1** — the `resource` field in §3.2 (Normative Scope Fields) was previously declared OPTIONAL with "if omitted, authorization is tool-wide," while §8 (Delegation Chains) required all privilege fields to be monotonically non-increasing under attenuation. These two rules prescribed opposite outcomes for the same scope JSON when a delegated token omitted `resource`: the field-semantic rule read the absence as unrestricted tool-wide grant (permitting widening), while the attenuation rule required the child's scope to be equal to or a subset of the parent (forbidding widening). An implementation that honored the field-semantic rule at authorization time and the attenuation rule at the delegation check could pass both checks against a malicious child token that omitted the field, resulting in a delegation-chain privilege escalation against the SEP's stated "cannot grant permissions it does not hold" invariant. r40 resolves the inconsistency by making `resource` REQUIRED with explicit `"*"` for tool-wide authorization. A new §8.1 subsection spells out the `resource` attenuation rule under glob subset semantics explicitly (including the canonical widening-attack pattern child `"*"` under parent `"public/*"`, which MUST be rejected) and carries the deprecation-window transition rule for r39-formatted tokens. No wire format change other than the requirement that the `resource` TLV field now MUST be present in every scope JSON. Implementations consuming r40-formatted tokens (version string `"2026-04-20-r40"`) MUST reject tokens where `resource` is absent or null. During the transition window, implementations MAY accept r39-formatted tokens that omit `resource` by coercing the absent value to `"*"` with a deprecation warning; the transition window closes at the revision after r40.

> **Revision note (r39).** Review-driven fix to r38. **P1.1** — §3.0.3 Step 3 (token minting algorithm, AAD assembly) updated to match the r38 conformance-scope model. The previous `request_format` parenthetical stated only the three-condition trigger (`content_type` non-null AND `require_pop = true` AND `require_channel_encryption = true`) without the r38 requirement that a companion codec-registry specification must additionally be negotiated for `0x01` to be used. An implementer reading §3.0.3 in isolation could have concluded that the TQS should mint `request_format = 0x01` whenever the three conditions held, which would contradict §3.6.1's reject-at-mint-gate rule. Step 3 now defers the `request_format` value to a dedicated base-conformance normbox placed immediately after Step 3. The normbox restates the full four-gate rule (three trigger conditions AND companion-spec negotiation) and cross-references §3.6.1 for the TQS mint-gate rejection behavior. This edit removes the last internal inconsistency in the pre-r39 minting algorithm and completes the r38 conformance-scope alignment.

> **Revision note (r38).** Review-driven fixes to r37. Changes: (1) **P1.1** — stale build references (`c56be6f2330525ee`) in §3.6 alignment note and §12 opening paragraph updated to `885a9acf16a78e4a`, matching the current publicly reviewable HAAP canonical specification; §12 stale "not yet publicly available" language removed and replaced with language that accurately reflects what the current CS now directly supports (three-layer intent model, Profile E IPC inventory, HaapRequestEnvelope schema); (2) **P1.2** — non-JSON PoP (`request_format = 0x01`) declared **outside base v6.0.0 conformance** matching the attached HAAP CS conformance-scope language: new §3.6 conformance scope normbox, new §3.6.1 base-conformance rejection points (Assembler pre-mint, TQS mint-gate, RS Step 1), new denial code `NON_JSON_POP_NOT_SUPPORTED` / `failed_check: CONFORMANCE_SCOPE` added to §6 table; token header byte 3 description, §10.1 plaintext scope `0x01` branch, §10.3 PoP transcript `0x01` branch, §10.3 channel-encryption normbox, §12.1 transport table note, and §4.1 Profile E actor narrative all updated with the conformance-scope caveat. The `HaapRequestEnvelope` schema, semantic equivalence invariant, and codec-registration mechanics remain documented in §3.6 as a normative reference for a future codec-registry companion specification but are no longer part of base conformance for this revision.

> **Revision note (r37).** CS reconciliation with HAAP canonical spec v6.0.0 Build 885a9acf16a78e4a (supersedes the Build c56be6f2330525ee referenced in r33). Changes: (1) **§4.7 Intent Verification** — replaced Assembler "fast-reject pre-filter" with **three-layer model**: Layer 1 (TQS mint-gate, authoritative; TQS holds `expected_intent_hash` inside sealed `scope_json` and compares `claimed_intent_hash` from `PrepareInvocation`), Layer 2 (Assembler post-mint, defense-in-depth), Layer 3 (RS Step 13.7, unchanged); (2) **§4.1 Profile E actors** — `PrepareInvocation` field list now includes `claimed_intent_hash`; Assembler no longer validates intent itself, forwards for TQS authoritative comparison; (3) **§11.3 `InvocationRejected`** — enum expanded from 4 reasons (r33) to 11 reasons: `DestinationPolicyViolation`, `TransactionRequired`, `IntentCaptureRequired`, `TxnBudgetExhausted`, `PurposeRequired`, `ScopeCeilingExceeded`, `IntentHashMismatch`, `AgentNotEnrolled`, `SessionSuspended`, `SessionExpired`, `MintFailure`; added optional `retry_after_ms` and `granted_ceiling` fields; added actionable-reason mapping table (TQS→Assembler→Agent, preserving 1:1 mapping for actionable reasons, opaque `RSError` for dashboard-only internal reasons); (4) **§11.3 IPC type codes** — added `0x005C` (TokenStatus), `0x005D` (PollResult), `0x005E`/`0x0061` (ClarificationAnswer, two hops), `0x005F` (PendingResponse), `0x0060` (SessionStateChange, TQS→Auth reverse signal for automatic re-authentication); (5) **§11.4 security table**, rationale bullet, and threats table — updated to reflect TQS-authoritative intent enforcement.

> **Revision note (r36).** Review-driven polish to r35. **P2.1** — codec-registration paragraph in §3.6 tightened to the full three-condition set (`content_type` non-null AND `require_pop = true` AND `require_channel_encryption = true`), matching the normalized `request_format = 0x01` condition everywhere else.

> **Revision note (r35).** Review-driven fix to r34. **P1.1** — normalized the `request_format = 0x01` issuance condition to the full three-condition set (`content_type` non-null AND `require_pop = true` AND `require_channel_encryption = true`) in ALL four locations that previously stated only two conditions: token header byte 3 description, AAD assembly (minting step 3), §3.6 Non-JSON Tool Support, and Profile E TQS minting flow.

> **Revision note (r34).** Review-driven fixes to r33. Changes: (1) **P1.1** — `request_format = 0x01` fully integrated: §10.1 plaintext scope now branches on `request_format` (direct vs enveloped); §10.3 PoP transcript source branches on `request_format` (`0x00`: hash decrypted arguments directly; `0x01`: hash `pop_args` from envelope, not entire envelope object); explicit rule added: `request_format = 0x01` MUST only be used when `require_channel_encryption = true`; (2) **P3.1** — stale `§11.5` cross-reference in token header table corrected to `§3.6`; (3) **P2.1** — §12 alignment note now states that r33-specific CS features are based on an internal build not yet publicly available; provenance record is the revision note + diff until the CS is published.

> **Revision note (r33).** CS reconciliation with HAAP canonical spec v6.0.0 Build c56be6f2330525ee. Changes: (1) **Token header byte 3** — `reserved` → `request_format` (`0x00` direct / `0x01` enveloped `HaapRequestEnvelope`); Step 1 framing check and AAD assembly updated; (2) **§3.6 Non-JSON Tool Support** — new section: `HaapRequestEnvelope` schema, semantic equivalence invariant, canonical codec registration, RS payload disambiguation via `request_format`; (3) **`aud_hash` sourcing** — Profile E from `PrepareInvocation.selected_aud_hash`, Profile S from session `audience`; (4) **`InvocationRejected` (0x005B)** — new TQS→Assembler IPC; TQS validates `selected_aud_hash` against cached destination policy; rejection-reason mapping documented; (5) **`PoolHint` (0x005A)** — formal IPC type code; (6) **Bounded escalation window** — pool + intent mismatch propagation delay; (7) **`content_type`** in `ToolCallRequest` and `PrepareInvocation`; (8) **§12.1** — `request_format` and `HaapRequestEnvelope` added as shared (non-divergent) wire elements.

> **Revision note (r32).** Review-driven fixes to r31. Changes: (1) **P1.1** — added **Pre-review stability note**; (2) **P2.1** — client-side `version` description fixed; (3) **P3.1** — exact-match version comparison semantics added.

> **Revision note (r31).** Review-driven fixes to r30. Changes: (1) **P1.1** — extension `version` field format changed from `YYYY-MM-DD` to `YYYY-MM-DD-rNN` (e.g., `"2026-04-16-r31"`); (2) **P3.1** — explicit non-TBAC `_meta` confidentiality sentence.

> **Revision note (r30).** Review-driven fixes to r29. Changes: (1) **P1.1** — §10.1 "Plaintext scope" now references the full logical tool result object (§10.2) for responses, not only `result.content` array; resolves last §10.1-vs-§10.2 contradiction; (2) **P2.1** — §10.2 now defines non-TBAC `_meta` handling: other extensions' `_meta` fields MAY remain plaintext and are not covered by `enc.ct`; (3) **P3.1** — §12.2 opening accurately describes all divergence types (HKDF derivations, transcript prefixes, AAD constants), not just HKDF.

> **Revision note (r29).** Review-driven fixes to r28. Changes: (1) **P0.1** — resolved `require_channel_encryption` contradiction: §3.3 now consistently says encryption is NOT used when flag is false/absent (strict-flag model), matching §10.2; (2) **P1.1** — capability `version` examples bumped to `"2026-04-16"` to reflect normative content added in r28; (3) **P1.2** — §12.1 no longer claims "identical key schedule" — correctly states layout/cascade/security-model alignment with explicit acknowledgment that domain-string divergence (§12.2) means byte-level interop requires conformance mode; (4) **P1.3** — §10.2 now covers full `CallToolResult` surface: `structuredContent` MUST be omitted from plaintext wire and carried in `enc.ct`, `isError` preserved in plaintext for orchestrator control flow; encrypted response plaintext is a JSON object with `content` + `structuredContent` + `isError`; (5) **P1.4** — A.5 re-labeled "Test Inputs and Derivation Reference" (not "Normative"); conformance artifact commitment now enumerates all expected output fields; (6) **P2.1** — PoP key-registration paragraph clarifies HAAP v6.0.0 defines the lifecycle normatively, MCP-specific provisioning mechanism is the implementation-defined layer; (7) **P2.2** — tool-schema validation ordering note added to §10.2.

> **Revision note (r28).** Review-driven refinements to r27. Changes: (1) **§10.1–10.5** — full normative confidential-channel `enc` envelope specification (P0-1: request/response JSON schema, GCM AAD construction, plaintext field handling, nonce reuse prevention, Profile E mapping); (2) **§12** — new HAAP-vs-MCP alignment note with transport framing divergence table (§12.1) and complete domain-separation string migration table (§12.2) covering all eight renamed strings; (3) **§3.5** — PoP status note rewritten to reflect canonical spec v6.0.0 now having full normative PoP (MCP transport mapping is the SEP-specific layer); (4) **Reference Implementation** — explicit "pre-review draft" framing per SEP-2133 submission prerequisites; (5) **§A.5** — test vectors restored with fixed inputs, key schedule, channel derivation, and verification under `tbac-*` domain strings.

> **Revision note (r27).** This revision aligns the SEP with the HAAP Canonical Specification v6.0.0 (2026-04-15). Key changes from r26: (1) Assembler architecture and deployment profiles (Profile E / Profile S); (2) Assembler Pool for concurrent tool invocations (N single-flight Assemblers per agent); (3) updated verification cascade (17-step enterprise, 19-step consumer, with conditional Steps 13.5 and 13.7); (4) expanded scope JSON fields (`org_id`, `txn_id`, `purpose`, `trust_level`, `human_confirmed_at`, `approval_digest`, `user_raw_intent`, `intent_hash`); (5) `msg_type` registry aligned with canonical spec (`0x08` = consumer, `0x09` = T0 ephemeral); (6) intent verification (Step 13.7); (7) transaction lifecycle IPC; (8) end-to-end destination binding with `selected_aud_hash` and RS allowlist; (9) two-phase replay (reserve/commit, Steps 10 + 15); (10) new denial codes; (11) updated TCB with Assembler component.

## Abstract

This SEP proposes a Task-Based Access Control (TBAC) extension for MCP authorization that binds each tool invocation to a single-use, parameter-bound, cryptographically sealed authorization token. Unlike session-scoped OAuth 2.1 access tokens, TBAC tokens carry the exact permissions for one specific tool call — the resource, the action, the operational constraints, and the delegation chain — authored by the policy component and cryptographically sealed by the TQS at mint time, then enforced by the resource server at verification time. TBAC layers on top of MCP's existing OAuth 2.1 authorization without modifying core protocol semantics.

TBAC addresses the central gap identified by the MCP Fine-Grained Authorization Working Group: OAuth scopes (`mcp:read`, `mcp:write`) are too coarse for per-tool, per-invocation authorization, and every production integration invents proprietary mechanisms outside OAuth to handle fine-grained access control. This extension standardizes those mechanisms at the protocol level.

## Motivation

### The Authorization Gap in MCP

The MCP specification (2025-11-25 stable) provides OAuth 2.1 as the standard authorization mechanism for HTTP transports when authorization is implemented. Authorization itself is optional in MCP — servers MAY operate without it. When present, OAuth correctly answers "who is this client?" (when paired with OpenID Connect for authentication) and "what broad permissions does this client have?" but does not answer "what task is this request part of, and does this request fall within that task's scope?" This distinction matters because AI agents are fundamentally different from human users in three ways that break session-scoped authorization models:

1. **AI agents are susceptible to prompt injection.** A compromised or manipulated agent can abuse the full scope of its session-scoped access token. In June 2025, EchoLeak ([CVE-2025-32711](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711); Microsoft/CNA CVSS 9.3, NVD CVSS 7.5) demonstrated zero-click data exfiltration from Microsoft 365 Copilot — the agent searched OneDrive, SharePoint, and Teams for sensitive documents using its full OAuth scope, triggered by a crafted email. A token scoped to "summarize Q4 report" would have denied the injected instruction to search for salary data.

2. **AI agents operate without human oversight at invocation time.** When a human user calls an API, the human exercises judgment about each action. When an AI agent calls a tool, the authorization system is the only constraint on what actions the agent performs. Session-scoped tokens grant blanket authorization for the session's duration; TBAC tokens grant authorization for exactly one invocation.

3. **AI agent fleets create scale challenges that session-scoped tokens cannot address.** Salesforce Agentforce processes 11 million agent calls per day. When millions of agents share synchronized token TTLs, recovery from a brief auth service outage triggers "retry storms" that re-crash the service. Per-invocation tokens with task-specific TTLs create natural temporal distribution.

### Insufficiency of Existing MCP Authorization

The MCP community has taken the position that complex fine-grained authorization systems are implementation details outside the core MCP specification (see [MCP Auth WG meeting notes, August 13, 2025](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1344) and [MCP FGA Working Group Requirements](https://docs.google.com/document/d/1jwxDAeu3kQXBOuVRIlyVPOVBswj5SY1icBuwfq6rOrI/) for the open requirements discussion). The result is that every production MCP deployment invents its own fine-grained authorization:

- Kong AI Gateway 3.13 implements tool-level ACLs at the gateway layer
- Cerbos provides policy-based access control via declarative YAML policies
- OpenFGA offers relationship-based authorization models
- AWS AgentCore's Policy feature evaluates Cedar policies per tool call

This fragmentation means MCP clients cannot reason about authorization portably. A TBAC extension provides the standard that the working group identified was needed but deferred.

### MCP FGA Working Group Requirements Alignment

The MCP FGA Working Group consolidated 12 requirements from five production case studies (Google Drive, GitHub, Dropbox, Notion, TrueLayer). TBAC addresses all 12, with varying coverage levels:

| Requirement | Description | TBAC Coverage |
|------------|-------------|---------------|
| R1 | Structured denial responses | **Extension** — cascade rejection codes with remediation hints |
| R2 | Remediation taxonomy | **Partial** — programmatic remediation via structured error codes; human-interactive remediation is out of scope for autonomous agents |
| R3 | Resource selection semantics | **Native** — per-token resource field with wildcard support |
| R4 | Discovery model | **Out of scope** — resource discovery is an MCP server responsibility (via `resources/list`); TBAC authorizes access to discovered resources |
| R5 | Resource-level constraint advertisement | **Extension** — policy template exposure via `tbac/templates` |
| R6 | Temporal scoping spectrum | **Native** — single-use, configurable TTL (default 60s) |
| R7 | Opaque authorization models | **Native** — encrypted token body; authorization decision authored by policy component and cryptographically sealed by TQS |
| R8 | Access type distinction | **Native** — action + resource + constraints |
| R9 | Hierarchical resource grants | **Partial** — wildcard resource patterns (`billing-api/*`) provide hierarchical scoping; relationship-based hierarchies require a ReBAC policy engine upstream of TBAC |
| R10 | Create-and-grant pattern | **Extension** — `"create"` action in classifier; post-creation grant requires new token mint |
| R11 | Per-invocation parameter binding | **Native** — constraints object sealed in the AEAD-encrypted token body |
| R12 | Two-phase commit | **Extension (r27)** — transaction lifecycle IPC (`BeginTransaction`/`EndTransaction`) with per-transaction token budgeting and `txn_id` binding in scope JSON |

### Regulatory Convergence

Multiple standards bodies have independently converged on requirements matching TBAC's design:

- **NIST NCCoE** (February 5, 2026): Concept paper asking "How to apply zero-trust principles to agent authorization? How to establish least privilege when agent actions aren't fully predictable?"
- **OWASP Agentic Top 10** (December 9, 2025): Recommends issuing short-lived, task-scoped credentials valid only for specific tools and durations, and binding permissions to subject, resource, purpose, and duration — directly aligning with TBAC's per-invocation, parameter-bound token model.
- **EU AI Act** (applies from 2 August 2026): Requires human oversight (Article 14) and comprehensive record-keeping and logging of AI system actions (Article 12). TBAC tokens contribute to the evidence collection these requirements demand — each token is a timestamped, cryptographically bound record of what authorization was granted and consumed for a specific invocation. Because `priv_sig` uses a symmetric HMAC (not an asymmetric signature), tokens alone do not constitute third-party-verifiable audit logs; full audit compliance requires signed logs or policy decision records at the policy component or TQS. TBAC is designed to support, not replace, those logging requirements.
- **CSA Agentic Trust Framework** (February 2, 2026): Defines progressive trust levels paralleling TBAC's graduated authorization

## Specification

### 1. Extension Identifier

```
io.modelcontextprotocol/tbac
```

### 2. Capability Negotiation

#### 2.1 Server Declaration

An MCP server that supports TBAC authorization MUST advertise the extension in its capabilities during initialization:

```json
{
  "capabilities": {
    "extensions": {
      "io.modelcontextprotocol/tbac": {
        "version": "2026-04-20-r40",
        "tokenFormats": ["opaque"],
        "maxDelegationDepth": 3,
        "supportsStepUp": true,
        "supportsPolicyTemplateDiscovery": true,
        "supportsConsumerProfile": false,
        "supportsEphemeralProfile": false,
        "supportsIntentVerification": false,
        "intentVerificationMode": "log_only",
        "supportsTransactions": false,
        "deploymentProfile": "E",
        "maxAssemblersPerAgent": 8
      }
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | REQUIRED | Extension version identifier in `YYYY-MM-DD-rNN` format, where `YYYY-MM-DD` is the date of the latest normative revision and `rNN` is the intra-day revision number (e.g., `"2026-04-20-r40"` for this revision). The version changes whenever normative requirements change (new fields, new cascade steps, new denial codes, new token format profiles, normative wording fixes). The revision suffix ensures that multiple normative changes on the same date are distinguishable during capability negotiation. Implementations MUST use **exact string matching** for version recognition; lexicographic or numeric ordering of version strings is NOT defined and MUST NOT be used for compatibility decisions. If the peer advertises a `version` that the implementation does not recognize, the implementation MUST treat TBAC as unsupported for that connection (i.e., proceed without TBAC rather than rejecting the connection entirely). This prevents silent downgrade to a mismatched normative version while allowing the underlying MCP connection to function. Operators that require TBAC for all connections SHOULD configure their deployments to reject connections where TBAC negotiation fails. |
| `tokenFormats` | string[] | REQUIRED | Supported token formats. This initial specification defines `"opaque"` (native TLV signcryption). A JOSE (JWE/JWS) profile with FIPS-approved primitives is planned for a future revision. |
| `maxDelegationDepth` | integer | OPTIONAL | Maximum supported delegation chain depth. Default: 0 (no delegation) |
| `supportsStepUp` | boolean | OPTIONAL | Whether the server supports TBAC step-up authorization. Default: false |
| `supportsPolicyTemplateDiscovery` | boolean | OPTIONAL | Whether the server exposes policy templates via `tbac/templates`. Default: false |
| `supportsConsumerProfile` | boolean | OPTIONAL | Whether the server supports consumer-profile tokens (`msg_type = 0x08`) with `user_policy_sig` verification (Steps 16–17). Default: false |
| `supportsEphemeralProfile` | boolean | OPTIONAL | Whether the server supports ephemeral T0 tokens (`msg_type = 0x09`) for cross-organizational discovery. Default: false |
| `supportsIntentVerification` | boolean | OPTIONAL | Whether the server performs intent verification at Step 13.7. Default: false |
| `intentVerificationMode` | string | OPTIONAL | Intent verification mode when `supportsIntentVerification` is true: `"log_only"`, `"keyword_match"`, or `"classifier"`. Default: `"log_only"` |
| `supportsTransactions` | boolean | OPTIONAL | Whether the server supports transaction-scoped token budgeting (`txn_id` binding). Default: false |
| `deploymentProfile` | string | OPTIONAL | `"E"` (Profile E: Assembler required, zero agent crypto) or `"S"` (Profile S: direct-attach, v5.8.0 compatible). Default: `"E"` |
| `maxAssemblersPerAgent` | integer | OPTIONAL | Maximum Assembler pool size per agent (Profile E only). Controls N-way parallelism for concurrent tool invocations (§11.1.1). Default: 8. Ignored in Profile S. |

#### 2.2 Client Declaration

An MCP client that supports TBAC MUST declare the extension in its capabilities:

```json
{
  "capabilities": {
    "extensions": {
      "io.modelcontextprotocol/tbac": {
        "version": "2026-04-20-r40",
        "tokenFormats": ["opaque"],
        "hasTqs": true,
        "hasAssembler": true,
        "deploymentProfile": "E"
      }
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | REQUIRED | Extension version identifier (same semantics as server `version` above) |
| `tokenFormats` | string[] | REQUIRED | Token formats the client can produce |
| `hasTqs` | boolean | OPTIONAL | Whether the client has a local Token Queue Service. Default: false |
| `hasAssembler` | boolean | OPTIONAL | Whether the client has a local Assembler process (Profile E). Default: false |
| `deploymentProfile` | string | OPTIONAL | `"E"` (Profile E) or `"S"` (Profile S). Default: `"E"` |

> **Transitional note:** If the `capabilities.extensions` mechanism (SEP-1724 / SEP-2133) is not yet supported by the MCP implementation, clients and servers MAY use `capabilities.experimental["io.modelcontextprotocol/tbac"]` as a transitional mechanism with the same schema. This SEP is normatively defined against the `extensions` mechanism.

### 3. TBAC Privilege Classifier

The TBAC Privilege Classifier is the authorization assertion sealed into each token. The token wire format uses three distinct layers with different cryptographic bindings:

- **AEAD-authenticated header** (`AAD_token`, bytes 0–103) — version, algorithm suite, message type, `session_id`, IV, `iat`, `exp`, `policy_epoch`, `aud_hash`, `jti`, `jti_pad`. These 104 bytes are bound into the AES-256-GCM authentication tag as additional data. The RS reads these before any decryption for Tier 1 checks (§4.3 Steps 1–4).
- **Schnorr-bound fields** (bytes 104–183) — `R_tok` (32 B), `GCM_tag` (16 B), `σ_tok` (32 B). `GCM_tag` is the AES-GCM authentication tag that protects `CT_body` and `AAD_token`. `R_tok` and `GCM_tag` are both bound into the Schnorr challenge hash (`h_tok`), so the Schnorr signature additionally commits the entire ciphertext and AEAD tag to the verifier-secret context. `σ_tok` is the Schnorr scalar; it is not itself an input to the hash (circular dependency).
- **Encrypted body** (`CT_body`, bytes 184+) — TLV-encoded `TokenBody` under AES-256-GCM. Decrypted only after Schnorr verification succeeds. Opaque to the bearer and any intermediary.

`AAD_token = TokenHeader[0:104]` — bytes 0 through 103 inclusive. The exact layout is defined normatively in §3.0.

The `priv_sig` HMAC covers **only the scope JSON** (in the encrypted body), not the full token. An implementation MUST NOT include header fields (`jti`, `aud_hash`, `iat`, `exp`, `policy_epoch`) inside the scope JSON — doing so creates semantic duplication of authorization data and divergent canonicalization across implementations. Resource servers MUST reject scope JSON objects containing reserved header field names.

#### 3.0 Opaque Token Outer Envelope (Normative)

> **Notation.** Throughout this specification, `∥` denotes byte-string concatenation. All cryptographic formulas, HKDF info strings, and transcript constructions use this operator. Where `||` appears in quoted external specifications (e.g., X3DH `DH1||DH2||DH3||DH4`), it carries the same meaning.

The opaque token is a fixed-layout binary structure. Implementations MUST produce and consume tokens exactly as specified here. Two implementations that each claim `"opaque"` token support MUST interoperate using this layout.

**Wire layout (184-byte fixed prefix + variable body):**

> Sub-structure: `AAD_token` = bytes 0–103 (104 B, AEAD-authenticated); Schnorr fields = bytes 104–183 (80 B: `R_tok` 32 B + `GCM_tag` 16 B + `σ_tok` 32 B); `CT_body` = bytes 184+ (AES-256-GCM ciphertext).

| Offset | Length | Field | Encoding | Description |
|--------|--------|-------|----------|-------------|
| 0 | 1 B | `version` | `0x03` | Protocol version. MUST be `0x03`. Reject any other value. |
| 1 | 1 B | `alg_id` | `0x01` | Algorithm suite. See registry below. Reject any undefined value. |
| 2 | 1 B | `msg_type` | `0x03` | Message type. `0x03` = TBAC token (enterprise). `0x08` = consumer. `0x09` = T0 ephemeral. Reject any other value. |
| 3 | 1 B | `request_format` | `0x00` or `0x01` | `0x00` = direct payload, `0x01` = enveloped (`HaapRequestEnvelope`, §3.6). For token messages: `0x00` is the default for JSON tool calls and is the sole base-conformance value; `0x01` is outside base v6.0.0 conformance and requires a companion codec-registry specification negotiated between peers (§3.6.1). When conditions would trigger `0x01` but the peer does not support the companion specification, the request MUST be rejected per §3.6.1. Non-token messages MUST use `0x00`. Reject any other byte value. |
| 4 | 8 B | `session_id` | `uint64_be` | Cleartext. Used by the RS for key-table lookup at Step 2 before any decryption. |
| 12 | 12 B | `token_iv` | raw bytes | AES-256-GCM initialization vector: 4-byte TQS instance prefix (e.g., process ID hash) + 8-byte big-endian monotonic counter. MUST be globally unique per token for a given session. |
| 24 | 8 B | `iat` | `uint64_be` | Token issued-at timestamp (Unix epoch seconds). Cleartext. Validated by RS before decryption (Step 3). |
| 32 | 8 B | `exp` | `uint64_be` | Token expiration timestamp (Unix epoch seconds). Cleartext. `exp - iat` MUST NOT exceed `max_ttl` (default 60 s). Validated by RS before decryption (Step 3). |
| 40 | 8 B | `policy_epoch` | `uint64_be` | Privilege epoch counter. Increments when enterprise policy changes or `K_priv[epoch]` derivation epoch rotates. Validated by RS at Step 11. |
| 48 | 32 B | `aud_hash` | SHA-256 digest | `SHA-256(UTF-8(canonical_service_id))`. Step 3 pre-decrypt check. Profile E: sourced from `PrepareInvocation.selected_aud_hash` (§11.3). Profile S: from session `audience`. The RS verifies this against `SHA-256(UTF-8(own_identifier))`. |
| 80 | 22 B | `jti` | base64url, no pad | Token identifier. MUST be `base64url(16 random bytes from CSPRNG)` — exactly 22 bytes in URL-safe base64url without padding. Non-sequential; used for replay cache lookup. |
| 102 | 2 B | `jti_pad` | `0x00 0x00` | Reserved padding to maintain 8-byte alignment. MUST be `0x00 0x00`. |
| 104 | 32 B | `R_tok` | Ristretto255 point (compressed) | Schnorr ephemeral commitment (32 bytes, compressed Ristretto255 point). |
| 136 | 16 B | `GCM_tag` | raw bytes | AES-256-GCM authentication tag (always 16 bytes). Placed here (after `R_tok`, before `σ_tok`) so that both `R_tok` and `GCM_tag` are available to the Schnorr challenge hash before `σ_tok` is written. |
| 152 | 32 B | `σ_tok` | scalar LE | Schnorr signature scalar (little-endian). Written last; NOT included in AAD (circular dependency). |
| 184 | variable | `CT_body` | AES-256-GCM ciphertext | Encrypted `TokenBody` (see `TokenBody` definition below). |

**AAD construction.** `AAD_token = TokenHeader[0:104]` — bytes 0 through 103 inclusive (the fixed header from `version` through `jti_pad`, excluding `R_tok`, `GCM_tag`, and `σ_tok`). This byte sequence is bound into the AES-256-GCM authentication tag. The `R_tok` and `GCM_tag` are excluded from AAD and instead included in the Schnorr challenge hash input (see below).

#### 3.0.1 Key Schedule (Normative)

All per-token cryptographic keys are derived from `K_session` (the session-scoped X3DH key) and the token-unique `jti` value. Implementations MUST use the following derivations.

**Step 5a — AEAD key derivation:**
```
K_tok_enc = HKDF-SHA-256(
  IKM  = K_session,
  salt = 0x00 (32 zero bytes),
  info = "tbac-token-enc-v1" ∥ UTF-8(jti),
  L    = 32
)
```
`K_tok_enc` is the 256-bit AES-GCM key used to encrypt/decrypt `CT_body`. MUST be zeroized after the token is processed.

**Step 5b — Schnorr key derivation:**

Two primitives are used for scalar derivation; they are explicitly separated to avoid ambiguity:

- **`ScalarReduce64(b[64]) → scalar`**: Interprets a fixed 64-byte input as a little-endian integer and reduces it modulo ℓ (Ristretto255 group order ≈ 2²⁵²). Input MUST be exactly 64 bytes.
- **`HashToScalar(m) → scalar`**: `ScalarReduce64(SHA-512(m))` — hashes variable-length input `m` with SHA-512 (producing exactly 64 bytes) then reduces. Used for the Schnorr challenge hash in Step 6.

```
K_tok_sign_scalar = ScalarReduce64(
  HKDF-SHA-256(
    IKM  = K_session,
    salt = 0x00 (32 zero bytes),
    info = "tbac-token-sign-v1" ∥ UTF-8(jti),
    L    = 64
  )
)
```
`ScalarReduce64` is used here (not `HashToScalar`) because the HKDF output is already exactly 64 bytes; applying SHA-512 again would be redundant and change the security reduction. This scalar is `tqs_sk` in the Schnorr signature construction.

`TQS_PK = tqs_sk · G` (Ristretto255 base-point scalar multiplication). The RS independently re-derives `TQS_PK` from `K_session + jti` rather than storing `TQS_PK` separately. This ensures `TQS_PK` is per-token and session-bound.

**SEK_PK** — The Signed Ephemeral Key public key is the TQS enrollment public key (Ristretto255), established during Phase I TQS↔RS enrollment. It is stable across multiple tokens within an enrollment period and is rotated according to the Phase I enrollment/rotation schedule (not per-token). It is included in the Schnorr challenge hash to bind the token to the specific TQS instance that produced it. The RS retrieves `SEK_PK` from the session key-table (provisioned at Phase I enrollment). If `SEK_PK` is absent from the key-table, the RS MUST reject the token.

**Step 6 — Schnorr challenge hash:**
```
h_tok = HashToScalar(
  R_tok ∥ TQS_PK ∥ SEK_PK ∥ verifier_secret
  ∥ GCM_tag ∥ CT_body ∥ AAD_token
)
```
i.e., `h_tok = ScalarReduce64(SHA-512(R_tok ∥ TQS_PK ∥ SEK_PK ∥ verifier_secret ∥ GCM_tag ∥ CT_body ∥ AAD_token))`.

Where: `TQS_PK` and `SEK_PK` are compressed Ristretto255 points (32 bytes each); `verifier_secret` is from the RS key-table (32 bytes); `GCM_tag` is the 16-byte AES-GCM authentication tag at header bytes 136–151; `CT_body` is the variable-length ciphertext; `AAD_token` = `TokenHeader[0:104]` (104 bytes).

**Signature verification:** RS verifies `σ_tok · G == R_tok + h_tok · TQS_PK`. Reject if not equal.

#### 3.0.2 TokenBody Definition (Normative)

`CT_body` is the AES-256-GCM encryption of the TLV-serialized `TokenBody`. The `TokenBody` contains the following fields, serialized in ascending TLV type-code order using the encoding rules of Appendix A (string, uint64, bytes, boolean types):

| Type Code | Field | Type | Description |
|-----------|-------|------|-------------|
| `0x01` | `scope_json` | bytes | TLV-canonical encoding of the privilege classifier scope (per Appendix A.2). This is the exact byte string over which `priv_sig` is computed. |
| `0x02` | `priv_sig` | bytes | 32-byte HMAC-SHA-256 over `scope_json` TLV bytes using `K_priv[epoch]` (§3.4). |
| `0x03` | `response_key` | bytes | 32-byte random symmetric key seed for bidirectional channel encryption (§9). Generated by TQS at mint time. |
| `0x04` | `mutual_auth` | bytes | 32-byte session binding value. Defense-in-depth cross-check at verification Step 8. |
| `0x05` | `verifier_secret` | bytes | 32-byte designated-verifier binding value. Defense-in-depth cross-check at verification Step 9. |

All five fields are REQUIRED in all profiles. The RS MUST reject a `TokenBody` that omits any of them.

**Consumer Profile Fields (v5.4.0 / updated r27).** The following fields are REQUIRED in consumer profile (`msg_type = 0x08`) and MUST be zeroed/omitted in enterprise profile (`msg_type = 0x03`). The RS skips Steps 16–17 verification when `msg_type = 0x03`.

| Type Code | Field | Type | Description |
|-----------|-------|------|-------------|
| `0x06` | `user_policy_sig` | bytes | 64-byte Ed25519 user policy signature. Zeroed (64 zero bytes) in enterprise profile. |
| `0x07` | `user_sign_pk` | bytes | 32-byte Ed25519 public key. Zeroed in enterprise. For self-contained receipt verification. |
| `0x08` | `signed_at` | uint64 | User's signature timestamp (Unix seconds). 0 in enterprise. |
| `0x09` | `tsa_token` | bytes | RFC 3161 TimeStampResp. OPTIONAL; omit in enterprise or when TSA not configured. |

> **Note (r27 alignment):** Consumer profile uses `msg_type = 0x08` (aligned with HAAP canonical spec v6.0.0). Prior SEP revisions used `0x04`; implementations of r26 or earlier MUST migrate to `0x08` for consumer tokens.

**Step 1 framing check.** The RS MUST validate `version == 0x03`, `alg_id == 0x01`, `msg_type ∈ {0x03, 0x08, 0x09}`, and `request_format ∈ {0x00, 0x01}` before performing any other operation. Tokens failing this check MUST be rejected immediately with no further processing.

**Step 2 key-table lookup.** `session_id` at bytes 4–11 is read in cleartext to look up the session record in the RS session key-table. If no entry exists for the presented `session_id`, the RS MUST reject the token immediately. The RS reads `profile` from the key table and selects the appropriate cascade: enterprise (17 steps), consumer (19 steps), or ephemeral T0 (13 steps). The backing store technology (e.g., Redis, PostgreSQL, in-memory map) is implementation-defined; the RS MUST retrieve at minimum: `K_session`, `verifier_secret`, `mutual_auth`, `SEK_PK`, `client_metadata`, `profile`, `org_id`, and the session validity window.

#### 3.0.3 Token Minting Algorithm (Normative)

The TQS MUST mint tokens using the following procedure. The ordering of steps is security-critical: AEAD encryption MUST occur before Schnorr signing, because `GCM_tag` and `CT_body` are inputs to the Schnorr challenge hash.

**Inputs:** `K_session`, `session_id`, `verifier_secret`, `mutual_auth`, `SEK_PK`, `policy_epoch`, `aud` (audience string), scope JSON (from policy component), `response_key` (CSPRNG-generated 256-bit seed).

**Procedure:**

1. **Generate `jti`**: `jti = base64url(CSPRNG(16))` — exactly 22 bytes, no padding. MUST be generated from a CSPRNG with at least 128 bits of entropy.

2. **Derive per-token keys** (§3.0.1):
   - `K_tok_enc` via HKDF (Step 5a).
   - `tqs_sk` = `K_tok_sign_scalar` via HKDF + `ScalarReduce64` (Step 5b).
   - `TQS_PK = tqs_sk · G`.

3. **Assemble `AAD_token`** (bytes 0–103): Write `version` (0x03), `alg_id` (0x01), `msg_type` (0x03/0x08/0x09 per profile), `request_format` (see base-conformance rule below), `session_id`, `token_iv`, `iat`, `exp`, `policy_epoch`, `aud_hash` (Profile E: `selected_aud_hash` from `PrepareInvocation`; Profile S: `SHA-256(UTF-8(audience))`), `jti`, `jti_pad` (0x0000).

> **`request_format` base-conformance rule (r39).** Base-conformant TQS implementations MUST mint `request_format = 0x00` for every token. `request_format = 0x01` MAY be written only when ALL of the following hold: (a) `content_type` is non-null, (b) `require_pop = true`, (c) `require_channel_encryption = true`, AND (d) a companion codec-registry specification (§3.6) has been negotiated between peers. When (a)–(c) hold but (d) does not, the TQS MUST NOT mint the token and MUST instead reject at mint-gate with `InvocationRejected{reason: MintFailure, detail: "non-json-pop-not-in-scope"}` per §3.6.1. This rule mirrors §3.6.1 and ensures the minting algorithm is internally consistent with the conformance-scope decision introduced in r38.

4. **Compute `priv_sig`**: Derive `K_priv[epoch]` per §3.4; compute `priv_sig = HMAC-SHA-256(K_priv[epoch], TLV-canonical(scope_json))`.

5. **Assemble and encrypt `TokenBody`**: TLV-serialize the `TokenBody` fields (`scope_json`, `priv_sig`, `response_key`, `mutual_auth`, `verifier_secret`) in ascending type-code order per §3.0.2. Encrypt with AES-256-GCM:
   ```
   (CT_body, GCM_tag) = AES-256-GCM.Encrypt(
     key = K_tok_enc,
     iv  = token_iv,
     aad = AAD_token,
     plaintext = TLV-serialized TokenBody
   )
   ```
   Write `GCM_tag` to bytes 136–151 and `CT_body` starting at byte 184.

6. **Generate Schnorr nonce**: The TQS MUST generate the nonce scalar `r_tok` using one of the following methods:
   - **(a) Randomized nonce (RECOMMENDED for most implementations):** `r_tok = ScalarReduce64(CSPRNG(64))`. This requires a reliable CSPRNG; nonce reuse across two tokens with the same `tqs_sk` leaks the signing key.
   - **(b) Deterministic nonce (RECOMMENDED for constrained environments or side-channel resistance):** `r_tok = ScalarReduce64(HMAC-SHA-512(tqs_sk_bytes, "tbac-schnorr-nonce-v1" ∥ AAD_token ∥ GCM_tag ∥ CT_body))`, where `tqs_sk_bytes` is the 64-byte pre-reduction HKDF output from Step 5b. This follows the pattern of RFC 6979 synthetic nonces: the nonce is deterministic given the signing key and message, eliminating nonce-reuse risk from RNG failure.

   Compute `R_tok = r_tok · G` (compressed Ristretto255 point). Write `R_tok` to bytes 104–135.

7. **Compute Schnorr signature**:
   ```
   h_tok = HashToScalar(R_tok ∥ TQS_PK ∥ SEK_PK ∥ verifier_secret
                        ∥ GCM_tag ∥ CT_body ∥ AAD_token)
   σ_tok = r_tok + h_tok · tqs_sk  mod ℓ
   ```
   Write `σ_tok` (little-endian scalar) to bytes 152–183.

8. **Zeroize**: `K_tok_enc`, `tqs_sk`, `r_tok`, and `K_priv[epoch]` MUST be zeroized immediately after minting.

**Output:** The complete token is the concatenation of `AAD_token ∥ R_tok ∥ GCM_tag ∥ σ_tok ∥ CT_body` (184-byte fixed prefix + variable `CT_body`).

**Algorithm identifier registry:**

| `alg_id` | Suite name | Hash for HKDF/HMAC | Hash for Schnorr reduction | Curve | AEAD |
|----------|------------|--------------------|---------------------------|-------|------|
| `0x01` | `Ristretto255-HKDF-SHA256-Schnorr-SHA512-AES256GCM` | SHA-256 | SHA-512 (via HashToScalar / ScalarReduce64) | Ristretto255 | AES-256-GCM |
| `0x02`–`0xFF` | Reserved. Reject. | — | — | — | — |

> **Note on hash functions:** SHA-256 is used for HKDF and HMAC (`priv_sig`, `aud_hash`). SHA-512 is used **only** inside `HashToScalar` for the Schnorr challenge hash (Step 6), which requires 512 bits of hash output to safely reduce modulo the Ristretto255 group order ℓ ≈ 2²⁵². `ScalarReduce64` (used in Step 5b) does **not** apply SHA-512 — it reduces a 64-byte HKDF output directly. The algorithm name reflects all hash roles.

**Message type registry (updated r27):**

| `msg_type` | Description |
|------------|-------------|
| `0x01` | Signcryption data message |
| `0x02` | SEK prekey bundle (Phase I enrollment request) |
| `0x03` | TBAC token — enterprise profile (this document) |
| `0x05` | Signed Ephemeral Key (SEK) rotation bundle |
| `0x06` | Encrypted response |
| `0x07` | Presentation binding |
| `0x08` | TBAC token — consumer profile |
| `0x09` | TBAC token — T0 ephemeral profile |
| Other | Reject. |

> **Note:** Message types `0x01`, `0x02`, `0x05`–`0x07` are defined by the parent AIAA protocol specification and are not used by this SEP. `0x03` (enterprise), `0x08` (consumer), and `0x09` (T0 ephemeral) are the token message types relevant to implementations of this extension. The registry is included here for completeness so that implementations can reject unexpected message types at the framing check (Step 1).

#### 3.1 Scope JSON

The scope JSON is the TBAC authorization payload authored by the policy component and integrity-protected at mint time via `priv_sig` computed by the TQS (see §3.4). The `iss` field identifies the policy author — the entity that made the authorization decision — not necessarily the cryptographic signer (which is always the TQS). The scope JSON is sealed inside the encrypted `TokenBody` and is never visible to the agent runtime.

```json
{
  "iss": "policy-engine-org-a",
  "sub": "IK:a1b2c3d4e5f6...",
  "aud": "https://rs.example.com/mcp",
  "agent_instance_id": "code-deploy-agent",
  "tool": "query_database",
  "action": "read",
  "resource": "billing-api/invoices/2025-Q3",
  "constraints": {
    "max_rows": 100,
    "time_window_sec": 30,
    "max_calls": 1,
    "require_channel_encryption": true
  },
  "delegation_depth": 0,
  "require_pop": false,
  "org_id": "org-a-prod",
  "trust_level": 2,
  "human_confirmed_at": 0,
  "purpose": "Generate Q3 billing summary report"
}
```

The fixed header (§3.0) carries the framing fields `iat`, `exp`, `policy_epoch`, `aud_hash`, and `jti` in cleartext. The `response_key` and session-binding values are carried in the encrypted `TokenBody` (§3.0.2) — they are only accessible to the RS after token decryption.

#### 3.2 Normative Scope Fields

The following fields comprise the **scope JSON** — the authorization payload covered by `priv_sig`. These fields MUST NOT duplicate fixed-header fields (`jti`, `aud_hash`, `iat`, `exp`, `policy_epoch`); those are carried in the fixed header and bound into the AEAD AAD. Resource servers MUST reject scope JSON objects containing those reserved header field names.

| Field | Type | Req | Description |
|-------|------|-----|-------------|
| `iss` | string | REQUIRED | Policy author identifier — the entity that made the authorization decision (not the cryptographic signer; `priv_sig` is always computed by the TQS) |
| `sub` | string | REQUIRED | Client identity (IK fingerprint) |
| `agent_instance_id` | string | REQUIRED | Agent class identifier. Each agent class under a client has its own classifier and RS-side policy template |
| `tool` | string | REQUIRED | MCP tool name this token authorizes (maps to `tools/call` `name` field) |
| `action` | string/list | REQUIRED | Permitted operations: `"read"`, `"write"`, `"execute"`, `"delete"`, or a list thereof. The action taxonomy is defined by the policy engine, not by MCP. |
| `aud` | string | REQUIRED | Full audience identifier (resource server URI). The fixed header carries `aud_hash = SHA-256(UTF-8(aud))` for pre-decryption audience binding (Step 3); this field carries the full string for post-decryption cross-check. The RS MUST verify `aud` matches its own identifier after decryption. **Normalization:** `aud` is compared byte-exact on its UTF-8 encoding with no normalization applied (no case folding, no URI percent-decoding, no trailing-slash stripping). The TQS and RS MUST be provisioned with identical `aud` strings; any discrepancy (e.g., trailing slash) will cause authentication failure. Implementers SHOULD use scheme+authority+path in fully-qualified form (e.g., `https://rs.example.com/mcp`) and avoid aliases. |
| `resource` | string | REQUIRED | Resource URI or pattern. Use `"*"` for tool-wide (unrestricted) authorization. Supports glob-style wildcards: `*` matches any single path segment, `**` matches zero or more segments. Literal `*` is escaped as `\*`. Delegation attenuation (§8) requires the child's `resource` to be equal to or a strict subset of the parent's under glob subset semantics; a child `"*"` MUST be rejected by attenuation when the parent is anything other than `"*"`. See §8.1 for the transition note on r39-format tokens that omitted this field. |
| `constraints` | object | OPTIONAL | Operational guardrails (see §3.3) |
| `delegation_depth` | integer | REQUIRED | Maximum remaining delegation hops. MUST monotonically decrease across chains. 0 = no further delegation |
| `parent_token_hash` | string | OPTIONAL | base64url-encoded SHA-256 digest of the parent token's canonical scope JSON TLV bytes. Present only in delegated tokens. |
| `require_pop` | boolean | OPTIONAL (default: false) | If true, RS requires per-request proof-of-possession (see §3.5). Absent is treated as false and MUST be encoded as `0x00` in TLV (see Appendix A.4). |
| `org_id` | string | REQUIRED | Organization trust boundary identifier. The RS MUST perform a constant-time comparison of `scope_json.org_id` against `key_table[session_id].org_id` at Step 13. Mismatch causes immediate rejection with opaque `AuthorizationFailed` error. This check runs unconditionally on every token. |
| `trust_level` | uint8 | REQUIRED | Trust tier (0–3). T0 = ephemeral, T1 = enrolled, T2 = policy-bound, T3 = human-confirmed. See §4.5 for trust level definitions. |
| `human_confirmed_at` | uint64 | CONDITIONAL | Unix epoch seconds of CIBA approval timestamp. REQUIRED and non-zero when `trust_level = 3`. MUST be 0 when `trust_level ∈ {0, 1, 2}`. |
| `approval_digest` | string | CONDITIONAL | 64 lowercase hex characters — SHA-256 over the canonical approval tuple (`agent_instance_id`, `tool`, `action`, `resource`, `constraints`, `purpose`, `org_id`, `txn_id`, `intent_hash`). REQUIRED when `trust_level = 3`. Absent or zeroed when `trust_level ∈ {0, 1, 2}`. Binds the CIBA approval to the exact scope, preventing "approve benign → execute sensitive" substitution. |
| `purpose` | string | OPTIONAL | Human-readable purpose string describing the intent of the tool invocation. REQUIRED when `purpose_required = true` in the MintPolicy. |
| `txn_id` | string | OPTIONAL | Transaction identifier (hex-encoded 16-byte CSPRNG). Present when the session is operating in transaction mode (§4.6). All tokens within a transaction carry the same `txn_id`. |
| `user_raw_intent` | string | OPTIONAL | UTF-8 natural-language user intent text (max 4096 bytes). Present when intent verification (§4.7) is active. Sealed inside the AEAD-encrypted token body. |
| `intent_hash` | string | OPTIONAL | Lowercase hex SHA-256 of `user_raw_intent`. Present when `user_raw_intent` is present. Used for integrity check at RS Step 13.7. |

#### 3.3 Constraints Object

The `constraints` object provides operational guardrails that are cryptographically bound to the token:

| Field | Type | Description |
|-------|------|-------------|
| `max_rows` | integer | Maximum records the tool may return |
| `max_calls` | integer | Maximum number of invocations. For individual tokens, this MUST be 1 (single-use semantics). In policy templates (§7), `max_calls` in `constraints_ceiling` defines a *mint-rate ceiling* — the maximum number of separate single-use tokens the TQS may mint within a `time_window_sec` for this tool, not multi-use tokens. (The name reflects invocation count at the template level; each minted token permits exactly one invocation.) |
| `time_window_sec` | integer | Time window in which the action must complete |
| `require_channel_encryption` | boolean | Whether the bidirectional per-token confidential channel (§9) MUST be active for this invocation. When true, the agent MUST encrypt the request payload using K_req and the RS MUST encrypt its response using K_resp. When false or absent, application-layer encryption is NOT used and the `enc` field MUST NOT be present in `_meta` (§10.2). |
| `data_classification` | string | Maximum data sensitivity level the tool may access (e.g., `"public"`, `"internal"`, `"confidential"`) |
| `allowed_parameters` | object | Parameter-level constraints that bind to the tool's `arguments`. Keys are argument names; values are match patterns. Unless overridden by a vendor extension, pattern matching uses glob semantics with `/` (forward slash, U+002F) as the sole path separator: `*` matches any sequence of bytes except `0x2F` (`/`), `**` matches any sequence of bytes including `0x2F`, and `?` matches any single byte except `0x2F`. Matching operates on raw UTF-8 byte sequences, not Unicode code points or grapheme clusters — this means `?` matches one byte, not one user-visible character, which may produce unexpected results for multi-byte UTF-8 sequences (e.g., emoji, CJK). Exact match is expressed as a literal string with no wildcards. Literal `*`, `?`, and `\` are escaped as `\*`, `\?`, and `\\` respectively. Example: `{"file_path": "/reports/*"}` permits any single-segment path under `/reports/`. The RS MUST reject any invocation where a constrained argument value does not match its pattern. Unrecognized argument names in `allowed_parameters` (i.e., argument names not present in the tool's `arguments`) MUST cause rejection unless prefixed with `x-`. |

Implementations MAY define additional constraint fields. Unknown constraint fields MUST cause the RS to reject the token unless the field name starts with `x-` (vendor extension prefix, treated as advisory). This prevents silent privilege escalation when constraint semantics are not understood by the RS. RS implementations MUST enforce all recognized constraint fields.

#### 3.4 Privilege Signature

The privilege classifier MUST be integrity-protected at mint time using HMAC-SHA-256 with a session-bound, epoch-rotated key:

```
priv_sig = HMAC-SHA-256(K_priv[epoch], canonical(classifier))
```

**Key derivation.** `K_priv[epoch]` is derived by the TQS from `K_session` — the shared session key delivered to the TQS by the user Authenticator via IPC after the Authenticator completes X3DH key agreement with the AS. The derivation MUST be bound to both the session and the epoch to prevent cross-session and cross-epoch reuse:

```
K_priv[epoch] = HKDF-SHA-256(
  ikm = K_session,
  salt = uint64_be(policy_epoch),
  info = "io.modelcontextprotocol/tbac:priv-sig:v1" ∥ uint64_be(session_id),
  L = 32
)
```

> **Migration note for Hawcx AIAA SDK users (non-normative; based on AIAA canonical spec v6.0.0):** The Hawcx AIAA canonical specification uses `"hawcx-priv-sig-v1"` as the info string. This SEP defines `"io.modelcontextprotocol/tbac:priv-sig:v1"` as the single normative string for MCP ecosystem implementations. A future release of the AIAA SDK will add a conformance mode that uses the SEP string. Until that release, deployments integrating the AIAA SDK directly MUST configure the SDK to use the canonical spec's string and MUST NOT mix tokens from both derivations in the same RS deployment. This SEP takes the standard-track position: all conformant SEP implementations MUST use `"io.modelcontextprotocol/tbac:priv-sig:v1"`.

Where `K_session` is the session key derived from X3DH key agreement, `policy_epoch` is the current epoch counter (uint64), and `session_id` is the session identifier allocated during mutual authentication. The salt is exactly 8 bytes (`uint64_be`); per RFC 5869 §2.2, HKDF salt MAY be any length — here it deliberately differs from the 32-byte zero salt used in per-token key derivations (§3.0.1). The inclusion of `session_id` in the info string is a REQUIRED security property — it prevents a compromised `K_priv` from one session being reused in a different session sharing the same epoch.

**Signer responsibilities.** The policy component authors the classifier (the authorization decision — which tool, which action, which constraints). The TQS receives the classifier from the policy component and computes `priv_sig` using `K_priv[epoch]` derived from its own session key material. The policy component does not hold `K_session` and does not compute `priv_sig` directly.

This architecture separates authorization decisions (policy component) from cryptographic token construction (TQS). The RS verifies `priv_sig` by independently deriving the same `K_priv[epoch]` from its copy of `K_session` — confirming that the token was minted by the TQS that holds the authenticated session and that the classifier has not been tampered with since minting.

> **Note on auditability:** Because `priv_sig` uses a symmetric HMAC, it proves integrity to the RS but is not independently verifiable by third-party auditors (sharing `K_priv` would enable forgery). For audit and compliance purposes, implementations SHOULD maintain signed audit logs at the policy component and/or TQS. A future revision may define an asymmetric signature option (e.g., Ed25519) for the privilege classifier to enable third-party verifiability without shared-secret distribution.

**Canonicalization.** The classifier MUST be canonicalized before signing. For the native TLV profile, implementations MUST use deterministic TLV encoding with fields serialized in ascending numeric type-code order (see **Appendix A: TLV Type-Code Registry** for the normative type-code table and encoding rules). For a future JOSE profile, implementations MUST apply JSON Canonicalization Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)).

#### 3.5 Proof-of-Possession (PoP)

> **Alignment note.** Proof-of-possession is normatively defined in the HAAP Canonical Specification v6.0.0 (§11), including key registration, signature computation, verification, and TQS-held private key lifecycle. This section defines the **MCP-specific transport mapping** — specifically, how PoP proofs are carried in JSON-RPC `_meta` fields rather than HTTP headers (`HAAP-PoP`), and how the PoP transcript interacts with the `enc` envelope (§10.1) when channel encryption is active.

> **Profile E note (r27).** In the Assembler deployment profile (Profile E), PoP proofs are computed by the TQS and delivered to the Assembler via the `TokenDelivery.pop_proof` field. The Assembler attaches the proof to the outgoing request (in `_meta.pop` for MCP, or `HAAP-PoP` header for generic HTTP). The Agent/LLM never computes or holds PoP key material.

When `require_pop: true` is set in the privilege classifier, the agent MUST demonstrate sender-binding on each tool invocation. This prevents token replay by a different sender — an attacker who exfiltrates a token cannot use it without also holding the session-bound private key.

**Key registration.** A session-bound Ed25519 keypair (`pop_pub`, `pop_priv`) is generated by the TQS sidecar during or immediately after X3DH session setup. `pop_pub` is provisioned to the RS key-table via the Authenticator relay (the same trusted IPC path used for session material); `pop_priv` is held exclusively by the TQS sidecar, isolated from the LLM runtime. The HAAP canonical spec v6.0.0 (§11) defines the key generation, lifecycle, and signature construction normatively. The MCP-specific provisioning mechanism — how `pop_pub` reaches the RS key-table in MCP deployments where the AS-to-RS path may differ from the HAAP reference topology — is left to implementation; future versions of this SEP will define a normative MCP wire format for this exchange if cross-implementation interop requires it.

**PoP signature computation.** For each `tools/call` invocation requiring PoP, the TQS sidecar computes a transcript signature over the canonical concatenation of:

```
pop_sig = Ed25519.Sign(
  pop_priv,
  SHA-256("tbac-pop-v1" ∥ uint64_be(session_id) ∥ uint16_be(len(UTF8(jti))) ∥ UTF8(jti) ∥ SHA-256(JCS(tool_arguments)))
)
```

Where:
- `"tbac-pop-v1"` is a UTF-8 domain-separation prefix (11 bytes).
- `uint64_be(session_id)` is the 8-byte big-endian encoding of the session identifier (same encoding as in HKDF info strings).
- `UTF8(jti)` is the UTF-8 encoding of the `jti` string (variable length). Implementations MUST length-prefix this field with a 2-byte big-endian uint16 length to prevent concatenation ambiguity: `uint16_be(len(UTF8(jti))) ∥ UTF8(jti)`.
- `JCS(tool_arguments)` is the JSON Canonicalization Scheme (RFC 8785) serialization of the `params.arguments` object. This provides a deterministic, implementation-independent canonical byte string regardless of JSON encoder key ordering or whitespace. If `params.arguments` is absent or null, use the empty string `{}` serialized per RFC 8785 (the 2-byte sequence `0x7B 0x7D`). **When `require_channel_encryption` is true:** `tool_arguments` refers to the **plaintext arguments before encryption** (client side) or the **decrypted arguments recovered from `_meta...enc.ct`** (RS side) — not the ciphertext envelope and not the empty/omitted `params.arguments` placeholder. Both the client and the RS MUST compute PoP over the same plaintext arguments that are encrypted/decrypted through the confidential channel. The RS MUST therefore decrypt `enc.ct` before computing the PoP verification transcript.

This transcript encoding is deterministic across all conformant implementations: RFC 8785 handles JSON number normalization, key ordering, and Unicode escaping.

> **Ed25519 mode note:** The message passed to `Ed25519.Sign` is the 32-byte SHA-256 digest shown above. This is standard Ed25519 (RFC 8032 §5.1) applied to a pre-computed digest — it is **not** Ed25519ph (RFC 8032 §5.1, prehash variant). Implementations MUST NOT apply an additional prehash; the SHA-256 in the transcript construction is the only hash applied to the variable-length input before signing.

**PoP transport.** The PoP signature MUST be included in the `_meta` field alongside the TBAC token:

```json
{
  "_meta": {
    "io.modelcontextprotocol/tbac": {
      "token": "<base64url-encoded-opaque-token>",
      "format": "opaque",
      "pop": {
        "alg": "Ed25519",
        "sig": "<base64url-encoded-pop-sig>"
      }
    }
  }
}
```

**RS verification.** The RS verifies `pop_sig` at cascade Step 14 (see §4.3) using `pop_pub` retrieved from the session key-table, over the same canonical transcript. If verification fails, the RS MUST reject with `failed_check: "POP_VERIFICATION"` / denial code `POP_FAILED`.

If `require_pop: true` is set but no `pop` field is present in `_meta`, the RS MUST reject with `failed_check: "POP_MISSING"` / denial code `POP_REQUIRED`.

#### 3.6 Non-JSON Tool Support (`request_format`, r33)

> **Alignment note.** This section aligns with HAAP canonical spec v6.0.0 (Build 885a9acf16a78e4a) §39.7. MCP tool calls are JSON-native (`params.arguments` is always JSON), so the default `request_format = 0x00` (direct) applies to all standard MCP tool invocations. The enveloped format (`request_format = 0x01`) is relevant for MCP servers that bridge to non-JSON backends (e.g., gRPC/protobuf services) where the PoP transcript must cover the semantic operation while the wire payload uses a different encoding.

> **Conformance scope (r38).** Non-JSON PoP — the combination of `content_type` non-null, `require_pop = true`, and `require_channel_encryption = true` that triggers `request_format = 0x01` — is **outside base v6.0.0 conformance** for this SEP, matching the HAAP Canonical Specification v6.0.0 (Build 885a9acf16a78e4a) conformance scope. Base-conformant implementations MUST reject such requests. Support for `request_format = 0x01` requires a separately versioned companion codec-registry specification that defines codec identifiers, codec-registry version, peer-declared version agreement, and failure behavior on mismatch. Such a companion specification is future work and is not defined by this SEP. The `HaapRequestEnvelope` schema, semantic equivalence invariant, and RS payload disambiguation rules below are documented here as a normative reference for that future companion specification; they do not constitute base-conformance behavior for this revision. Specific base-conformance rejection points are given in §3.6.1.

The `request_format` field (token header byte 3) distinguishes two request payload formats:

- **`0x00` (direct):** The encrypted request body is the tool arguments directly (JSON for MCP). This is the default for all JSON-native tool calls, regardless of whether `require_pop` is true or false.
- **`0x01` (enveloped):** The encrypted request body is a `HaapRequestEnvelope` JSON object. Used ONLY when `content_type` is non-null (non-JSON tool) AND `require_pop = true` AND `require_channel_encryption = true` (all three conditions required; see §10.3) **AND** a companion codec-registry specification has been negotiated between peers. Under base conformance, implementations MUST reject such requests per §3.6.1.

**`HaapRequestEnvelope` schema:**

```json
{
  "pop_args": "<UTF-8 JCS(tool_arguments)>",
  "content_type": "<MIME type, e.g. application/protobuf>",
  "body": "<base64url-encoded native request body>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `pop_args` | string | UTF-8 JCS(tool_arguments) — the PoP-binding payload. Identical to what the PoP transcript hashes. |
| `content_type` | string | MIME type of the native body (e.g., `"application/protobuf"`). |
| `body` | string | base64url-encoded native request body. MUST be derived deterministically from `pop_args` via a registered canonical codec. |

**Semantic equivalence invariant (MUST).** The Assembler MUST construct `body` deterministically from `tool_arguments` using the tool's registered canonical codec — it MUST NOT accept `body` independently from the Agent. The RS MUST re-derive `expected_body` from `pop_args` via the same codec and reject if `body != expected_body` (Step 13 failure).

**Canonical codec registration (requires companion specification).** Each non-JSON `content_type` used with `require_pop = true` and `require_channel_encryption = true` (the full `request_format = 0x01` condition set) MUST have a registered deterministic codec in a companion codec-registry specification agreed between peers. This SEP does not define the codec-registry format, governance, or version-negotiation surface; those are future work. Until a codec-registry companion specification exists and peers have negotiated its version, `request_format = 0x01` is outside base conformance and implementations MUST reject per §3.6.1.

**RS payload disambiguation.** The RS reads `request_format` from the token header (byte 3) before decryption: `0x01` = parse decrypted payload as `HaapRequestEnvelope`; `0x00` = parse as direct request body. The `msg_type` field (byte 2) remains a closed enum and is NOT used as a bitfield.

> **MCP note.** For standard MCP `tools/call` invocations, `content_type` is null and `request_format` is always `0x00`. The envelope mechanism is transparent to MCP-only deployments.

#### 3.6.1 Base Conformance — Rejection of Non-JSON PoP (r38)

Under base SEP conformance for this revision, the three-condition set that would otherwise trigger `request_format = 0x01` MUST be rejected at the earliest reachable layer. This ensures the companion codec-registry dependency does not silently leak into the default interoperable path.

The rejection layer depends on which deployment profile is in use and which component first observes the triggering condition. In Profile E, the Assembler is the earliest reachable layer for most requests because it sees the `ToolCallRequest.content_type` field before any token work begins; the Assembler MUST reject pre-mint with `RequestRejected{reason: NonJsonPopNotSupported}` when all three conditions hold and no companion codec-registry version has been negotiated. If a request nevertheless reaches the TQS (for example, due to a Profile-S client or a malformed Assembler), the TQS MUST reject at mint-gate with `InvocationRejected{reason: MintFailure, detail: "non-json-pop-not-in-scope"}` rather than minting a token with `request_format = 0x01`. If a token with `request_format = 0x01` nevertheless reaches an RS that does not support the companion specification, the RS MUST reject at cascade Step 1 with denial code `NON_JSON_POP_NOT_SUPPORTED` / `failed_check: CONFORMANCE_SCOPE`.

Implementations that wish to support `request_format = 0x01` MUST do so by implementing the eventual companion codec-registry specification and negotiating its version with peers at the capability-advertisement stage. Such implementations remain extended-conformance for this SEP; base conformance is defined by the rejection behavior above.

The denial code `NON_JSON_POP_NOT_SUPPORTED` is added to the denial-code table in §6 for this revision.

### 4. Token Lifecycle

#### 4.1 Token Acquisition

TBAC tokens are acquired through a **Token Queue Service (TQS)** — a local sidecar process that pre-mints tokens before the agent needs them. The TQS-to-agent interface depends on the deployment profile:

**Profile E (Assembler, REQUIRED for new production deployments):**

```
SDK Supervisor/Scheduler (parent — control plane, zero crypto)
  ├── Authenticator        (UDS: auth-tqs.sock)
  ├── TQS                  (UDS: auth-tqs.sock, tqs-assembler-*.sock)
  ├── Assembler[0]         (UDS: tqs-assembler-0.sock, agent-assembler-0.sock)
  ├── Assembler[1]         (UDS: tqs-assembler-1.sock, agent-assembler-1.sock)  ← pool (§11.1.1)
  ├── ...
  ├── Assembler[N-1]       (UDS: tqs-assembler-{N-1}.sock, agent-assembler-{N-1}.sock)
  └── Agent/LLM            (UDS: agent-assembler-*.sock — ZERO CRYPTO)
         │ HTTPS (Assembler[i] → RS)
    ┌────▼────┐
    │   RS    │◄──key table──────────────────────────────────────────────┐
    │(Resource│  provisioning                                           │
    │ Server) │                                                    ┌────┴────┐
    └─────────┘                                                    │   AS    │
                                                                   └─────────┘
```

Note: N=1 is the default (single-Assembler model). N>1 enables concurrent tool invocations via the Assembler Pool (§11.1.1). Max N = `maxAssemblersPerAgent` (default: 8).

**Profile S (direct-attach, constrained/development deployments):**

```
┌─────────┐   local IPC   ┌─────────┐   local IPC   ┌─────────┐
│  Agent   │ ◄──────────► │   TQS   │ ◄──────────── │  Auth-  │
│ (MCP     │  DequeueToken │ (local  │  session mat. │ enticator│
│  Client) │  TokenStatus  │ sidecar)│  (K_session,  │ (local  │
│          │               │         │  verif_secret,│ process)│
└─────────┘               └────┬────┘  mutual_auth)  └────┬────┘
                               │                          │
                          ┌────▼────┐               ┌─────▼────┐
                          │   RS    │◄──key table────│    AS    │
                          │(Resource│  provisioning  │  (Auth.  │
                          │ Server) │                │  Service)│
                          └─────────┘               └──────────┘
```

**Profile E actor responsibilities (r27):**
- **Agent ↔ Assembler[i]:** Plaintext IPC only. Agent sends `ToolCallRequest{tool, action, resource, constraints, plaintext_request_body, tool_arguments, claimed_intent_hash, target_rs_url, http_method, content_type}`. Assembler returns `ToolCallResponse{plaintext_response_body, http_status}`, `RequestRejected`, or `PendingNotification`. Agent NEVER holds tokens, `response_key`, or any cryptographic material. The Supervisor dispatches each request to an idle Assembler in the pool (round-robin or least-recently-used); the Agent does not choose which Assembler handles its request.
- **Assembler[i] ↔ TQS:** Token and key IPC. Assembler sends `PrepareInvocation{agent_instance_id, requested_scope, tool_arguments, http_method, target_rs_url, selected_aud_hash, claimed_intent_hash, content_type}` to TQS. The Assembler does NOT validate `claimed_intent_hash` itself — it forwards the value for TQS authoritative comparison (§4.7 three-layer model). Under base conformance, the Assembler MUST pre-mint reject requests where `content_type` is non-null AND `require_pop = true` AND `require_channel_encryption = true` and no companion codec-registry version has been negotiated (§3.6.1), returning `RequestRejected{reason: NonJsonPopNotSupported}` without forwarding to the TQS. When the Assembler does forward a valid `PrepareInvocation`, the TQS validates `selected_aud_hash` against its cached `SetDestinationPolicy` entries and validates `claimed_intent_hash` against its authoritative `expected_intent_hash`; on either mismatch the TQS rejects via `InvocationRejected` (§11.3) with no token minted. On success, TQS mints the token with `aud_hash = selected_aud_hash` and `request_format = 0x00` for all base-conformance requests. TQS returns `TokenDelivery{token_bytes, response_key, expected_intent_hash, session_id, pop_proof}`. Assembler performs K_req/K_resp derivation, request encryption, response decryption, and token attachment, and separately performs a post-mint defense-in-depth comparison of `claimed_intent_hash` against `TokenDelivery.expected_intent_hash` (§4.7 Layer 2).
- **Authenticator ↔ TQS:** Policy IPC. Relays `SetSessionContext`, `MintPolicy`, `UpdateMintPolicy`, `SetIntent`, `ClearIntent`, `SuspendSession`, `TrustUpgrade`, `SetDestinationPolicy`.
- **Authenticator ↔ AS:** X3DH 4-DH key agreement. The Authenticator is a separate trusted process — distinct from both the agent/LLM runtime, the TQS, and the Assembler(s).
- **AS → RS:** Provisions session key-table entry (`K_session`, `verifier_secret`, `mutual_auth`, `session_id`) out-of-band. The RS never contacts the AS for per-token operations.

**Profile S actor responsibilities (unchanged from r26):**
- **Agent ↔ TQS:** Local IPC only. Three permitted message types: `DequeueToken(tool_name)`, `TokenStatus()`, `SessionInfo()`. TQS rejects all other agent-channel messages.
- All other actor relationships are identical to Profile E except the Agent holds `response_key` and performs K_req/K_resp derivation directly.

The TQS:
- Runs as a separate process alongside the agent, managed by the SDK supervisor
- Pre-mints batches of single-use tokens (typically 10) with short TTLs (default 60s)
- Receives `verifier_secret`, `mutual_auth`, and `session_id` from the **user Authenticator** via authenticated IPC — the Authenticator performs the X3DH handshake with the AS and relays session artifacts to the TQS; `K_session` is available within the same hardened trust boundary; **the AS and TQS never communicate directly**
- Receives policy-authored privilege classifiers from the policy component; computes `priv_sig = HMAC-SHA-256(K_priv[epoch], canonical(scope))` where `K_priv[epoch] = HKDF(IKM=K_session, salt=uint64_be(epoch), info="io.modelcontextprotocol/tbac:priv-sig:v1" ∥ uint64_be(session_id), L=32)`, then packages the token
- **MUST NOT communicate with the AS directly** — the user Authenticator is the sole relay for all session material
- **MUST NOT modify** privilege classifiers received from the policy component

The agent's experience is equivalent to using an API key: call a local endpoint ("give me a token for this tool and action" in Profile S, or "execute this tool call" in Profile E), receive an opaque token or plaintext response, proceed.

#### 4.1.1 Session Establishment — Required Outputs and Security Properties

Session establishment is **out of scope for this SEP**. TBAC is agnostic to the specific mutual authentication protocol used, provided that protocol delivers the required session artifacts with the security properties below. This decoupling allows TBAC to be used with different authentication layers while keeping the TBAC token format and verification cascade stable.

**Required session artifacts.** Whatever session establishment protocol is used MUST produce the following artifacts and provision them to the appropriate parties before any TBAC tokens are minted:

| Artifact | Held by | Security requirement |
|----------|---------|---------------------|
| `K_session` | TQS + RS (shared) | Derived exclusively by the Authenticator (client) via X3DH key agreement with AS. The TQS does not participate in X3DH. The Authenticator relays `session_id`, `verifier_secret`, and `mutual_auth` to the TQS via authenticated IPC. For `K_session` delivery, two implementation patterns are permitted: **(a)** the Authenticator passes `K_session` to the TQS over the same authenticated IPC channel, or **(b)** the Authenticator and TQS are co-resident in the same hardened process boundary and share `K_session` through in-process memory. In either case, `K_session` MUST NOT transit outside the hardened client boundary. Provisioned to the RS key-table directly by the AS. Agent/LLM runtime MUST NOT hold this value. |
| `session_id` | TQS + RS + token header | Globally unique, monotonically allocated by AS (e.g., atomic Redis INCR); MUST NOT be reused across sessions |
| `verifier_secret` | TQS (sealed in token body) + RS (key-table) | 256-bit random value generated by AS; delivered to client in signcrypted session response; client relays to TQS via IPC. Provides designated-verifier binding in Schnorr challenge hash. |
| `mutual_auth` | TQS (sealed in token body) + RS (key-table) | 256-bit random value generated by the **client (Authenticator)** via CSPRNG; sent to AS, echoed back in session response, provisioned to RS key-table; client relays to TQS via IPC. Defense-in-depth session binding. |
| `pop_pub` | RS key-table only | Ed25519 public key generated by TQS sidecar during session setup and provisioned to RS key-table via Authenticator relay; session-bound (rotated per X3DH session). Required only when `require_pop: true` is used. See §3.5 for key lifecycle. |
| Session validity window | RS key-table | Time-bounded session lifetime; RS rejects tokens minted outside this window (Step 4 check) |
| `profile` | RS key-table | `"enterprise"`, `"consumer"`, or `"ephemeral"`; determines cascade branching at Step 2. Set by AS at Phase 2. |
| `user_sign_pk` | RS key-table | Consumer only: user's Ed25519 public key for Step 16 `user_policy_sig` verification. Registered during Phase 1. |
| `rs_sign_pk` | Client | Consumer only: RS's Ed25519 public key for receipt verification. Published and registered with platform. |
| `org_id` | RS key-table + scope JSON | Organization trust boundary identifier. Provisioned by Authenticator via AS relay. |

**Required security properties.** The session establishment protocol MUST provide:
- **Mutual authentication** — the client Authenticator and the AS authenticate to each other via X3DH; the RS is provisioned with session material by the AS out-of-band. The TQS, Assembler, and the agent/LLM runtime are not principals in this authentication.
- **Forward secrecy** — compromise of long-term keys does not expose past session keys.
- **Key Compromise Impersonation (KCI) resistance** — compromise of one party's long-term key does not allow impersonation of the other party.
- **Authenticator-as-sole-relay** — the AS and TQS MUST NOT communicate directly. The user Authenticator receives session material from the AS (inside a signcrypted response) and relays `verifier_secret`, `mutual_auth`, and `session_id` to the TQS via authenticated IPC. `K_session` is available to the TQS within the same hardened client trust boundary; it MUST NOT transit outside that boundary. This isolation ensures that if the TQS is compromised, the attacker cannot leverage a direct TQS→AS channel to escalate.

**Reference implementation.** The Hawcx AIAA Protocol (see References) implements session establishment using X3DH Extended Triple Diffie-Hellman ([Signal X3DH spec](https://signal.org/docs/specifications/x3dh/)) in 4-DH Mode B, with the AS mediating key-table provisioning. This is one conformant implementation of the above contract; other implementations satisfying the security properties above are permitted.

#### 4.2 Token Transport (updated r27)

When a TBAC-enabled MCP client invokes a tool, it MUST include the TBAC token in the `_meta` field of the `tools/call` request.

**Base64url encoding convention.** All binary fields transmitted as strings in `_meta` fields and scope JSON use base64url encoding as defined in RFC 4648 §5 — URL-safe alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`), **no padding characters** (`=`). This applies to: the opaque token value, `pop.sig`, `parent_token_hash`, and `priv_sig` if exposed in diagnostic contexts. Implementations MUST NOT include padding and MUST accept tokens without padding.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "query_database",
    "arguments": {
      "query": "SELECT * FROM invoices WHERE quarter = 'Q3'"
    },
    "_meta": {
      "io.modelcontextprotocol/tbac": {
        "token": "<base64url-encoded-opaque-token>",
        "format": "opaque"
      }
    }
  }
}
```

> **Note:** A JOSE (JWE/JWS) token format profile with FIPS-approved primitives is planned for a future revision of this extension. Implementations requiring FIPS compliance SHOULD track the extension's version updates for JOSE profile availability.

> **Profile E transport note (r27).** In Profile E deployments, the Assembler constructs the `_meta` field and attaches the token to the outgoing HTTP request. The Agent/LLM never constructs this JSON — it sends a `ToolCallRequest` with plaintext arguments to the Assembler, and the Assembler handles all token attachment and encryption. The JSON-RPC structure above describes the wire format that the RS receives, regardless of which profile produced it.

#### 4.3 Token Verification (updated r27)

> **Session key-table terms.** The verification cascade references session-scoped values that are established during X3DH mutual authentication (Phase I/II) and stored in the RS key-table. Definitions:
>
> - **`K_session`** — The shared symmetric session key derived by the user Authenticator via X3DH four-DH key agreement with the AS. Available to the TQS within the same hardened client trust boundary; provisioned to the RS key-table directly by the AS. All per-token keys are derived from `K_session` via HKDF. Lifecycle: one per X3DH session, rotated on low-water-mark re-authentication.
> - **`verifier_secret`** — A 256-bit random value generated by the authentication server during session setup and provisioned to both the TQS (for inclusion in the token body) and the RS key-table. It is included in the Schnorr designated-verifier challenge hash, ensuring only the RS holding the correct `verifier_secret` can verify the Schnorr signature. This is the designated-verifier binding mechanism: the token is verifiable only to the intended RS.
> - **`mutual_auth`** — A 256-bit random value generated by the **client Authenticator** via CSPRNG during session setup. Sent to the AS during session init, echoed inside the signcrypted session response, provisioned by the AS to the RS key-table, and relayed by the Authenticator to the TQS via IPC. Its presence in the token body and in the key-table serves as a defense-in-depth session-binding check after decryption (Step 8). The agent/LLM runtime does not generate or observe this value.
> - **Session validity window** — A time-bounded acceptance window (e.g., `[session_start, session_start + max_session_duration]`) stored in the session record. Step 4 verifies that the token was minted within an active session window, rejecting tokens minted after the session was invalidated or expired. The session validity window is distinct from the token TTL (`exp - iat`): TTL bounds individual token freshness; the session validity window bounds the session's overall authorized lifetime.

The MCP server (acting as resource server) MUST verify the TBAC token before executing the tool. Verification follows a **17-step cascade** (enterprise profile), **19-step cascade** (consumer profile), or **13-step cascade** (T0 ephemeral), organized into four tiers for DoS resilience — early tiers reject invalid tokens with minimal computation:

**Tier 1 — Header-only (Steps 1–4, no public-key or AEAD operations; only parsing, key-table lookup, and SHA-256 audience hashing):**

1. **Framing check** — Token version (0x03), algorithm ID (0x01), message type (`0x03`/`0x08`/`0x09`), `request_format` (`0x00`/`0x01`) validation
2. **Session lookup** — Retrieve session key-table entry; read `profile` and branch cascade. Reject immediately if no entry exists or `status ≠ active`
3. **Temporal + audience validation** — `iat` within acceptable clock skew, `exp` not passed; `aud_hash` (bytes 48–79) matches `SHA-256(UTF-8(own_identifier))`
4. **Session validity window** — SEK within validity window; session validity check against the session record

**Tier 2 — Cryptographic (Steps 5–7):**

5. **K_tok derivation** — Derive per-token encryption and signing keys via HKDF from K_session + jti
6. **Schnorr verification** — Designated-verifier Schnorr signature over Ristretto255 (uses verifier_secret from key table to reconstruct challenge hash — pre-decryption verification)
7. **AEAD decryption** — AES-256-GCM decryption of token body

**Tier 3 — Defense-in-depth + TBAC (Steps 8–15):**

8. **mutual_auth check** — Constant-time equality: key-table value vs. token-body copy
9. **verifier_secret check** — Constant-time equality: key-table value vs. token-body copy
10. **Replay pre-check** — `GET hawcx:replay:{session_id}:{jti}`; reject immediately if marker exists (fast-reject for known replays). Do NOT consume yet.
11. **Policy epoch validation** — `policy_epoch` ≥ RS current epoch; reject stale-epoch tokens
12. **Privilege signature** — `priv_sig` HMAC-SHA-256 verified against canonicalized scope JSON using `K_priv[policy_epoch]`
13. **TBAC scope evaluation + `org_id` check** — `aud` cross-checked against RS's own identifier (post-decryption complement to Step 3); constant-time `org_id` mismatch check against key-table; scope JSON evaluated against RS-side policy template for this `agent_instance_id`; `tool`, `action`, `resource`, and `constraints` all validated
13.5. **HAAPI billing verification (CONDITIONAL)** — If `scope_json.haapi_proof` is present: verify expiry → HMAC daily-key → Ed25519 non-repudiation → log metering event. Skipped when `haapi_proof` is absent. (~85µs when active)
13.7. **Intent verification (CONDITIONAL)** — If `scope_json.user_raw_intent` is present: hash integrity check (`SHA-256(user_raw_intent) == intent_hash`), then intent-action comparison per RS-configured `intent_verification_mode`. Three modes: `log_only` (0µs, audit only), `keyword_match` (~5µs, action verb/resource path match), `classifier` (≤50ms, external endpoint). On mismatch: `block_and_log`, `escalate_to_ciba`, or `log_only` per `intent_mismatch_action`. Skipped when `user_raw_intent` is absent. See §4.7.
14. **Proof-of-possession** — If `require_pop: true`: verify Ed25519 `pop_sig` over canonical transcript using `pop_pub` from key-table. Skipped when `require_pop: false`.
15. **Replay consume** — Atomic `SET hawcx:replay:{session_id}:{jti} 1 NX EX {token_ttl + grace}`. Reject if SETNX fails (concurrent consumer won the race). This step executes ONLY after all validation gates (Steps 1–14) have passed.

> **PoP ordering for externalized side effects.** When `require_pop = true` AND `intent_verification_mode` is `classifier` or `intent_mismatch_action` is `escalate_to_ciba`, the RS MUST verify PoP (Step 14) BEFORE executing Step 13.7's external classifier call or CIBA escalation signal. This prevents a token holder without `pop_priv` from driving external work before sender-binding fails. For `log_only` and `keyword_match` modes (which are purely local), the standard cascade ordering (13.7 before 14) is retained.

**Tier 4 — Consumer Profile (Steps 16–17, consumer only; ~160µs additional):**

16. **User policy signature** (consumer only, ~80µs) — Extract `user_sign_pk` from key table (NOT from token body — prevents key substitution). Reconstruct `policy_transcript = "hawcx-user-policy-v1" ∥ uint64_be(session_id) ∥ uint64_be(policy_epoch) ∥ u32be(len(UTF-8(agent_instance_id))) ∥ UTF-8(agent_instance_id) ∥ u32be(len(CanonicalJSON(scope))) ∥ CanonicalJSON(scope) ∥ uint64_be(signed_at)`. `Ed25519_Verify(user_sign_pk, policy_transcript, user_policy_sig)`. Verify `signed_at` within ±300s of `iat`. If `session.tsa_required`: verify `tsa_token` (RFC 3161 signature, hash, timestamp window).
17. **RS receipt generation** (consumer only, ~80µs, POST-execution) — Construct `receipt_transcript = "hawcx-rs-receipt-v1" ∥ uint64_be(session_id) ∥ jti (raw 16 bytes) ∥ u32be(len(CanonicalJSON(scope))) ∥ CanonicalJSON(scope) ∥ SHA-256(request_body) ∥ SHA-256(response_body) ∥ uint8(result_code) ∥ uint64_be(executed_at)`. `rs_receipt_sig = Ed25519_Sign(rs_sign_sk, receipt_transcript)`. Include in encrypted response `_meta`.

**Cascade ordering rationale.** The cascade enforces verify-then-decrypt ordering: Step 6 (Schnorr signature verification) MUST complete before Step 7 (AEAD decryption). This prevents decryption-oracle attacks by ensuring the ciphertext is authenticated before any decryption is attempted. The replay mechanism uses a two-phase reserve/commit model: Step 10 is a non-destructive pre-check (GET) — if a replay marker exists, reject fast. Step 15 is the atomic consume (SETNX) — marks the token as used ONLY after all validation gates pass. This prevents **token-burn DoS**: an attacker who obtains a token but cannot produce valid PoP cannot permanently consume the token, because SETNX occurs after PoP verification.

**Total verification latency:** <490µs for the 17-step enterprise cascade with HAAPI + intent `log_only`. <400µs without HAAPI proof and intent. Consumer cascade: <690µs for 19 steps. The `classifier` intent mode adds up to 50ms and is NOT RECOMMENDED for latency-sensitive deployments.

If any step fails, the server MUST reject the request. The server SHOULD return a structured error indicating the failure category (see §6).

#### 4.4 Single-Use Semantics

Each TBAC token MUST be consumed on first successful use. Implementations MUST use atomic operations (e.g., Redis `SETNX` or compare-and-swap) to prevent concurrent consumption. A token that has been consumed MUST be rejected on any subsequent presentation, regardless of whether it is within its TTL.

Replay cache sizing: with a default 60s TTL, the RS must maintain consumed `jti` entries for at least `TTL + clock_skew` seconds. At fleet scale, implementations SHOULD use TTL-based automatic expiry (e.g., Redis key TTL) rather than manual eviction to ensure deterministic cleanup. Replay markers MUST use the key format `hawcx:replay:{session_id}:{jti}` with `SET key 1 NX EX ttl` semantics. The TTL MUST be ≥ `token_ttl` + `skew_tolerance` (RECOMMENDED: `token_ttl` + 60s).

#### 4.5 Trust Levels (r27)

The protocol defines four trust levels that govern enrollment, token minting, and RS verification behavior. Trust levels are **policy outputs** — the result of an external policy engine evaluation, not protocol modes selected by an operator.

| Tier | Name | Policy Decides When | Enrollment | Token Capability |
|------|------|---------------------|------------|-----------------|
| T0 | Ephemeral | Agent unrecognized; domain permitted for discovery | Ephemeral DH (lightweight key-table entry) | Read-only, `max_calls` capped |
| T1 | Enrolled | Agent class matches a policy permit rule | Full X3DH | Standard TBAC scope |
| T2 | Policy-bound | Agent class permitted with constraint enforcement | Full X3DH | TBAC + constraint evaluation |
| T3 | Human-confirmed | Policy requires `require_ciba: true` | Full X3DH + CIBA gate | TBAC + `human_confirmed_at` + `approval_digest` |

**Monotonic upgrade.** Trust level can increase within a session but MUST NOT decrease. T0 → T1 via X3DH enrollment. T1 → T2 via policy epoch binding. T2 → T3 via CIBA approval. Downgrade requires session termination and re-enrollment.

#### 4.6 Transaction Lifecycle (r27)

The Authenticator-facing IPC channel supports transaction management for multi-step workflows:

```
BeginTransaction {
  txn_id: [u8; 16],   // CSPRNG-generated by Authenticator
  session_id: u64,     // Session identifier
  max_tokens: u32,     // Budget for this transaction (0 = unlimited)
  txn_ttl_sec: u32,    // Transaction-level timeout (RECOMMENDED: 300s)
}

EndTransaction {
  txn_id: [u8; 16],    // Transaction identifier
  session_id: u64,     // Session identifier
  reason: enum,        // Completed | Timeout | Revoked | Error
}
```

Between `BeginTransaction` and `EndTransaction`, all tokens minted by the TQS for this `session_id` carry the specified `txn_id` in their `scope_json`. At most one transaction MAY be active per session at any time. If `max_tokens` is reached, the TQS returns `TxnBudgetExhausted`. If `txn_ttl_sec` elapses, the TQS auto-issues an implicit `EndTransaction` with reason `Timeout`.

#### 4.7 Intent Verification (r27)

Intent verification provides a mechanism to detect divergence between a user's stated intent and the agent's requested tool invocation. Intent data is delivered to the TQS via `SetIntent` IPC (per-conversation-turn, separate from session-scoped `MintPolicy`).

**RS Step 13.7 procedure (when `user_raw_intent` is present):**

1. **Hash integrity:** Verify `SHA-256(user_raw_intent) == intent_hash`. Reject with `IntentIntegrityFailed` on mismatch.
2. **Intent-action comparison** per the RS-configured `intent_verification_mode`:
   - `log_only` (0µs): Log the intent alongside the tool invocation for audit. No enforcement.
   - `keyword_match` (~5µs): Compare action verbs and resource path tokens from the intent against the scope JSON fields. Reject on mismatch per `intent_mismatch_action`.
   - `classifier` (≤50ms): Forward intent and scope to an external classification endpoint. RECOMMENDED for high-security deployments; NOT RECOMMENDED for latency-sensitive paths.
3. **On mismatch:** Behavior per `intent_mismatch_action` configuration: `block_and_log` (reject token), `escalate_to_ciba` (trigger CIBA approval for the divergent scope), or `log_only` (permit but log).

**Three-layer intent verification (Profile E).** In the Assembler deployment profile, intent verification is enforced across three independent layers:

1. **Layer 1 — TQS mint-gate (PRIMARY, authoritative, r37).** The Agent forwards `claimed_intent_hash` through the Assembler to the TQS in `PrepareInvocation`. When intent mode is active, the TQS compares `claimed_intent_hash` against its authoritative `expected_intent_hash` (held inside the AEAD-sealed `scope_json` that only the TQS can decrypt). On mismatch, the TQS rejects with `InvocationRejected{reason: IntentHashMismatch}` without minting — no token issued, no approval budget consumed. This is the primary enforcement point. The `expected_intent_hash` is never cached at the Assembler because only the TQS holds the authoritative view.
2. **Layer 2 — Assembler post-mint (defense-in-depth).** After the TQS returns `TokenDelivery`, the Assembler compares `claimed_intent_hash` against `TokenDelivery.expected_intent_hash`. On mismatch, the Assembler rejects with `RequestRejected{reason: HashMismatch}` and voids the token. This catches corruption or tampering on the TQS→Assembler IPC path. It is NOT the primary check — the TQS already performed the authoritative comparison at Layer 1.
3. **Layer 3 — RS Step 13.7 (existing).** The RS performs hash-integrity and intent-action comparison per §4.7 RS Step 13.7 procedure above. This is the final enforcement at the resource boundary.

**Bounded escalation window (Pool deployments).** In Assembler Pool deployments (§11.1.1), up to `maxAssemblersPerAgent - 1` in-flight requests may execute at the RS before an intent escalation signal (from RS Step 13.7 `escalate_to_ciba`) propagates through Auth→TQS and takes effect. This is a bounded window (max 7 additional requests at default pool size of 8). The escalation blocks the (N+1)th request and all subsequent ones. Deployments requiring zero-tolerance intent enforcement SHOULD set `maxAssemblersPerAgent = 1` (single-flight mode).

### 5. Step-Up Authorization

TBAC defines a challenge profile for acquiring per-invocation authorization. The client acquires a TBAC token from its local TQS and retries — no OAuth re-authentication is required.

**MCP transport semantics.** Both step-up ("no token present") and verification failure ("token invalid") MUST use the same `CallToolResult` envelope with `isError: true`. This unifies all TBAC authorization outcomes in a single, consistently handled response surface — MCP SDKs and orchestrators can apply a single error-handling path for all TBAC denials regardless of cause. The `_meta` field carries the machine-readable reason and, for step-up, the acquisition hint.

When a tool call requires TBAC authorization and no valid token is present, the server MUST respond with a `CallToolResult`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "isError": true,
    "content": [
      {
        "type": "text",
        "text": "TBAC authorization required for tool 'query_database'"
      }
    ],
    "_meta": {
      "io.modelcontextprotocol/tbac": {
        "denied": true,
        "reason": "TBAC_REQUIRED",
        "failed_check": "TOKEN_ABSENT",
        "tool": "query_database",
        "action": "read",
        "resource": "billing-api/invoices/*",
        "hint": "Acquire a TBAC token scoped to this tool and action from your local TQS and retry"
      }
    }
  }
}
```

The client SHOULD inspect `_meta["io.modelcontextprotocol/tbac"]` to acquire an appropriately scoped TBAC token from its TQS and retry the request.

For Streamable HTTP transport, the server MAY additionally include an HTTP-level header to support middleware that inspects transport headers. This header is advisory and supplements the `CallToolResult` — it does not replace it:

```http
WWW-Authenticate: Bearer error="insufficient_scope",
  scope="io.modelcontextprotocol/tbac",
  tbac_tool="query_database",
  tbac_action="read",
  tbac_resource="billing-api/invoices/*"
```

### 6. Structured Denial Responses

When TBAC verification fails, the server MUST return the denial as a successful JSON-RPC response whose `result` is a `CallToolResult` with `isError: true`. The `_meta["io.modelcontextprotocol/tbac"]` field carries the machine-readable denial details for programmatic remediation.

> **Note on step numbering in denial metadata.** Denial responses use a stable `failed_check` identifier (e.g., `"TBAC_SCOPE_EVALUATION"`) rather than a numeric step number. Step numbers are an implementation detail of the verification cascade (§4.3) and are subject to change as the cascade evolves. Stable identifiers are safe to hard-code in clients; numeric step references are not.

TBAC denial reason codes:

| Code | `failed_check` | Description |
|------|----------------|-------------|
| `TBAC_REQUIRED` | `TOKEN_ABSENT` | No TBAC token present; client must acquire one and retry |
| `MALFORMED_TOKEN` | `FRAMING_CHECK` | Token structure invalid |
| `SESSION_NOT_FOUND` | `SESSION_LOOKUP` | No key-table entry for presented session |
| `STALE_TIMESTAMP` | `TEMPORAL_VALIDATION` | Token expired or timestamp outside skew |
| `AUD_MISMATCH` | `AUDIENCE_VALIDATION` | `aud_hash` does not match RS's own identifier (pre-decryption) or decrypted `aud` string does not match RS's own identifier (post-decryption) |
| `SESSION_EXPIRED` | `SESSION_VALIDITY` | Session validity window expired |
| `KEY_DERIVATION_FAILED` | `KEY_DERIVATION` | Per-token key derivation failed |
| `INVALID_SIGNATURE` | `SCHNORR_VERIFICATION` | Cryptographic signature verification failed |
| `DECRYPTION_FAILED` | `AEAD_DECRYPTION` | AEAD decryption failed |
| `MUTUAL_AUTH_MISMATCH` | `MUTUAL_AUTH_CHECK` | mutual_auth cross-check failed (defense-in-depth) |
| `VERIFIER_SECRET_MISMATCH` | `VERIFIER_SECRET_CHECK` | verifier_secret cross-check failed (defense-in-depth) |
| `TOKEN_REPLAYED` | `REPLAY_CONSUME` | Token already consumed (jti seen in replay cache) |
| `EPOCH_EXPIRED` | `POLICY_EPOCH_VALIDATION` | `policy_epoch` outside server's accepted window |
| `PRIVILEGE_SIG_INVALID` | `PRIVILEGE_SIGNATURE` | `priv_sig` HMAC verification failed |
| `INSUFFICIENT_PRIVILEGE` | `TBAC_SCOPE_EVALUATION` | TBAC scope insufficient for requested operation |
| `ORG_ID_MISMATCH` | `ORG_ID_VALIDATION` | `scope_json.org_id` does not match `key_table.org_id` (tenant isolation) |
| `POP_REQUIRED` | `POP_MISSING` | `require_pop: true` but no `pop` field in `_meta` |
| `POP_FAILED` | `POP_VERIFICATION` | Ed25519 PoP signature verification failed |
| `CHANNEL_ENCRYPTION_REQUIRED` | `CHANNEL_ENCRYPTION_MISSING` | `require_channel_encryption` is true but request lacks `enc` field in `_meta` |
| `MALFORMED_REQUEST` | `REQUEST_FRAMING` | Request structure invalid |
| `USER_POLICY_SIG_INVALID` | `USER_POLICY_SIG_VERIFICATION` | `user_policy_sig` Ed25519 verification failed (consumer profile, Step 16) |
| `USER_POLICY_SIG_EXPIRED` | `USER_POLICY_SIG_TIMESTAMP` | `signed_at` outside acceptable ±300s window (consumer profile, Step 16) |
| `TSA_TOKEN_MISSING` | `TSA_VERIFICATION` | `tsa_required=true` but `tsa_token` absent (consumer profile, Step 16) |
| `TSA_TOKEN_INVALID` | `TSA_VERIFICATION` | TSA signature/hash verification failed (consumer profile, Step 16) |
| `INTENT_INTEGRITY_FAILED` | `INTENT_HASH_CHECK` | `SHA-256(user_raw_intent) ≠ intent_hash` (Step 13.7) |
| `INTENT_MISMATCH` | `INTENT_ACTION_COMPARISON` | Intent-action comparison failed with `block_and_log` action (Step 13.7) |
| `INTENT_PAYLOAD_TOO_LARGE` | `INTENT_VALIDATION` | `user_raw_intent` exceeds 4096 bytes UTF-8 |
| `CIBA_APPROVAL_EXPIRED` | `CIBA_VALIDATION` | `human_confirmed_at` outside CIBA approval window (T3 Step 13) |
| `APPROVAL_DIGEST_MISMATCH` | `CIBA_DIGEST_VALIDATION` | Recomputed `approval_digest` does not match token's value (T3 Step 13) |
| `NON_JSON_POP_NOT_SUPPORTED` | `CONFORMANCE_SCOPE` | `request_format = 0x01` presented but implementation does not support the companion codec-registry specification required for non-JSON PoP (§3.6.1). Added in r38 to align with HAAP v6.0.0 base-conformance scope. |

Servers MAY choose to return opaque denials (mapping cryptographic failures to a generic `AUTHORIZATION_FAILED` / `failed_check: "CRYPTOGRAPHIC_VERIFICATION"`) for security reasons to avoid leaking verification step details.

### 7. Policy Template Discovery

MCP servers that support TBAC MAY expose policy templates to help clients understand what authorizations are available. This uses a new JSON-RPC method `tbac/templates`.

> **Method naming note:** This SEP uses the short form `tbac/templates` consistent with MCP's existing method naming convention (e.g., `tools/list`, `resources/read`). If the MCP extension registry adopts fully-qualified method naming, this method would be `io.modelcontextprotocol/tbac/templates`. Implementations SHOULD document which naming form they support; future revisions of this SEP will align with whatever convention the extension registry standardizes.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tbac/templates",
  "params": {
    "agent_instance_id": "code-deploy-agent"
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "templates": [
      {
        "tool": "query_database",
        "allowed_actions": ["read"],
        "max_delegation_depth": 1,
        "permitted_audiences": ["analytics-rs.org-b.example.com"],
        "constraints_ceiling": {
          "max_rows": 1000,
          "max_calls": 10,
          "time_window_sec": 60
        },
        "min_trust_level": 1
      },
      {
        "tool": "deploy_service",
        "allowed_actions": ["execute"],
        "max_delegation_depth": 0,
        "permitted_audiences": ["deploy-rs.org-a.example.com"],
        "require_pop": true,
        "constraints_ceiling": {
          "max_calls": 1
        },
        "min_trust_level": 3,
        "require_ciba": true,
        "require_intent_capture": true
      }
    ]
  }
}
```

Policy templates define the **ceiling** (maximum privilege envelope) for each agent class and tool combination. The privilege classifier in any given token MUST be a subset of the corresponding policy template. The RS validates this at verification step 13.

### 8. Delegation Chains

TBAC supports bounded delegation for multi-agent workflows. When Agent A delegates a subtask to Agent B:

1. Agent A's TQS mints a **delegated token** where:
   - `delegation_depth` is decremented (MUST be strictly less than parent's value)
   - `parent_token_hash` is set to `base64url(SHA-256(TLV-canonical(parent_scope_JSON)))` — using the same TLV canonicalization as `priv_sig` (Appendix A)
   - All privilege fields MUST be equal to or a subset of the parent's scope

2. Agent B presents the delegated token to the RS
3. The RS verifies the delegation chain:
   - `delegation_depth >= 0`
   - `parent_token_hash` validates against known parent
   - Scope is monotonically non-increasing

This prevents privilege escalation through delegation. An agent cannot grant permissions it does not hold. For same-RS delegation, the RS verifies `parent_token_hash` against the parent's classifier hash stored in the consumed-token log. **The parent token MUST have been consumed at that RS before the child token is presented** — if the parent has not yet been recorded in the consumed-token log, the RS MUST reject the child token with `failed_check: TBAC_SCOPE_EVALUATION`. For cross-RS delegation, verification of `parent_token_hash` against the parent classifier is **application-layer** — this SEP does not define the transport mechanism.

#### 8.1 `resource` attenuation under glob subset semantics (r40)

Because `resource` is REQUIRED in r40 (§3.2), the delegation attenuation check for this field is unambiguous. The rule is that the child's `resource` pattern MUST be equal to or a strict subset of the parent's `resource` pattern under glob subset semantics, where:

- `"*"` (single-segment wildcard) is a subset of `"*"`, and is a subset of `"**"` at the same path depth.
- `"**"` (multi-segment wildcard) is a subset of `"**"` only.
- Any literal pattern (e.g., `"public/docs"`) is a subset of any wildcard pattern that matches it (`"public/*"`, `"public/**"`, `"*"`, `"**"`).
- Two literal patterns are in a subset relationship only when one is an exact prefix of the other at a path-segment boundary (`"public/docs/api"` is a subset of `"public/docs"` but not of `"public/do"`).

The TQS MUST evaluate this subset relationship at mint time for every delegated token and MUST reject with `InvocationRejected{reason: ScopeCeilingExceeded}` if the child's `resource` is not a subset of the parent's. The RS MUST additionally evaluate the same relationship at cascade Step 13 (TBAC scope evaluation) as a defense-in-depth check; a delegation chain that passed mint-time attenuation but fails RS-time attenuation MUST be rejected with `failed_check: TBAC_SCOPE_EVALUATION`.

A child `"resource": "*"` under a parent `"resource": "public/*"` is the canonical widening-attack pattern that this rule prevents. The child's `"*"` is a superset of `"public/*"` (it matches more paths), so attenuation MUST reject.

**Transition from r39.** r39 declared `resource` as OPTIONAL with "if omitted, authorization is tool-wide." r40 declares `resource` REQUIRED with explicit `"*"` for tool-wide. Implementations consuming r40-formatted tokens (distinguished by the version string `"2026-04-17-r40"` in the capability advertisement) MUST reject tokens where `resource` is absent or null. During the transition period (r40 through the first subsequent stable revision), implementations MAY additionally accept r39-formatted tokens that omit `resource` by coercing the absent value to `"*"` for evaluation; this behavior is DEPRECATED and implementations that accept such tokens SHOULD emit a warning log indicating the deprecated semantic was exercised. Producers MUST NOT rely on this backward-compatible behavior in new code. The deprecation window closes at the revision after r40; the subsequent revision MUST reject r39-formatted tokens that omit `resource` with no coercion.

### 9. Per-Token Confidential Channel

#### 9.1 Bidirectional Encryption via response_key

Each TBAC token contains a `response_key` — a 256-bit random symmetric key seed generated by the TQS at token mint time. It is embedded inside the AEAD-encrypted token body (accessible to the RS only after signature verification and decryption).

**Profile E (r27).** The TQS delivers the `response_key` to the **Assembler** (not the Agent) via the `TokenDelivery` IPC message. The Assembler derives K_req and K_resp, performs all encryption/decryption, and zeroizes key material after each round-trip. The Agent/LLM never holds `response_key` or derived keys.

**Profile S.** The TQS delivers the `response_key` to the agent separately via secure IPC as an opaque handle — the key material is held in the TQS sidecar's process memory, isolated from the LLM runtime context.

The `response_key` establishes a **bidirectional per-token confidential channel** between the agent (via its TQS sidecar or Assembler) and the specific RS. Two directional keys are derived from the same symmetric seed:

```
K_req = HKDF-SHA-256(
  ikm  = response_key,
  salt = 0x00 (32 zero bytes),
  info = "tbac-req-enc-v1" ∥ uint64_be(session_id),
  L    = 32
)

K_resp = HKDF-SHA-256(
  ikm  = response_key,
  salt = 0x00 (32 zero bytes),
  info = "tbac-resp-enc-v1" ∥ uint64_be(session_id),
  L    = 32
)

IV_resp = HKDF-SHA-256(
  ikm  = response_key,
  salt = 0x00 (32 zero bytes),
  info = "tbac-resp-iv-v1" ∥ uint64_be(session_id),
  L    = 12
)
```

Security properties:

- **RE-1 (bidirectional confidentiality):** Only the token holder (agent via TQS sidecar/Assembler) and the token verifier (RS) can read data in either direction.
- **RE-2 (no side-effect prevention):** Encryption does not prevent side-effecting operations from executing. Side-effect prevention requires the `require_pop` sender-constraint mechanism.
- **RE-3 (channel separation):** Compromise of the network channel (token) does not yield the IPC channel (`response_key`); both are required for end-to-end access.
- **RE-4 (three-channel separation, Profile E, r27):** The three-channel design (token over network Assembler→RS, `response_key` over TQS→Assembler IPC, plaintext over Agent↔Assembler IPC) ensures that compromise of the Agent process yields access to none of the cryptographic channels.
- **RE-5 (directional key independence):** K_req and K_resp are derived with distinct HKDF info strings, preventing cross-direction key reuse.
- **RE-6 (bounded crypto lifetime, Profile E, r27):** The Assembler holds `response_key` material for at most one token at any instant, for the duration of one HTTP round-trip. Zeroized immediately after delivering the decrypted response to the Agent.

### 10. Extension Settings and Confidential Channel Envelope in `_meta`

Servers and clients communicate TBAC-specific metadata in the `_meta` field of relevant messages. The extension namespace `io.modelcontextprotocol/tbac` is used for all TBAC metadata.

All TBAC extension fields are namespaced under `_meta["io.modelcontextprotocol/tbac"]` to avoid collision with other extensions.

#### 10.1 Confidential Channel Envelope (Normative)

When `constraints.require_channel_encryption` is true, encrypted payloads are carried in the `_meta["io.modelcontextprotocol/tbac"]` container using the following fields.

**Cipher suite.** The per-token confidential channel uses **AES-256-GCM** (the same AEAD algorithm used for `CT_body` encryption). The 32-byte derived keys (`K_req`, `K_resp`) are AES-256-GCM keys; IVs are 96 bits (12 bytes). The authentication tag length is 128 bits (16 bytes). Implementations MUST NOT use a different AEAD for the per-token channel than for `CT_body` within the same `alg_id` suite.

**Request (Agent → RS, inside `tools/call` `_meta`):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "query_database",
    "arguments": {},
    "_meta": {
      "io.modelcontextprotocol/tbac": {
        "token": "<base64url-encoded-opaque-token>",
        "format": "opaque",
        "enc": {
          "alg": "AES-256-GCM",
          "iv": "<base64url(12-byte-random-IV)>",
          "ct": "<base64url(ciphertext ∥ 16-byte-GCM-tag)>"
        }
      }
    }
  }
}
```

**Response (RS → Agent, inside `CallToolResult` `_meta`):**

```json
{
  "_meta": {
    "io.modelcontextprotocol/tbac": {
      "enc": {
        "alg": "AES-256-GCM",
        "iv": "<base64url(IV_resp)> or <base64url(12-byte-random-IV)>",
        "ct": "<base64url(ciphertext ∥ 16-byte-GCM-tag)>"
      },
      "receipt": {
        "sig": "<base64url(rs_receipt_sig)>",
        "rs_pk": "<base64url(rs_sign_pk)>",
        "executed_at": 1741305700
      }
    }
  }
}
```

**`enc` field schema:**

| Field | Type | Description |
|-------|------|-------------|
| `alg` | string | REQUIRED. Algorithm identifier. MUST be `"AES-256-GCM"` for `alg_id` `0x01`. |
| `iv` | string | REQUIRED. Base64url-encoded initialization vector (12 bytes). For requests: MUST be a fresh random IV per encryption attempt. For responses: the deterministic `IV_resp` derived from `response_key`, unless the RS uses the random-IV fallback (§9.1 nonce reuse prevention). |
| `ct` | string | REQUIRED. Base64url-encoded ciphertext concatenated with the 16-byte GCM authentication tag (`ciphertext ∥ tag`). |

> **Consumer receipt field.** The `receipt` object is PRESENT only when the token is a consumer profile token (`msg_type = 0x08`) and the RS supports consumer receipts. Enterprise profile responses (`msg_type = 0x03`) MUST NOT include the `receipt` field.

**GCM AAD construction.** The RS MUST use the GCM AAD value `"tbac-req-aad-v1" ∥ uint64_be(session_id) ∥ UTF-8(jti)` for request decryption and `"tbac-resp-aad-v1" ∥ uint64_be(session_id) ∥ UTF-8(jti)` for response encryption, binding the payload to the specific session and token. The agent's TQS sidecar or Assembler MUST use the same AAD construction.

**Plaintext scope.** The encrypted content (`ct` plaintext) depends on the `request_format` field in the token header (byte 3):

- **Requests, `request_format = 0x00` (direct):** The `ct` plaintext is the UTF-8 encoding of the JSON-serialized `params.arguments` object. This is the default for all JSON-native MCP tool calls.
- **Requests, `request_format = 0x01` (enveloped, outside base conformance):** The `ct` plaintext is the UTF-8 encoding of the JSON-serialized `HaapRequestEnvelope` object (§3.6). The RS MUST parse the decrypted payload as a `HaapRequestEnvelope` and extract `pop_args` for PoP verification and `body` for execution. `request_format = 0x01` requires a companion codec-registry specification negotiated between peers (§3.6, §3.6.1); implementations that do not support the companion specification MUST reject such tokens per §3.6.1. `request_format = 0x01` MUST only be used when `require_channel_encryption = true`; if `require_channel_encryption` is false or absent, the `enc` field is not present (§10.2) and there is no container for the envelope.
- **Responses (all `request_format` values):** The `ct` plaintext is the UTF-8 encoding of the JSON-serialized **full logical tool result object**, as defined in §10.2.

#### 10.2 Plaintext Field Handling (Normative)

When `require_channel_encryption` is true:

- **Requests:** The client MUST set `params.arguments` to the empty object `{}`. The actual arguments MUST be carried exclusively in the `_meta...enc.ct` ciphertext. If the RS receives both a non-empty `params.arguments` and an `enc` field, it MUST reject the request with denial code `MALFORMED_REQUEST` / `failed_check: REQUEST_FRAMING`.
- **Responses:** The RS MUST encrypt the **full logical tool result** as a single JSON object containing all result fields. The encrypted plaintext is a JSON object with the following fields (omit any that are absent/null):

```json
{
  "content": [ ... ],
  "structuredContent": { ... },
  "isError": false
}
```

The `CallToolResult` wire representation MUST use the following plaintext placeholders:
  - `content` MUST be set to the sentinel `[{"type": "text", "text": "encrypted"}]`
  - `structuredContent` MUST be omitted (not present in the plaintext `CallToolResult`)
  - `isError` MUST be preserved in the plaintext `CallToolResult` (it is not confidential — it indicates whether the client should treat the result as an error, and MCP orchestrators may need this for control flow without decrypting the payload)

The client MUST ignore `result.content` and `result.structuredContent` in the plaintext `CallToolResult` when `_meta...enc` is present, and use the decrypted content instead. The client MUST use `result.isError` from the plaintext wire as-is (it is authoritative whether or not encryption is active).

- **Streaming constraint:** Tools that require `require_channel_encryption: true` MUST NOT stream partial plaintext results. The RS MUST buffer the complete response and encrypt it as a single `ct` value.
- **Tool-schema validation ordering:** When `require_channel_encryption` is active, extension-aware servers MUST defer tool-argument schema validation (including `outputSchema` validation for `structuredContent`) until after decrypting `enc.ct`. The decrypted plaintext arguments are the authoritative input for schema validation, not the empty `params.arguments` placeholder.
- **Non-TBAC `_meta` fields:** Top-level `_meta` fields from other extensions (i.e., keys other than `"io.modelcontextprotocol/tbac"`) MAY remain in plaintext in the `CallToolResult`. They are not part of the encrypted logical tool result and are not covered by `enc.ct`. Extensions that carry semantically sensitive result metadata SHOULD define their own encryption mechanism or coordinate with the TBAC `enc` envelope. The TBAC extension does not encrypt or suppress other extensions' `_meta` fields. Extensions that place semantically sensitive data in top-level `_meta` SHOULD NOT assume TBAC response encryption protects it.

When `require_channel_encryption` is false or absent, the `enc` field MUST NOT be present. Plaintext `params.arguments`, `result.content`, `result.structuredContent`, and `result.isError` are used normally.

#### 10.3 Cascade Interaction

When `require_channel_encryption` is true, the RS MUST decrypt the request payload **after** completing token verification Steps 1–12 and **before** executing Step 13 (TBAC scope evaluation) and Step 14 (PoP verification). This ordering ensures:

- The RS does not decrypt untrusted payloads (all cryptographic and defense-in-depth checks pass first).
- Step 13 (`allowed_parameters` constraint evaluation) operates on plaintext arguments.
- Step 14 (PoP transcript) source depends on `request_format`:
  - **`request_format = 0x00` (direct):** PoP hashes `SHA-256(JCS(tool_arguments))` where `tool_arguments` is the **plaintext** arguments — when channel encryption is active, this is the **decrypted content recovered from `enc.ct`** (which is the JSON-serialized `params.arguments`), not the empty placeholder.
  - **`request_format = 0x01` (enveloped, outside base conformance):** PoP hashes `SHA-256(pop_args)` where `pop_args` is extracted from the decrypted `HaapRequestEnvelope` (§3.6). The PoP transcript binds to the **semantic tool arguments** (`pop_args`), NOT the entire envelope object. The RS MUST also verify semantic equivalence between `pop_args` and `body` via the registered canonical codec before execution. This branch applies only when the companion codec-registry specification has been negotiated between peers; otherwise the request MUST be rejected per §3.6.1.

> **Channel-encryption requirement for enveloped requests.** `request_format = 0x01` MUST only be used when `require_channel_encryption = true`. The `HaapRequestEnvelope` lives inside `enc.ct`; if channel encryption is not active, there is no container for the envelope. The TQS MUST NOT set `request_format = 0x01` unless the token's scope includes `require_channel_encryption = true` AND a companion codec-registry specification has been negotiated between peers (§3.6.1). Implementations that receive a token with `request_format = 0x01` but no `enc` field in the request MUST reject with `CHANNEL_ENCRYPTION_REQUIRED`. Implementations that receive a token with `request_format = 0x01` but do not support the companion codec-registry specification MUST reject with `NON_JSON_POP_NOT_SUPPORTED` (§3.6.1).

#### 10.4 Nonce Reuse Prevention

Because `IV_resp` is deterministic, the RS MUST NOT encrypt more than one distinct plaintext with the same `(K_resp, IV_resp)` pair. On transport-layer retransmission, the RS MUST retransmit the exact same ciphertext bytes — it MUST NOT re-encrypt the response. If the RS cannot guarantee this, it MUST use a random 96-bit IV (included in the `iv` field) rather than the deterministic `IV_resp`. For request encryption (K_req), implementations MUST generate a fresh random 96-bit IV per encryption attempt.

#### 10.5 Profile E Mapping

In Profile E deployments, the Assembler (not the Agent) constructs the `_meta` JSON and performs all `enc` field encryption/decryption. The Agent sends plaintext `ToolCallRequest` to the Assembler via IPC; the Assembler produces the MCP JSON-RPC wire format shown above. The RS receives identical JSON-RPC regardless of whether Profile E or Profile S produced it.

### 11. Assembler Architecture (r27)

> **This section is new in r27, aligned with HAAP canonical spec v6.0.0 §39.**

The Assembler is a per-agent, single-flight, bidirectional crypto-proxy process that sits between the Agent/LLM and the Resource Server. It takes over all token attachment, request encryption (K_req), and response decryption (K_resp) responsibilities from the Agent process. The Agent/LLM process is thereby reduced to **zero cryptographic material** — the most vulnerable component in the system holds nothing an attacker can use.

#### 11.1 Process Model

The Assembler is its own OS process, spawned by the SDK supervisor/scheduler at boot (eager spawn). It is NOT merged into TQS (which would change TQS's network profile to include egress HTTP) and NOT merged into the Supervisor/Scheduler (which would place crypto material in the control plane).

**Normative requirements:**

- The Assembler MUST be a separate OS process from the Agent/LLM runtime.
- Each agent MUST have its own Assembler instance(s). A shared Assembler serving multiple agents is PROHIBITED. Multiple Assemblers per agent (pool) are permitted (§11.1.1).
- The SDK supervisor MUST spawn the Assembler(s) at boot alongside Auth and TQS (eager spawn). The Agent/LLM MUST NOT request or influence Assembler process creation.
- Each Assembler MUST NOT hold `response_key` material for more than one token simultaneously (single-flight constraint).

**Trust hierarchy:**

| Component | Key material | Attack surface | Crypto trust |
|-----------|-------------|----------------|-------------|
| Authenticator | IK private key | Small binary, IPC-only | Highest |
| TQS | K_session, SEK, priv_sig | Small binary, IPC-only | High |
| Assembler | Per-token response_key (ephemeral) | Small Rust binary, IPC + egress HTTP | Medium |
| Supervisor/Scheduler | None | Process lifecycle, dispatch | None |
| Agent/LLM | **None** | LLM, plugins, prompt context | **None** |

#### 11.1.1 Assembler Pool (Concurrent Tool Invocations)

When agent workloads require concurrent tool invocations (e.g., parallel reads across multiple RS endpoints), the Supervisor MAY maintain a pool of N single-flight Assembler instances per agent. Each instance is an independent OS process with its own IPC channels, its own `response_key` lifecycle, and its own single-flight constraint. The pool provides N-way parallelism while each Assembler still holds at most one `response_key` at any instant.

**Pool sizing.** The pool size is controlled exclusively by the Supervisor based on one of three strategies:

- **Static pool:** N Assemblers spawned at boot based on agent class policy. Fixed for the session.
- **Hint-driven scaling:** The Supervisor receives a `PoolHint` from the Scheduler before each turn and scales the pool up or down. Assemblers are lightweight (~few MB, ~1–5 ms spawn time).
- **Warm pool with lazy activation:** N Assemblers pre-spawned idle (zero keys). Activated on demand by `ToolCallRequest` dispatch. Pool size is capacity; active count is utilization.

The Agent/LLM MUST NOT influence pool sizing or Assembler spawning. The Scheduler provides hints; the Supervisor makes the spawn decision.

```
PoolHint {
  turn_id:              u64,   // conversation turn identifier
  expected_concurrency: u8,    // 1–16 (capped by policy)
  hint_source:          enum { SchedulerClassification, LlmToolPlan, PolicyDefault },
}
```

The Supervisor treats `PoolHint` as advisory, not mandatory. If resources are insufficient, requests queue behind existing Assemblers — graceful degradation to serial execution, not failure.

**Maximum pool size.** Capped by `maxAssemblersPerAgent` (RECOMMENDED default: 8, configurable per agent class in Cedar policy). The Supervisor MUST NOT exceed this cap regardless of hint values.

**Dispatch.** The Supervisor (or a thin dispatcher layer) routes each `ToolCallRequest` to an idle Assembler in the pool. If all Assemblers are active, the request queues until one becomes idle. Round-robin or least-recently-used dispatch; the Agent does not choose which Assembler handles its request.

**Blast radius analysis:**

| Compromise scope | Single Assembler | Full pool (N) | v5.8.0 direct-attach |
|-----------------|------------------|---------------|---------------------|
| One Assembler compromised | 1 response_key | 1 response_key | N/A |
| All Assemblers compromised | N/A | N response_keys (max) | All in-flight keys |

Compromising one pool member yields exactly one `response_key` because each Assembler is a separate OS process with separate address space, seccomp profile, and sandbox. The pool is strictly better than v5.8.0 direct-attach (where the Agent held ALL in-flight keys in one process).

**Backward compatibility.** A pool of size 1 is equivalent to the single-Assembler model. Deployments that do not need concurrency operate identically to the base design.

#### 11.2 Single-Flight Constraint

Each Assembler processes exactly ONE request at a time. At any instant it holds either zero `response_key` values (idle) or one (during a single HTTP round-trip, typically 50–500ms). Concurrent request pipelining through a single Assembler is PROHIBITED.

**Maximum blast radius per Assembler:** A fully compromised Assembler at the worst possible instant yields exactly ONE `response_key`, for ONE token, scoped to ONE RS endpoint, valid for ONE operation. This is the smallest unit of crypto exposure the protocol can express.

#### 11.3 Destination Binding and End-to-End Audience Chain

The Assembler maintains an RS endpoint allowlist provisioned via `SetDestinationPolicy` from the Authenticator. Before transmitting any request, the Assembler:

1. Canonicalizes `target_rs_url` per RFC 3986 normalization.
2. Selects the matching allowlist entry using path-segment-safe prefix matching (literal string-prefix matching where `/mcp` would match `/mcp-admin` is PROHIBITED — entry prefix P matches `canon_url` if and only if `canon_url == P` OR `canon_url` starts with `P + "/"`).
3. Passes `selected_aud_hash` (from the selected entry) to TQS in `PrepareInvocation`.
4. Verifies the returned token header's `aud_hash` (bytes 48–79) against the **selected entry's** `aud_hash` (post-mint confirmation).
5. Verifies the TLS certificate chains to the expected RS identity for that entry.

On any failure, the Assembler rejects immediately — no token is transmitted. If a token has already been delivered by the TQS, the Assembler sends `VoidDeliveredToken` to the TQS (the voided token does not count toward approval budgets).

**End-to-end destination binding.** The audience-binding chain is: (1) Authenticator provisions `SetDestinationPolicy` with `RsAllowlistEntry` list to TQS and Assembler; (2) Assembler selects an entry at pre-mint time using the canonical destination-binding algorithm; (3) Assembler passes `selected_aud_hash` to TQS in `PrepareInvocation`; (4) TQS validates `selected_aud_hash` against its own cached `SetDestinationPolicy` entries — if no match, the TQS rejects with `InvocationRejected{reason: DestinationPolicyViolation}` (no token minted); (5) TQS mints token with `aud_hash = selected_aud_hash`; (6) Assembler confirms post-mint that the token header's `aud_hash` matches the selected entry's hash. The TQS MUST NOT override `selected_aud_hash` or compute `aud_hash` from a session-wide audience field. The `RsAllowlistEntry.aud_hash` is the single source of truth for audience binding.

**`InvocationRejected` (TQS → Assembler).** When the TQS rejects a `PrepareInvocation` before minting, it sends `InvocationRejected` with one of the following `reason` values, plus optional `retry_after_ms` (for transient reasons) and `granted_ceiling` (for scope rejections):

```
InvocationRejected {
  session_id:       u64,
  reason:           enum { DestinationPolicyViolation, TransactionRequired,
                           IntentCaptureRequired, TxnBudgetExhausted, PurposeRequired,
                           ScopeCeilingExceeded, IntentHashMismatch, AgentNotEnrolled,
                           SessionSuspended, SessionExpired, MintFailure },
  detail:           Option<String>,
  retry_after_ms:   Option<u32>,      // present for transient reasons (MintFailure)
  granted_ceiling:  Option<String>,   // present when reason = ScopeCeilingExceeded
  rejected_at:      u64,
}
```

**Agent-facing mapping.** The Assembler maps `InvocationRejected` to Agent-facing `RequestRejected`, preserving actionable reasons 1:1 so the Agent SDK can take corrective action without inspecting opaque detail strings:

| `InvocationRejected.reason` (TQS) | `RequestRejected.reason` (Agent) | Notes |
|----------------------------------|----------------------------------|-------|
| `DestinationPolicyViolation` | `DestinationMismatch` | Opaque (internal detail dashboard only) |
| `IntentHashMismatch` | `IntentHashMismatch` | 1:1; Agent SDK may refetch intent state or prompt for user re-confirmation |
| `TransactionRequired` | `TransactionRequired` | 1:1 (actionable) |
| `IntentCaptureRequired` | `IntentCaptureRequired` | 1:1 (actionable) |
| `TxnBudgetExhausted` | `TxnBudgetExhausted` | 1:1 (actionable) |
| `PurposeRequired` | `PurposeRequired` | 1:1 (actionable) |
| `ScopeCeilingExceeded` | `ScopeCeilingExceeded` | 1:1; `granted_ceiling` passed through |
| `MintFailure` | `MintFailure` | 1:1; `retry_after_ms` passed through |
| `AgentNotEnrolled` | `RSError` | Internal reason preserved for user console dashboard |
| `SessionSuspended` | `RSError` | Internal reason preserved for user console dashboard |
| `SessionExpired` | `RSError` | TQS also emits `SessionStateChange` (0x0060) to Authenticator for automatic re-authentication |

**IPC type codes (Assembler additions, r33/r37):**

| Type Code | Message | Direction | Section |
|-----------|---------|-----------|---------|
| `0x005A` | `PoolHint` | Scheduler → Supervisor | §11.1.1 |
| `0x005B` | `InvocationRejected` | TQS → Assembler | §11.3 |
| `0x005C` | `TokenStatus` | Assembler → TQS | §11.3 (Profile E pending-state poll) |
| `0x005D` | `PollResult` | TQS → Assembler | §11.3 (Profile E pending-state poll response) |
| `0x005E` | `ClarificationAnswer` | Assembler → TQS | §11.3 (Profile E; forwarded from Agent) |
| `0x005F` | `PendingResponse` | TQS → Assembler | §11.3 (Profile E initial pending return) |
| `0x0060` | `SessionStateChange` | TQS → Authenticator | §11.3 (reverse signal: SessionExpired auto-reauth trigger) |
| `0x0061` | `ClarificationAnswer` | Agent → Assembler | §11.3 (Profile E Agent-to-Assembler hop; Assembler re-forwards with 0x005E) |

#### 11.4 Security Properties by Profile

| Property | Profile E | Profile S |
|----------|-----------|-----------|
| Agent/LLM holds zero crypto material | Yes | No |
| Three-channel separation (RE-4) | Yes | No (two-channel) |
| Bounded crypto lifetime (RE-6) | Yes | No |
| Blast radius of agent compromise | Plaintext only | response_key + token |
| Blast radius per Assembler | 1 response_key | N/A |
| Concurrent tool invocations | Yes (Assembler Pool, N-way) | Yes (agent-managed) |
| PoP via TQS (agent cannot forge) | Yes | Yes |
| Intent hash pre-filter (Assembler) | N/A — TQS-authoritative at mint-gate (three-layer model, §4.7) | No (RS only) |
| Destination binding (RS allowlist) | Yes | No |
| End-to-end aud_hash binding | Yes (selected_aud_hash) | No |

### 12. HAAP Canonical Specification Alignment (Normative Note)

This SEP is architecturally and semantically aligned with the HAAP Canonical Specification v6.0.0 (2026-04-15). The protocol design, verification cascade, key schedule, trust model, Assembler architecture, scope-field semantics, three-layer intent verification, Profile E IPC inventory, and the `HaapRequestEnvelope` schema are aligned with HAAP Canonical Specification v6.0.0 Build 885a9acf16a78e4a, which is the current publicly reviewable canonical artifact as of r40. The non-JSON PoP branch (`request_format = 0x01`) is declared outside base v6.0.0 conformance in both the canonical specification and this SEP (§3.6.1); a companion codec-registry specification remains future work. The `resource` field semantic tightening landed in r40 (§3.2, §8.1) is a SEP-local change and does not affect HAAP canonical alignment; the canonical specification does not itself constrain the `resource` optional/required disposition for MCP-profile deployments.

However, this SEP defines an **MCP-specific wire mapping** that intentionally diverges from the HAAP canonical spec's generic HTTP wire format on two axes: **transport framing** and **domain-separation string naming**. These divergences are by design — they ensure TBAC tokens and metadata are visible to MCP message-processing layers across all MCP transports (Streamable HTTP, stdio, SSE) rather than being confined to HTTP headers.

Direct byte-level interoperability between a conformant SEP implementation and a current HAAP SDK implementation requires an explicit conformance mode in the HAAP SDK. The Hawcx AIAA SDK will provide such a mode in a future release.

#### 12.1 Transport Framing Divergence

| Artifact | HAAP v6.0.0 (HTTP wire) | This SEP (MCP wire) |
|----------|------------------------|---------------------|
| Token attachment | `Authorization: HAAP <token>` HTTP header | `_meta["io.modelcontextprotocol/tbac"].token` in JSON-RPC |
| PoP proof | `HAAP-PoP` HTTP header | `_meta["io.modelcontextprotocol/tbac"].pop.sig` in JSON-RPC |
| Encrypted request payload | HTTP request body (encrypted by Assembler) | `_meta["io.modelcontextprotocol/tbac"].enc.ct` in JSON-RPC (§10.1) |
| Encrypted response payload | HTTP response body (encrypted by RS) | `_meta["io.modelcontextprotocol/tbac"].enc.ct` in `CallToolResult` (§10.1) |
| `request_format` (byte 3) | Identical: `0x00` (direct) / `0x01` (enveloped) | Identical: `0x00` (direct) / `0x01` (enveloped) |
| `HaapRequestEnvelope` | Identical schema: `pop_args`, `content_type`, `body` (outside base conformance) | Identical schema (§3.6, outside base conformance, §3.6.1) |

> HAAP v6.0.0 defines a generic HTTP wire mapping using `Authorization: HAAP` and `HAAP-PoP` headers. This SEP defines the MCP-specific mapping of those artifacts into JSON-RPC `_meta` fields so they remain visible to MCP message-processing layers across transports. The token binary layout, overall verification cascade structure, and security model are aligned with HAAP v6.0.0. This SEP intentionally diverges in MCP transport mapping and domain-separation labels (§12.2), so byte-level interoperability with current HAAP implementations requires an explicit conformance mode in the HAAP SDK. The `request_format` field is shared between HAAP and this SEP. The `HaapRequestEnvelope` schema is also shared but is outside base v6.0.0 conformance on both sides; peers that implement the companion codec-registry specification may use it as an extension.

#### 12.2 Domain-Separation String Divergence

This SEP uses MCP-namespaced domain-separation labels for HKDF derivations, transcript prefixes, and AAD constants. The HAAP canonical spec uses Hawcx-branded labels for the corresponding roles. For HKDF derivations, both produce identical-length outputs from the same `K_session` and `jti` inputs — the only difference is the `info` parameter. For transcript prefixes and AAD constants, the label bytes differ but the construction structure is identical.

| Derivation | HAAP v6.0.0 string | This SEP string |
|-----------|-------------------|----------------|
| Per-token AEAD key (`K_tok_enc`) | `"hawcx-token-enc-v3"` | `"tbac-token-enc-v1"` |
| Per-token Schnorr scalar (`tqs_sk`) | `"hawcx-token-sign-v3"` | `"tbac-token-sign-v1"` |
| Request encryption key (`K_req`) | `"hawcx-req-enc-v3"` | `"tbac-req-enc-v1"` |
| Response encryption key (`K_resp`) | `"hawcx-resp-enc-v3"` | `"tbac-resp-enc-v1"` |
| Response IV (`IV_resp`) | `"hawcx-resp-iv-v3"` | `"tbac-resp-iv-v1"` |
| Privilege signature key (`K_priv[epoch]`) | `"hawcx-priv-sig-v1"` | `"io.modelcontextprotocol/tbac:priv-sig:v1"` |
| PoP transcript prefix | `"hawcx-pop-v1"` | `"tbac-pop-v1"` |
| Schnorr deterministic nonce | `"hawcx:schnorr:tok-nonce:v1"` | `"tbac-schnorr-nonce-v1"` |
| Request AAD prefix | (not applicable — HTTP body) | `"tbac-req-aad-v1"` |
| Response AAD prefix | (not applicable — HTTP body) | `"tbac-resp-aad-v1"` |

> **Migration note.** Deployments integrating the Hawcx AIAA SDK directly MUST configure the SDK to use the HAAP canonical spec's strings and MUST NOT mix tokens from both derivation namespaces in the same RS deployment. A future release of the AIAA SDK will add an MCP conformance mode that uses the SEP strings. All conformant SEP implementations MUST use the strings defined in this document.

## Rationale

### Why Not Just Use Rich Authorization Requests (RFC 9396)?

GitHub Issue #1670 proposes adding RAR to MCP. RAR can express richer scopes than flat OAuth scope strings, but it still produces session-scoped access tokens. The authorization decision is made once at token issuance and then reused. TBAC makes the authorization decision per invocation — each tool call gets its own token with its own scope.

RAR and TBAC are complementary: RAR can be used during the initial OAuth flow to establish the session-level authorization ceiling, while TBAC tokens enforce per-invocation authorization within that ceiling.

### Why Not Biscuit / Macaroon Tokens?

Biscuit tokens (Eclipse Foundation) provide offline attenuation through Ed25519 signatures and a Datalog policy language. Google DeepMind's "Intelligent AI Delegation" framework (February 2026) proposes Delegation Capability Tokens based on Biscuits. These are the closest competing approaches.

Key distinctions:
- **Task semantics are first-class in TBAC**, not manually encoded via Datalog caveats
- **TBAC tokens are opaque to the bearer** (AES-256-GCM encrypted), while Biscuit tokens are readable by any holder
- **TBAC separates the policy decision from token construction** — the policy engine (ABAC/RBAC/Zanzibar) authors the classifier; the TQS packages it; the RS enforces it. Biscuit conflates attenuation with policy decision
- **No major identity provider natively issues Biscuit tokens**, creating adoption friction

### Why Not Cedar / AWS AgentCore?

Cedar (open-source, deployable in any environment including disconnected ones) provides deterministic policy enforcement with formal verification. AgentCore's Policy feature is AWS-managed infrastructure that evaluates Cedar policies per tool call at a gateway. Cedar is tens of times faster than OPA/Rego (43–81× depending on workload, per [Cutler et al., OOPSLA 2024](https://doi.org/10.1145/3649835)).

Key distinctions:
- **Cedar evaluates at request time; TBAC seals decisions into tokens.** This is a fundamental architectural difference. TBAC tokens carry the authorization decision as a portable, cryptographically bound artifact that can be verified without contacting a policy evaluation service. Cedar requires a running policy evaluation service accessible at verification time.
- **TBAC produces a portable proof of authorization** that can traverse organizational boundaries. Cedar's authorization decision is ephemeral — an authorization granted at time T does not produce a portable credential that a downstream RS can independently verify.
- **AWS infrastructure dependency applies to AgentCore specifically, not Cedar itself.** Cedar is infrastructure-neutral and open-source. The relevant comparison for MCP is whether deployments want a policy engine that evaluates at request time (Cedar) or a token-based approach that pre-seals decisions (TBAC). Both are viable; TBAC's advantage is zero-latency hot-path verification and offline portability.

### Why Not SpiceDB / OpenFGA?

ReBAC naturally models delegation chains as graph relationships and scales to millions of queries per second. SpiceDB (via AuthZed) counts OpenAI among its customers for authorization infrastructure.

Key distinction:
- **ReBAC evaluates against a central graph at request time; TBAC pre-computes into portable tokens.** For fleet-scale deployments (1M+ concurrent agents), the central graph becomes a bottleneck. TBAC's pre-materialization via TQS eliminates this centralized dependency for the hot path

### Why a TQS Sidecar Instead of a Token Endpoint?

Traditional OAuth token endpoints are network services. At agent fleet scale, millions of agents requesting tokens creates infrastructure pressure. The TQS runs locally alongside the agent, pre-minting tokens via IPC. Benefits:
- **Zero network round-trips** for token acquisition (sub-millisecond local IPC)
- **No thundering herd** on token endpoint during fleet-wide recovery
- **Prompt injection isolation** — the LLM runtime never handles cryptographic keys; all crypto is in the TQS process boundary (or Assembler process in Profile E)

### Why an Assembler Process? (r27)

The v5.8.0 direct-attach model (Profile S) required the Agent runtime to hold `response_key` and perform K_req/K_resp derivation. This meant a compromised Agent could decrypt response payloads. The Assembler (Profile E) eliminates this by moving all cryptographic operations into a dedicated per-agent process with a single-flight constraint. Benefits:
- **Zero crypto material in Agent/LLM** — the most vulnerable component holds nothing useful to an attacker
- **Bounded blast radius** — at worst, one `response_key` for one token for one operation per Assembler
- **N-way parallelism without N-way exposure** — an Assembler Pool (§11.1.1) provides concurrent tool invocations via multiple single-flight Assemblers, each in its own OS process with separate address space. Compromising one pool member yields exactly one `response_key`, not all in-flight keys.
- **Destination binding** — RS allowlist with end-to-end `selected_aud_hash` chain prevents exfiltration to unregistered endpoints
- **TQS-authoritative intent verification** — TQS performs authoritative intent-hash comparison at mint-gate before any token is minted (three-layer model, §4.7)

### Design Principles

1. **The task is the unit of authorization.** Not the session, not the workload, not the relationship graph.
2. **Verify-then-decrypt.** Schnorr signature verification (Step 6) MUST precede AEAD decryption (Step 7) — designated-verifier signatures provide cryptographic proof of token provenance and binding (audience and session) before any decryption occurs.
3. **The agent is excluded from the security perimeter.** The agent cannot read, modify, or expand its own authorization. The privilege classifier is encrypted inside the token. In Profile E, the agent holds zero cryptographic material.
4. **Pre-materialization over on-demand issuance.** Authorization decisions are computed before the agent needs them, not in the critical path.
5. **No refresh tokens.** Refresh tokens are persistent bearer credentials vulnerable to prompt injection and exfiltration. Session renewal uses full mutual re-authentication.

## Backward Compatibility

This extension introduces **no backward incompatibilities**:

- **Purely additive**: TBAC is an optional authorization layer. Existing MCP clients and servers that do not implement TBAC continue to function unchanged.
- **Capability-negotiated**: TBAC support is discovered through MCP's standard capability negotiation during initialization. Clients and servers that do not advertise `io.modelcontextprotocol/tbac` are unaffected.
- **Transport-agnostic**: TBAC tokens are carried in `_meta` fields of standard JSON-RPC messages, not in transport-level headers.
- **Composable with existing auth**: TBAC layers on top of OAuth 2.1.
- **Opt-in per tool**: Servers can require TBAC for sensitive tools while allowing other tools to operate with session-scoped OAuth alone.
- **Extensions-compliant**: Follows MCP extension governance (SEP-1724 / SEP-2133). Disabled by default, requires explicit opt-in.
- **Consumer profile backward-compatible**: Consumer profile tokens (`msg_type = 0x08`) are a backward-compatible extension. Servers that do not advertise `supportsConsumerProfile: true` will reject `msg_type = 0x08` at Step 1 (framing check). Enterprise tokens (`msg_type = 0x03`) are unaffected.
- **Profile backward-compatible**: Profile E (Assembler) and Profile S (direct-attach) produce identical token wire formats. The RS does not need to know which profile the client uses — the verification cascade is the same. The profiles differ only in client-side process architecture.
- **r26 → r40 migration**: The breaking change is the `msg_type` value for consumer profile (`0x04` → `0x08`). Enterprise profile (`0x03`) is unchanged. Additional breaking change in r33: token header byte 3 changed from `reserved = 0x00` to `request_format ∈ {0x00, 0x01}`. r34 added `require_channel_encryption = true` as a mandatory third condition for `request_format = 0x01`. r35–r36 normalized the three-condition set across all specification locations including codec registration. r37 reconciled with CS Build 885a9acf16a78e4a: three-layer intent model (TQS mint-gate authoritative, Assembler Layer-2 defense-in-depth, RS Step 13.7 unchanged); expanded `InvocationRejected` enum (4 → 11 reasons) with `retry_after_ms` / `granted_ceiling` fields and actionable-reason mapping; new IPC codes `0x005C`–`0x0061`. Profile E `PrepareInvocation` now carries `claimed_intent_hash`. r38 aligned with the HAAP v6.0.0 conformance-scope language: non-JSON PoP (`request_format = 0x01`) is explicitly **outside base v6.0.0 conformance** and requires a companion codec-registry specification; implementations that previously advertised support for `0x01` without such a companion specification are no longer base-conformant for r38 and MUST either reject `0x01` or advertise extended conformance (§3.6.1). r39 closed the last internal inconsistency by updating §3.0.3 Step 3 (minting algorithm, AAD assembly) to defer the `request_format` value to a dedicated base-conformance normbox that restates the full four-gate rule. No wire format change between r38 and r39; r39 is a pure specification-text consistency fix. r40 is the `resource`-semantics breaking change driven by the 2026-04-20 external security audit: `resource` transitions from OPTIONAL (with "omit means tool-wide" implicit semantics) to REQUIRED (with explicit `"*"` for tool-wide). New §8.1 spells out the `resource` attenuation rule under glob subset semantics and carries a deprecation-window transition note — during the r40 window, implementations MAY accept r39-formatted tokens that omit `resource` by coercing the absent value to `"*"` with a deprecation warning, but the deprecation window closes at the revision after r40. The r40 breaking change eliminates a delegation-chain widening attack identified in the audit: a parent `resource: "public/*"` could previously issue a child token that omitted `resource`, which some code paths read as unrestricted tool-wide (privilege escalation) and other code paths read as inherit-from-parent (narrowing), with both behaviors arising from the same scope JSON depending on which code path evaluated the token. All r33+ changes are additive to the r27 wire format and do not break r27 token-level implementations at the RS. r40 is the first revision since r33 with a normative scope-field disposition change. All revisions r26–r40 are pre-review drafts (see Pre-review stability note).

## Reference Implementation

> **Submission readiness note.** This SEP is a **pre-review draft** pending two official-extension review prerequisites: (1) at least one reference implementation in an official MCP SDK, and (2) a public conformance artifact (test vectors under the `tbac-*` domain strings). The cryptographic design and protocol architecture are complete; the procedural requirements for formal `ext-auth` review (per SEP-2133) are in progress.

### Prototype Status

A reference implementation is available at:

- **Repository**: [github.com/ravi-hawcx/haiaap-protocol](https://github.com/ravi-hawcx/haiaap-protocol) (private — access available to reviewers on request)
- **Language**: Rust core with N-API bridge to TypeScript SDK
- **Test coverage**: 591 tests (574 Rust unit/integration + 17 TypeScript SDK tests) across all 6 implementation phases — all passing as of SDK v0.5.1 (2026-03-05) *(author-reported; reference implementation repository is currently private — see note below)*
- **CI**: GitHub Actions, all checks passing

### What the Prototype Demonstrates

1. **Token minting and verification**: TQS pre-mints TBAC tokens; RS verifies via 17-step cascade (enterprise) with sub-millisecond latency
2. **Multi-session support**: Single TQS manages concurrent sessions for different audiences (multi-org)
3. **Policy template enforcement**: RS-side ceiling per `agent_instance_id` validated at verification step 13
4. **Bidirectional per-token encryption**: Per-token `response_key` shared secret with three-channel design (Profile E) or two-channel design (Profile S)
5. **Delegation chains**: Monotonically decreasing `delegation_depth` with `parent_token_hash` verification
6. **Single-use consumption**: Atomic CAS prevents concurrent token use
7. **Assembler architecture (Profile E)**: Zero-crypto agent process with single-flight Assembler pool (N-way concurrent invocations)
8. **Intent verification**: RS Step 13.7 with `log_only` and `keyword_match` modes
9. **Transaction lifecycle**: `txn_id` binding with per-transaction token budgeting

### MCP SDK Integration (Planned)

A TypeScript package (`hawcx-mcp-auth`) providing:
- `TbacAuthProvider` implementing the MCP SDK `AuthProvider` interface
- `TbacTokenVerifier` middleware for MCP servers
- TQS client for local token acquisition
- Assembler IPC client for Profile E deployments
- Demo: MCP server + client exercising TBAC authorization on tool calls

Reviewers may request access to the reference implementation repository. Public availability is planned to coincide with the MCP SDK integration milestone.

## Security Implications

### Threat Model

TBAC assumes the agent (MCP client) is potentially compromised. The security perimeter includes the **Authenticator**, **Assembler** (Profile E), TQS, policy engine, and RS — but explicitly excludes the LLM runtime. This means:

- **Agent cannot modify its authorization**: The privilege classifier is encrypted inside the token (AES-256-GCM). The agent receives an opaque blob and passes it through (Profile S) or never sees it at all (Profile E).
- **Agent cannot expand its scope**: The TQS packages policy-authored classifiers; the agent has no mechanism to request elevated privileges directly.
- **Agent cannot replay tokens**: Single-use consumption with two-phase atomic reserve/commit prevents replay.
- **Agent cannot forge tokens**: Schnorr designated-verifier signatures over Ristretto255 provide integrity verification.
- **Agent cannot exfiltrate to arbitrary endpoints (Profile E)**: Assembler destination binding restricts token transmission to the RS allowlist.

#### Trusted Computing Base (TCB) Enumeration

**Inside the TCB (compromise breaks TBAC guarantees):**

| Component | Holds | Compromise impact |
|-----------|-------|-------------------|
| **Authenticator** | `K_session` (derives via X3DH), `mutual_auth` (generates) | Full session compromise — attacker can mint arbitrary tokens for the session. |
| **TQS sidecar** | `K_session` (received via IPC), per-token keys, `response_key`, privilege classifiers | Token forgery + confidential channel decryption for the session. |
| **Assembler (Profile E)** | Per-token `response_key` (ephemeral, single-flight per instance) | Decryption of ONE response for ONE token per compromised instance. Pool of N: at most N response_keys if all N instances compromised. Cannot forge tokens (no `K_session`). Cannot exfiltrate to unregistered endpoints (destination binding). |
| **Policy engine** | Privilege classifier authoring authority | Arbitrary privilege grant — bounded by RS-side policy template ceiling (Step 13). |
| **Resource Server (RS)** | `K_session` copy, `verifier_secret`, `mutual_auth`, consumed-token log | Full authorization bypass for the RS's resources. |
| **Authentication Service (AS)** | Long-term identity keys, session provisioning authority | Can provision fraudulent sessions to any RS. |
| **Host OS / hypervisor** | Process isolation enforcement | Breaks TQS↔agent isolation boundary. |

**Outside the TCB (compromise does NOT break TBAC guarantees):**

| Component | What attacker gains | What attacker cannot do |
|-----------|--------------------|-----------------------|
| **Agent / LLM runtime** | Profile S: opaque token blobs and `response_key` handles. Profile E: plaintext request/response data only. | Cannot read, modify, or expand authorization. Cannot decrypt token body. Cannot forge tokens. Profile E: cannot decrypt confidential channel payloads, cannot send to unregistered endpoints. |
| **Network transport** | Can observe encrypted token bytes in transit | Cannot decrypt `CT_body` (AEAD), cannot forge Schnorr signatures, cannot replay (single-use `jti`). |
| **MCP proxy / gateway** | Can observe `_meta` fields containing opaque tokens | Cannot decrypt token body, cannot decrypt `enc.ct` channel payloads, cannot modify tokens without breaking Schnorr verification. |

### Attack Mitigations

| Attack | Current MCP Risk | TBAC Mitigation |
|--------|-----------------|-----------------|
| Prompt injection → scope abuse | Session-scoped token grants full scope | Per-invocation token scoped to specific tool + resource + constraints |
| Token theft | Long-lived access tokens + refresh tokens | Single-use tokens with 60s TTL; no refresh tokens |
| Confused deputy | Tool receives authorization context for wrong user/task | `agent_instance_id` + `aud` + `tool` + `org_id` binding in token; RS validates all four |
| Delegation escalation | No standard mechanism | `delegation_depth` monotonically decreasing; `parent_token_hash` chain verification |
| Replay attack | Token valid for session duration | Two-phase `jti`-based replay cache (reserve + commit) with atomic single-use consumption |
| Parameter manipulation | Tool arguments not bound to authorization | `constraints.allowed_parameters` cryptographically sealed in token |
| Retry storms at fleet scale | Synchronized token expiry across agents | TQS pre-materialization with staggered minting; no centralized token endpoint |
| Exfiltration to unregistered RS | No standard mechanism | Profile E: Assembler destination binding with RS allowlist |
| Intent divergence | No standard mechanism | Intent verification at RS Step 13.7; Profile E adds TQS-authoritative mint-gate enforcement + Assembler post-mint defense-in-depth (three-layer model, §4.7) |
| Approve-benign-execute-sensitive | No standard mechanism | T3 `approval_digest` binds CIBA approval to exact scope tuple |

### Cryptographic Considerations

- **Algorithm profile**: Single cryptographic profile: Schnorr designated-verifier signatures and AEAD signcryption over Ristretto255 with AES-256-GCM. The signature is a designated-verifier construction: per-token signing material (`tqs_sk`, `TQS_PK`) is derived from `K_session` and the token-unique `jti` via HKDF (§3.0.1 Step 5b). Only the intended RS can re-derive `TQS_PK` and verify the Schnorr equation.
- **Post-quantum readiness**: The `alg_id` registry allows future algorithm suites (e.g., ML-KEM hybridization or PQXDH-based session establishment) to be added as new `alg_id` values without breaking existing `0x01` deployments.
- **Constant-time operations**: All cryptographic verification MUST use constant-time comparison to prevent timing side-channels.
- **Secure erasure**: Key material (session keys, `response_key`, per-token keys) MUST be zeroized after use.

**Key Ownership and Trust:**

| Key | Owner | Purpose | Rotation | Compromise Impact |
|-----|-------|---------|----------|-------------------|
| `K_session` | TQS + RS (shared) | Token AEAD encryption/decryption | Per X3DH session | Tokens from this session decryptable |
| `tqs_sk` / `TQS_PK` (per-token) | TQS (derives at mint) + RS (re-derives at verify) | Schnorr designated-verifier signature | Per token (not persisted) | Token forgery limited to one `K_session` window |
| `K_priv[epoch]` | TQS + RS (independently derived) | `priv_sig` HMAC — proves classifier integrity | Per session × per epoch | Classifier forgery for that session until epoch rotates |
| `response_key` | TQS (generates) + RS (discovers in token) + Assembler (ephemeral, Profile E) or Agent handle (Profile S) | Per-token symmetric key seed for bidirectional channel | Per token (single-use) | Single invocation's request/response data decryptable |
| `verifier_secret` | TQS + RS (shared) | Defense-in-depth token binding | Per X3DH session | Reduced to Schnorr-only verification |

### Privacy Considerations

- TBAC tokens are opaque to the agent and to any intermediary. The privilege classifier contents are only visible to the policy engine (at mint time) and the RS (at verification time).
- All authorization-relevant metadata — including `org_id`, `txn_id`, `user_raw_intent`, `intent_hash`, and any future identity or correlation fields — resides inside the AEAD-encrypted scope JSON. These fields MUST NOT appear in the cleartext token header.
- The per-token `response_key` shared secret establishes a bidirectional confidential channel. In Profile E, the Agent/LLM never sees `response_key` or derived keys.
- The `jti` is a random value with no embedded metadata that could leak information.

## Appendix A: TLV Type-Code Registry (Normative)

This appendix defines the normative TLV type codes and encoding rules for the TBAC Privilege Classifier scope JSON used in the native opaque token format. Implementations MUST serialize fields in ascending numeric type-code order to produce a deterministic canonical byte string for `priv_sig` computation.

### A.1 Encoding Rules

- **Tag**: 1 byte, unsigned. Values 0x00–0x7F are defined by this SEP. Values 0x80–0xFF are reserved for vendor extensions (`x-` prefix fields).
- **Length**: 1–2 bytes. If the value length fits in 7 bits (0–127 bytes), encode as a single byte. Otherwise encode as a 2-byte big-endian uint16 with the high bit of the first byte set (`0x8000 | length`). Maximum field value length is 32767 bytes (0x7FFF); values exceeding this MUST be rejected as malformed.
- **Value**: byte string of the specified length, encoding depends on field type (see below).

Field type encodings:
- `string`: UTF-8 encoded, no null terminator
- `integer` / `uint64`: 8-byte big-endian unsigned integer (`uint64_be`)
- `boolean`: 1 byte, `0x01` = true, `0x00` = false
- `bytes`: raw byte sequence
- `null`: zero-length value (length = 0x00)
- `object` (constraints, etc.): recursively TLV-encoded sub-fields in ascending type-code order

### A.2 Scope JSON Field Type-Code Table (updated r27)

| Type Code | Field | Type | Notes |
|-----------|-------|------|-------|
| `0x01` | `iss` | string | Policy author identifier |
| `0x02` | `sub` | string | Client identity (IK fingerprint) |
| `0x03` | `agent_instance_id` | string | Agent class identifier |
| `0x04` | `tool` | string | MCP tool name |
| `0x05` | `action` | string | Single action string; repeat tag for list values |
| `0x06` | `resource` | string | Resource URI or pattern; omit if tool-wide |
| `0x07` | `constraints` | object | Recursively TLV-encoded constraint sub-fields (see §A.3) |
| `0x08` | `delegation_depth` | uint64 | Remaining delegation hops |
| `0x09` | `parent_token_hash` | bytes | 32 raw bytes (SHA-256 digest of TLV-canonical parent scope JSON). Omit field entirely if not delegated. |
| `0x0A` | `require_pop` | boolean | Proof-of-possession required flag |
| `0x0B` | `aud` | string | Full audience identifier (resource server URI). REQUIRED. |
| `0x0C` | `org_id` | string | Organization trust boundary identifier. REQUIRED. |
| `0x0D` | `trust_level` | uint64 | Trust tier (0–3). REQUIRED. |
| `0x0E` | `human_confirmed_at` | uint64 | CIBA approval timestamp (Unix seconds). 0 for T0–T2. |
| `0x0F` | `approval_digest` | bytes | 32 raw bytes. SHA-256 of canonical approval tuple. Absent for T0–T2. |
| `0x10` | `purpose` | string | Human-readable purpose string. Omit when not required. |
| `0x11` | `txn_id` | bytes | 16 raw bytes. Transaction identifier. Omit when not in transaction mode. |
| `0x12` | `user_raw_intent` | string | UTF-8 intent text (max 4096 bytes). Omit when intent not active. |
| `0x13` | `intent_hash` | string | Lowercase hex SHA-256 of `user_raw_intent`. Omit when intent not active. |
| `0x14` | `user_policy_sig` | bytes | 64-byte Ed25519 user policy signature (consumer only). TokenBody-level. |
| `0x15` | `user_sign_pk` | bytes | 32-byte User Ed25519 public key (consumer only). TokenBody-level. |
| `0x16` | `signed_at` | uint64 | User signature timestamp (consumer only). TokenBody-level. |

> **Note (r27):** Type codes `0x0C`–`0x13` are new in r27. Codes `0x14`–`0x16` replace the prior r26 codes `0x0C`–`0x0E` for consumer-profile fields. Implementations upgrading from r26 MUST update their TLV parsers.

### A.3 Constraints Sub-Field Type-Code Table

| Type Code | Field | Type | Notes |
|-----------|-------|------|-------|
| `0x01` | `max_rows` | uint64 | Maximum records returnable |
| `0x02` | `max_calls` | uint64 | Mint-rate ceiling (policy template) or MUST be 1 (token) |
| `0x03` | `time_window_sec` | uint64 | Action time window in seconds |
| `0x04` | `require_channel_encryption` | boolean | Bidirectional channel encryption required (see §3.3) |
| `0x05` | `data_classification` | string | Maximum data sensitivity level |
| `0x06` | `allowed_parameters` | object | Encoded as a sequence of parameter entries in ascending UTF-8 byte-order (see §A.3.1) |

### A.4 Minimum Conformance Requirement

A conformant implementation MUST:
1. Serialize all defined fields present in the scope JSON using the type codes above, in strictly ascending type-code order.
2. Treat `null` and absent as equivalent for OPTIONAL fields — **both MUST be omitted from the TLV canonical byte string**, with one exception: fields that have a defined default value MUST be encoded using that default value rather than being omitted. Specifically:
   - `parent_token_hash`: OPTIONAL with no default. When `delegation_depth == 0` or field is absent, MUST be omitted.
   - `require_pop`: OPTIONAL with default `false`. When absent or null, implementations MUST treat it as `false` and MUST encode it as boolean `0x00` in the canonical TLV.
   - `human_confirmed_at`: REQUIRED. When `trust_level ∈ {0, 1, 2}`, MUST be encoded as uint64 value `0`.
3. For the `action` field when a list is provided, encode each action as a separate TLV entry with type code `0x05` in the order they appear in the list.

### A.5 Test Inputs and Derivation Reference

The following test inputs and derivation formulas provide fixed, canonical parameters for computing byte-exact expected outputs. A full public conformance artifact with hex-encoded expected outputs for all derivations under the `tbac-*` domain strings will be published alongside the reference implementation prior to formal extension review submission. Until that artifact is available, this section provides the derivation structure and fixed inputs needed to independently compute conformance values.

> **Point encoding.** All point values use **compressed Ristretto255 encoding** as required by the `alg_id = 0x01` wire format.

#### A.5.1 Test Inputs (Fixed)

```
K_session      = a1b2c3d4e5f60718293a4b5c6d7e8f90 0102030405060708090a0b0c0d0e0f10
session_id     = 0x00000000DEADBEEF
policy_epoch   = 1
jti (string)   = "AAECAwQFBgcICQoLDA0ODw"  (base64url of 0x000102...0f, no padding)
aud            = "https://rs.example.com/mcp"
iat            = 1741305600  (0x0000000067CA3700)
exp            = 1741305660  (0x0000000067CA373C)
token_iv       = 01020304 0000000000000001
SEK_PK         = (scalar=7)*G  [enrollment key for test]
                = 44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d  (Ristretto255)
verifier_secret = SHA-256("test-verifier-secret")
                = dd8ef00728e3b455c7b18e84f518c5195af752963391c5e62d89cc6007712675
mutual_auth    = SHA-256("test-mutual-auth")
                = b4e523ea791a6496c5aa1ca415009c433328212e5a34fa17aed195561fc82973
response_key   = SHA-256("test-response-key")
                = 336e4cd4882715b29efaf7759a2be263c3df232f3fa5f5ebdcd9b6f81efa8c76
```

Scope JSON:
```json
{
  "iss": "policy-engine-test",
  "sub": "IK:test-client-fingerprint",
  "aud": "https://rs.example.com/mcp",
  "agent_instance_id": "test-agent",
  "tool": "query_database",
  "action": "read",
  "resource": "billing-api/invoices/2025-Q3",
  "constraints": {
    "max_rows": 100, "time_window_sec": 30,
    "max_calls": 1, "require_channel_encryption": true
  },
  "delegation_depth": 0,
  "require_pop": false,
  "org_id": "org-a-prod",
  "trust_level": 2,
  "human_confirmed_at": 0
}
```

#### A.5.2 Key Schedule

```
K_tok_enc (Step 5a):
  HKDF-SHA-256(IKM=K_session, salt=0x00*32,
    info="tbac-token-enc-v1" ∥ UTF-8(jti), L=32)

K_tok_sign_scalar (Step 5b):
  HKDF-SHA-256(IKM=K_session, salt=0x00*32,
    info="tbac-token-sign-v1" ∥ UTF-8(jti), L=64)
  tqs_sk = ScalarReduce64(HKDF_output)
  TQS_PK = tqs_sk · G (Ristretto255)

K_priv[epoch=1]:
  HKDF-SHA-256(IKM=K_session, salt=uint64_be(1),
    info="io.modelcontextprotocol/tbac:priv-sig:v1" ∥ uint64_be(session_id), L=32)

priv_sig = HMAC-SHA-256(K_priv, scope_tlv)
```

> **Note:** This SEP uses different domain-separation strings than the HAAP canonical spec (see §12.2), so byte-exact HKDF outputs will differ from those in the canonical spec's test vectors. Both are correct for their respective string namespaces. Implementations MUST use the SEP strings for MCP deployments and the HAAP strings for HAAP-native deployments.

#### A.5.3 Channel Encryption Key Derivation

```
K_req = HKDF-SHA-256(IKM=response_key, salt=0x00*32,
  info="tbac-req-enc-v1" ∥ uint64_be(session_id), L=32)

K_resp = HKDF-SHA-256(IKM=response_key, salt=0x00*32,
  info="tbac-resp-enc-v1" ∥ uint64_be(session_id), L=32)

IV_resp = HKDF-SHA-256(IKM=response_key, salt=0x00*32,
  info="tbac-resp-iv-v1" ∥ uint64_be(session_id), L=12)
```

#### A.5.4 Verification

```
aud_hash = SHA-256(UTF-8("https://rs.example.com/mcp"))
  = e4b259de5352880ebf7d058d3ce2787a 7d7b68ec9fc71e94d8b2f8ae98298e3a

Schnorr verification: σ_tok · G == R_tok + h_tok · TQS_PK
```

> **Byte-exact computed values.** The test input parameters above are fixed and canonical; implementations can independently compute expected outputs using these inputs with the `tbac-*` domain strings defined in this SEP. A full public conformance artifact with hex-encoded expected values for all derivations — including `K_tok_enc`, `tqs_sk`, `TQS_PK`, `K_priv`, `priv_sig`, `K_req`, `K_resp`, `IV_resp`, `scope_tlv`, and at least one complete token fixture — will be published prior to formal extension review submission.

---

## References

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [MCP Authorization Extensions (ext-auth)](https://github.com/modelcontextprotocol/ext-auth)
- [SEP-2133: MCP Extensions](https://modelcontextprotocol.io/community/seps/2133-extensions) — Definitive specification for the MCP extension governance framework (`capabilities.extensions` mechanism)
- [SEP-1724: MCP Extension Governance (historical issue)](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1724) — Original community discussion that led to SEP-2133; retained as historical context for the governance evolution
- [MCP Auth WG Meeting Notes (August 13, 2025)](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1344)
- [MCP FGA Working Group Requirements](https://docs.google.com/document/d/1jwxDAeu3kQXBOuVRIlyVPOVBswj5SY1icBuwfq6rOrI/) — *(Access-restricted; may require MCP working group membership.)*
- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/) — Extended Triple Diffie-Hellman key agreement
- [Hawcx AIAA Protocol Specification v6.0.0](https://hawcx.com/) — *(Non-normative background / implementation reference.)* Reference implementation of session establishment using X3DH 4-DH Mode B with Assembler architecture (v6.0.0). Public specification URL to be updated on release.
- [NIST NCCoE: Accelerating Adoption of AI Agent Identity and Authorization](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd) (February 2026)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (December 2025)
- [CSA Agentic Trust Framework](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents) (February 2026)
- [Google DeepMind: Intelligent AI Delegation](https://arxiv.org/abs/2602.11865) (February 2026)
- [IETF RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [IETF RFC 9396: OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
- [Eclipse Biscuit Tokens](https://www.biscuitsec.org/)
- [CoSAI MCP Security Whitepaper: "Securing the AI Agent Revolution"](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/) (January 20, 2026)
- [IETF draft-liu-agent-operation-authorization](https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/) — Agent operation authorization framework
- [IETF draft-goswami-agentic-jwt-00](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/) — Agentic JWT extensions
- [EchoLeak (CVE-2025-32711)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711) — Microsoft 365 Copilot zero-click exfiltration (June 2025)
- [Langflow CVE-2025-34291](https://nvd.nist.gov/vuln/detail/CVE-2025-34291) — CORS/CSRF to refresh token theft
- [mcp-remote CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) — MCP OAuth proxy RCE
- Salesloft-Drift compromise (August 2025) — OAuth token theft across hundreds of organizations ([GTIG advisory](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift/))
- [Salesforce Engineering: Agentforce runs secure AI agents at 11 million calls per day](https://engineering.salesforce.com/how-agentforce-runs-secure-ai-agents-at-11-million-calls-per-day/)
- [Kong AI Gateway 3.13: MCP Tool ACLs](https://konghq.com/blog/product-releases/mcp-tool-acls-ai-gateway)
- [AWS AgentCore Policy — Cedar-based authorization](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)
- [Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization](https://doi.org/10.1145/3649835) (OOPSLA 2024)
- [AuthZed / SpiceDB: OpenAI customer story](https://authzed.com/customers/openai)

## Copyright

This standalone draft is released under the CC0-1.0-Universal license (public domain dedication) to maximize accessibility during the pre-submission review period. Upon formal submission as an official MCP extension, this document is intended to be contributed under the Apache License 2.0, consistent with SEP-2133's licensing requirements for official extensions. (Submission may require coordination with MCP maintainers to ensure the target extension repository's licensing matches SEP-2133.) Contributors to the official extension-repo version agree to the applicable contributor terms.

**Patent notice:** Hawcx Inc. has filed a patent application (U.S. Provisional Application, filed 2025; non-provisional filing in progress — application number to be updated upon publication) covering specific implementation techniques including the proprietary signcryption construction, TQS architecture optimizations, Assembler architecture, and bidirectional response encryption mechanisms. This notice is informational only and does not constitute a license grant; public application details will be added when available. The normative requirements of this SEP (token format, privilege classifier schema, verification cascade interface, capability negotiation, and `_meta` transport) are described at the interface level and do not require use of patented methods. The current `alg_id = 0x01` opaque profile defines a fixed algorithm suite; alternative cryptographic constructions would require a new profile and algorithm identifier in a future revision. The authors commit to not asserting patent claims against implementations that conform solely to this specification's normative requirements. For the full intellectual property position applicable to official extension submissions, see the contributor terms of the `ext-auth` repository. For patent-related inquiries, contact: legal@hawcx.com.
