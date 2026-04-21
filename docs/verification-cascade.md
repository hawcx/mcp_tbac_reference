# Verification cascade

The 17-step enterprise cascade from SEP §4.3. Each step is a pure transformation on the accumulating verification context; the cascade short-circuits on the first failure.

| Step | Check | Failure denial |
|---|---|---|
| 1 | Framing (`version`, `alg_id`, `msg_type`, `request_format`) | `MALFORMED_TOKEN` / `FRAMING_CHECK` (or `NON_JSON_POP_NOT_SUPPORTED` / `CONFORMANCE_SCOPE` for `request_format=0x01`) |
| 2 | Session key-table lookup | `SESSION_NOT_FOUND` / `SESSION_LOOKUP` |
| 3 | Temporal + `aud_hash` | `STALE_TIMESTAMP` / `TEMPORAL_VALIDATION` or `AUD_MISMATCH` / `AUDIENCE_VALIDATION` |
| 4 | Session validity window | `SESSION_EXPIRED` / `SESSION_VALIDITY` |
| 5 | Key derivation (`K_tok_enc`, `tqs_sk`, `TQS_PK`) | (internal) |
| **6** | **Schnorr verify** (Ristretto255) | `INVALID_SIGNATURE` / `SCHNORR_VERIFICATION` |
| **7** | **AES-GCM decrypt** (AFTER Schnorr verify) | `DECRYPTION_FAILED` / `AEAD_DECRYPTION` |
| 8 | `mutual_auth` constant-time compare | `MUTUAL_AUTH_MISMATCH` / `MUTUAL_AUTH_CHECK` |
| 9 | `verifier_secret` compare + scope canonicalization + r40 §3.2 validation | `VERIFIER_SECRET_MISMATCH` / `VERIFIER_SECRET_CHECK`, or `SCOPE_FIELD_MISSING` / `TBAC_SCOPE_EVALUATION` |
| 10 | Replay pre-check (non-destructive) | `TOKEN_REPLAYED` / `REPLAY_CONSUME` |
| 11 | `policy_epoch` vs RS current | `EPOCH_EXPIRED` / `POLICY_EPOCH_VALIDATION` |
| 12 | `priv_sig` HMAC | `PRIVILEGE_SIG_INVALID` / `PRIVILEGE_SIGNATURE` |
| **13** | **Scope eval + `org_id` + §8.1 attenuation** | `INSUFFICIENT_PRIVILEGE` or `ORG_ID_MISMATCH` / `TBAC_SCOPE_EVALUATION` |
| 13.7 | Intent verification (hook, default `log_only`) | (skipped in base conformance) |
| 14 | PoP (hook; default rejects if `require_pop=true`) | `POP_REQUIRED` / `POP_MISSING` |
| 15 | Replay commit (atomic SETNX) | `TOKEN_REPLAYED` / `REPLAY_CONSUME` |
| 16 | Consumer profile signature (hook, no-op) | — |
| 17 | Receipt signature (hook, no-op) | — |

## Verify-then-decrypt

Steps 6 → 7 ordering is load-bearing. If a future refactor reverses them, the meta-test at [`src/cascade/verify.order.test.ts`](../packages/tbac-core-ts/src/cascade/verify.order.test.ts) fails: a token with intact GCM tag but tampered `σ_tok` MUST be rejected with `INVALID_SIGNATURE`, not `DECRYPTION_FAILED`.

## §8.1 attenuation at Step 13

When the decrypted scope carries `parent_token_hash`, Step 13 also runs [`checkAttenuation(child, parent, 'rs')`](../packages/tbac-core-ts/src/scope/attenuation.ts) with the parent scope retrieved from the RS's consumed-token log (`ConsumedTokenLog.lookupParent`). Violations return `TBAC_SCOPE_EVALUATION` with an `internalTag` starting `r40.8.1.rs_cascade.*` — used for telemetry, never surfaced in the denial envelope.

## Two-phase replay

Step 10 is a non-destructive `GET`. Step 15 is the atomic `SETNX` that actually marks the token as consumed. Placing `SETNX` at Step 15 (after PoP, after intent) prevents token-burn DoS: an attacker without the right `pop_priv` cannot permanently consume a token they cannot use.

## Total latency

Per §4.3 the enterprise cascade targets <490 µs with HAAPI+intent `log_only`, <400 µs without. This reference implementation is not latency-optimized but runs well under that target for the §A.5.1 fixture in CI (≤5 ms including replay-store allocation).
