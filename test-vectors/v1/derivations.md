# Conformance derivations — prose trace

Values in this trace are byte-identical to `expected.json`. If you are debugging an interop failure with another TBAC r40 implementation, work top-to-bottom and compare each derived value against your implementation.

## Inputs

All inputs come from `inputs.json` (verbatim §A.5.1). The key fields:

- `K_session` — 32-byte shared session key (hex). Established by X3DH in production; fixed here.
- `session_id` — `0x00000000deadbeef` (big-endian uint64 on the wire).
- `jti` — 22-byte base64url (no padding). §A.5.1 value: `AAECAwQFBgcICQoLDA0ODw`.
- `aud` — `https://rs.example.com/mcp`.
- Scope JSON — r40-compliant with explicit `resource: "billing-api/invoices/2025-Q3"`.

## Derivations

### `aud_hash`

```
aud_hash = SHA-256(UTF-8("https://rs.example.com/mcp"))
```

### `K_tok_enc` (§3.0.1 Step 5a)

```
K_tok_enc = HKDF-SHA-256(
  IKM  = K_session,
  salt = 0x00 * 32,
  info = "tbac-token-enc-v1" ∥ UTF-8(jti),
  L    = 32
)
```

### `tqs_sk` and `TQS_PK` (§3.0.1 Step 5b)

```
tqs_sk_bytes = HKDF-SHA-256(
  IKM  = K_session,
  salt = 0x00 * 32,
  info = "tbac-token-sign-v1" ∥ UTF-8(jti),
  L    = 64
)
tqs_sk = ScalarReduce64(tqs_sk_bytes)
TQS_PK = tqs_sk · G              (Ristretto255 basepoint, 32-byte compressed)
```

### `K_priv[epoch]` (§3.4)

```
K_priv[epoch] = HKDF-SHA-256(
  IKM  = K_session,
  salt = uint64_be(epoch),
  info = "io.modelcontextprotocol/tbac:priv-sig:v1" ∥ uint64_be(session_id),
  L    = 32
)
```

### `priv_sig`

```
scope_tlv = canonicalize(scope_json, §A.2)
priv_sig  = HMAC-SHA-256(K_priv, scope_tlv)
```

The generator script independently recomputes this value from `K_priv` and the canonical TLV and asserts equality against the mint path's output. If the assertion fires, the canonicalization order or the HKDF derivation diverges.

### Channel keys (§9.1)

```
K_req   = HKDF-SHA-256(response_key, 0x00*32, "tbac-req-enc-v1"  ∥ u64be(session_id), 32)
K_resp  = HKDF-SHA-256(response_key, 0x00*32, "tbac-resp-enc-v1" ∥ u64be(session_id), 32)
IV_resp = HKDF-SHA-256(response_key, 0x00*32, "tbac-resp-iv-v1"  ∥ u64be(session_id), 12)
```

These values are recorded in `expected.json` for completeness. In this reference implementation the channel is a hook interface with plaintext defaults (§scope-out). A production deployment uses `K_req` / `K_resp` to encrypt payloads inside `_meta[..].enc.ct`.

### Token wire layout (§3.0)

184-byte fixed prefix (bytes 0–183) + variable `CT_body` (from byte 184). AAD bound into AES-256-GCM is exactly bytes 0–103 (`AAD_token`). The Schnorr challenge hash covers `R_tok ∥ TQS_PK ∥ SEK_PK ∥ verifier_secret ∥ GCM_tag ∥ CT_body ∥ AAD_token` per §3.0.1 Step 6.

## r40 §8.1 attenuation vector

See [`r40-attenuation.json`](r40-attenuation.json). A child scope with `resource: "*"` presented under a parent with `resource: "public/*"` MUST be rejected at both the TQS mint-gate (denial path 1) and the RS cascade Step 13 (denial path 2). The reference implementation's `pnpm demo:widening` reproduces both rejections and is the ground-truth regression signal.
