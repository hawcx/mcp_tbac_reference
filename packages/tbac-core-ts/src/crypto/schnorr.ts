// SPDX-License-Identifier: Apache-2.0
//
// Ristretto255 Schnorr signing and verification for `alg_id = 0x01`.
// RistrettoPoint is a top-level export from `@noble/curves/ed25519`.

import { RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2';

/** Ristretto255 prime-subgroup order ℓ. Equal to the Curve25519 prime subgroup order. */
export const GROUP_ORDER: bigint =
  2n ** 252n + 27742317777372353535851937790883648493n;

/** ScalarReduce64: interpret b as little-endian 64-byte integer, reduce mod ℓ. */
export function scalarReduce64(b: Uint8Array): bigint {
  if (b.length !== 64) throw new Error('scalarReduce64: input must be exactly 64 bytes');
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(b[i]!);
  }
  return n % GROUP_ORDER;
}

/** HashToScalar(m) = ScalarReduce64(SHA-512(m)). */
export function hashToScalar(m: Uint8Array): bigint {
  return scalarReduce64(sha512(m));
}

/** Encode a scalar as a 32-byte little-endian byte array. */
export function scalarToBytes(s: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let n = s;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/** Decode a little-endian 32-byte scalar. */
export function scalarFromBytes(b: Uint8Array): bigint {
  if (b.length !== 32) throw new Error('scalarFromBytes: input must be 32 bytes');
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

/** Base-point scalar multiplication; returns 32-byte compressed Ristretto255 point. */
export function scalarMulBase(s: bigint): Uint8Array {
  const normalized = ((s % GROUP_ORDER) + GROUP_ORDER) % GROUP_ORDER;
  if (normalized === 0n) {
    // Zero scalar ⇒ identity point. Return Ristretto identity encoding.
    return RistrettoPoint.ZERO.toBytes();
  }
  return RistrettoPoint.BASE.multiply(normalized).toBytes();
}

/**
 * Signs `message` per §3.0.1 Step 6. Inputs are delivered pre-concatenated.
 */
export function schnorrSign(
  tqsSk: bigint,
  rTok: bigint,
  message: Uint8Array,
): { R: Uint8Array; sigma: Uint8Array } {
  const r = ((rTok % GROUP_ORDER) + GROUP_ORDER) % GROUP_ORDER;
  const R = r === 0n ? RistrettoPoint.ZERO.toBytes() : RistrettoPoint.BASE.multiply(r).toBytes();
  const h = hashToScalar(message);
  const sigma = (r + h * tqsSk) % GROUP_ORDER;
  return { R, sigma: scalarToBytes(sigma) };
}

/** Verifies `σ·G == R + h·TQS_PK` per §3.0.1 Step 6 verification clause. */
export function schnorrVerify(
  R: Uint8Array,
  sigma: Uint8Array,
  tqsPk: Uint8Array,
  message: Uint8Array,
): boolean {
  try {
    const Rpt = RistrettoPoint.fromBytes(R);
    const PK = RistrettoPoint.fromBytes(tqsPk);
    const s = scalarFromBytes(sigma) % GROUP_ORDER;
    const lhs = s === 0n ? RistrettoPoint.ZERO : RistrettoPoint.BASE.multiply(s);
    const h = hashToScalar(message);
    const rhs = h === 0n ? Rpt : Rpt.add(PK.multiply(h));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
