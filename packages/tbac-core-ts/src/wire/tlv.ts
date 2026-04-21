// SPDX-License-Identifier: Apache-2.0
//
// TLV encoding per Appendix A.1.
//   - Tag: 1 byte unsigned.
//   - Length: 1 byte when value ≤ 127, else 2 bytes big-endian uint16 with
//     the high bit of the first byte set (value ≤ 0x7FFF).
//   - Value: raw bytes.

export interface TlvField {
  readonly tag: number;
  readonly value: Uint8Array;
}

export function encodeTlv(fields: readonly TlvField[]): Uint8Array {
  let total = 0;
  for (const f of fields) total += 1 + lengthHeaderBytes(f.value.length) + f.value.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const f of fields) {
    if (f.tag < 0 || f.tag > 0xff) throw new Error(`tag ${f.tag} out of range`);
    if (f.value.length > 0x7fff) throw new Error(`value length ${f.value.length} exceeds 0x7FFF`);
    out[off++] = f.tag & 0xff;
    if (f.value.length <= 0x7f) {
      out[off++] = f.value.length;
    } else {
      out[off++] = 0x80 | ((f.value.length >> 8) & 0x7f);
      out[off++] = f.value.length & 0xff;
    }
    out.set(f.value, off);
    off += f.value.length;
  }
  return out;
}

export function decodeTlv(bytes: Uint8Array): TlvField[] {
  const out: TlvField[] = [];
  let off = 0;
  while (off < bytes.length) {
    if (off + 1 > bytes.length) throw new Error('TLV truncated (tag)');
    const tag = bytes[off++]!;
    if (off + 1 > bytes.length) throw new Error('TLV truncated (length byte 1)');
    const lenHi = bytes[off++]!;
    let len: number;
    if ((lenHi & 0x80) === 0) {
      len = lenHi;
    } else {
      if (off + 1 > bytes.length) throw new Error('TLV truncated (length byte 2)');
      const lenLo = bytes[off++]!;
      len = ((lenHi & 0x7f) << 8) | lenLo;
    }
    if (off + len > bytes.length) throw new Error('TLV truncated (value)');
    out.push({ tag, value: bytes.slice(off, off + len) });
    off += len;
  }
  return out;
}

/** True iff the TLV fields are in strictly non-decreasing tag order. */
export function isCanonical(fields: readonly TlvField[]): boolean {
  for (let i = 1; i < fields.length; i++) {
    if (fields[i]!.tag < fields[i - 1]!.tag) return false;
  }
  return true;
}

function lengthHeaderBytes(n: number): number {
  return n <= 0x7f ? 1 : 2;
}
