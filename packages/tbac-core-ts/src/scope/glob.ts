// SPDX-License-Identifier: Apache-2.0
//
// r40 §8.1 glob-subset predicate. Implemented from scratch — do NOT substitute
// a third-party glob library. `minimatch`, `picomatch`, and similar engines
// implement different semantics (e.g., brace expansion, character classes,
// different `**` path-boundary rules). §8.1 defines the exact behaviour:
//
//   - `"*"`  (single-segment wildcard) ⊆ `"*"`; also ⊆ `"**"` at same depth.
//   - `"**"` (multi-segment wildcard)  ⊆ `"**"` only.
//   - Any literal pattern ⊆ any wildcard pattern that matches it.
//   - Two literals relate only when one is an exact path-segment-boundary
//     prefix of the other.
//   - `\*` in a pattern escapes a literal asterisk in the containing segment.
//
// Parse pipeline: split the pattern on `/` boundaries that are NOT preceded
// by an unescaped backslash. (The SEP does not define escape sequences for
// `/`, so this implementation treats `/` as the unconditional path separator
// per §3.3's definition of "the sole path separator".)

/** A single parsed path segment. */
export type Segment =
  | { readonly kind: 'literal'; readonly value: string }
  | { readonly kind: 'single' }
  | { readonly kind: 'double' };

/**
 * Parse a resource pattern into an ordered list of segments, honoring the
 * `\*` literal-asterisk escape rule from §3.2. An empty segment (from a
 * leading, trailing, or double slash) is preserved as a literal `""` to
 * keep path-segment boundary semantics unambiguous.
 */
export function parsePattern(pattern: string): Segment[] {
  if (typeof pattern !== 'string') {
    throw new TypeError('parsePattern: pattern must be a string');
  }
  const rawSegments = pattern.split('/');
  return rawSegments.map(classifySegment);
}

function classifySegment(raw: string): Segment {
  if (raw === '*') return { kind: 'single' };
  if (raw === '**') return { kind: 'double' };
  return { kind: 'literal', value: unescapeLiteral(raw) };
}

function unescapeLiteral(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '\\' && i + 1 < s.length && s[i + 1] === '*') {
      out += '*';
      i += 1;
      continue;
    }
    out += ch;
  }
  return out;
}

/**
 * §8.1 subset relation: `child ⊆ parent`.
 *
 * Returns `true` iff every path the child pattern matches is also matched by
 * the parent pattern. Defensive on bad input: non-string values → `false`
 * (no pattern is a subset of a non-pattern).
 */
export function isSubset(child: string, parent: string): boolean {
  if (typeof child !== 'string' || typeof parent !== 'string') return false;
  const c = parsePattern(child);
  const p = parsePattern(parent);
  return segmentsSubset(c, p);
}

function segmentsSubset(child: Segment[], parent: Segment[]): boolean {
  // Allocate match tables: m[i][j] = true iff parent[0..j) matches child[0..i).
  // Interpretation: we pretend each child segment list is a concrete instance
  // of itself and ask whether the parent pattern matches it, with the caveat
  // that a child `*` must only match things the parent would also match with
  // a `*`, and a child `**` must only appear where the parent has `**`.
  //
  // Equivalently, we walk both lists left-to-right:
  //   - parent literal  vs child literal  → byte-equal required.
  //   - parent `*`      vs child literal  → consume 1 child.
  //   - parent `*`      vs child `*`      → consume 1 child.
  //   - parent `*`      vs child `**`     → FALSE (child matches strictly more).
  //   - parent `**`     vs anything       → nondeterministic consume-zero-or-more.
  //   - parent literal  vs child `*`      → FALSE (child matches strictly more).
  //   - parent literal  vs child `**`     → FALSE.
  const n = child.length;
  const m = parent.length;
  // dp[i][j] = child[0..i) ⊆ parent[0..j)
  const dp: boolean[][] = Array.from({ length: n + 1 }, () =>
    Array.from<boolean>({ length: m + 1 }).fill(false),
  );
  dp[0]![0] = true;
  // parent `**` on the left can match an empty child prefix
  for (let j = 1; j <= m; j++) {
    if (parent[j - 1]!.kind === 'double') dp[0]![j] = dp[0]![j - 1]!;
  }
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      const cs = child[i - 1]!;
      const ps = parent[j - 1]!;
      if (ps.kind === 'double') {
        // parent `**` matches zero segments (use previous parent) OR one more child segment
        dp[i]![j] = dp[i]![j - 1]! || dp[i - 1]![j]!;
        continue;
      }
      if (cs.kind === 'double') {
        // child `**` is strictly wider than any non-`**` parent segment
        dp[i]![j] = false;
        continue;
      }
      if (ps.kind === 'single') {
        // parent `*` matches exactly one child segment that is NOT `**`
        // (`**` was handled above). Both `single` and `literal` ⊆ `*`.
        dp[i]![j] = dp[i - 1]![j - 1]!;
        continue;
      }
      // parent literal
      if (cs.kind === 'single') {
        // child `*` matches more than just the parent literal
        dp[i]![j] = false;
        continue;
      }
      // literal vs literal
      dp[i]![j] = cs.value === ps.value && dp[i - 1]![j - 1]!;
    }
  }
  return dp[n]![m]!;
}
