// SPDX-License-Identifier: Apache-2.0
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { isSubset, parsePattern } from './glob.js';

describe('§8.1 glob-subset predicate — canonical examples', () => {
  it('star ⊆ star', () => {
    expect(isSubset('*', '*')).toBe(true);
  });

  it('public/* ⊆ public/*', () => {
    expect(isSubset('public/*', 'public/*')).toBe(true);
  });

  it('public/docs ⊆ public/*', () => {
    expect(isSubset('public/docs', 'public/*')).toBe(true);
  });

  it('public/docs/api ⊆ public/**', () => {
    expect(isSubset('public/docs/api', 'public/**')).toBe(true);
  });

  it('public/docs/api NOT ⊆ public/* (two segments vs one)', () => {
    expect(isSubset('public/docs/api', 'public/*')).toBe(false);
  });

  it('public/docs NOT ⊆ public/do (not path-segment aligned)', () => {
    expect(isSubset('public/docs', 'public/do')).toBe(false);
  });

  it('widening_attack_star_under_public_star: * NOT ⊆ public/*', () => {
    // Canonical r40 §8.1 widening attack pattern. This is the test named in
    // the build prompt; its failure is the ground-truth regression signal.
    expect(isSubset('*', 'public/*')).toBe(false);
  });

  it('** NOT ⊆ *', () => {
    expect(isSubset('**', '*')).toBe(false);
  });

  it('literal escape: "\\*name" is treated as literal "*name"', () => {
    const segs = parsePattern('\\*name');
    expect(segs).toHaveLength(1);
    expect(segs[0]).toEqual({ kind: 'literal', value: '*name' });
    // A literal "*name" is a subset of "*" (single segment) but NOT
    // byte-equal to the wildcard marker pattern "*name" (which does not
    // exist as a wildcard — only bare "*" is).
    expect(isSubset('\\*name', '*')).toBe(true);
  });
});

describe('§8.1 glob-subset predicate — wildcard-vs-wildcard rules', () => {
  it('single wildcard ⊆ double wildcard at same depth', () => {
    expect(isSubset('*', '**')).toBe(true);
  });

  it('double wildcard ⊆ double wildcard only', () => {
    expect(isSubset('**', '**')).toBe(true);
  });

  it('double wildcard NOT ⊆ single wildcard', () => {
    expect(isSubset('**', '*')).toBe(false);
  });

  it('segment/* ⊆ segment/** ', () => {
    expect(isSubset('segment/*', 'segment/**')).toBe(true);
  });

  it('a/b/c ⊆ ** (zero or more segments)', () => {
    expect(isSubset('a/b/c', '**')).toBe(true);
  });

  it('a ⊆ ** (zero or more segments absorbs one)', () => {
    expect(isSubset('a', '**')).toBe(true);
  });

  it('empty pattern ⊆ ** (zero segments)', () => {
    expect(isSubset('', '**')).toBe(true);
  });
});

describe('§8.1 glob-subset predicate — literal-vs-literal rules', () => {
  it('literals equal → subset', () => {
    expect(isSubset('alpha', 'alpha')).toBe(true);
  });

  it('literal prefix at segment boundary → subset', () => {
    expect(isSubset('public/docs/api', 'public/docs')).toBe(false);
    // SEP §8.1: literal-vs-literal requires exact byte-equality across the
    // compared length. "public/docs/api" has three segments; "public/docs"
    // has two. Different segment count ⇒ not a subset.
  });

  it('literal byte-prefix that is NOT a path-segment prefix → NOT subset', () => {
    expect(isSubset('public/docs', 'public/do')).toBe(false);
  });

  it('distinct literals of the same length → NOT subset', () => {
    expect(isSubset('alpha', 'beta')).toBe(false);
  });
});

describe('§8.1 glob-subset predicate — defensive inputs', () => {
  it('non-string inputs → false', () => {
    // Test at runtime since the public interface accepts strings.
    expect(isSubset(42 as unknown as string, '*')).toBe(false);
    expect(isSubset('*', null as unknown as string)).toBe(false);
  });
});

describe('§8.1 glob-subset predicate — property tests', () => {
  it('reflexive: every pattern is a subset of itself (restricted to literal-or-*)', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.oneof(
            fc.constant('*'),
            fc.stringMatching(/^[a-z]{1,6}$/),
          ),
          { minLength: 1, maxLength: 5 },
        ),
        (segments) => {
          const pattern = segments.join('/');
          return isSubset(pattern, pattern);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('antisymmetric on pure-literal patterns: a ⊆ b and b ⊆ a ⇒ a == b', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z]{1,4}(\/[a-z]{1,4}){0,3}$/),
        fc.stringMatching(/^[a-z]{1,4}(\/[a-z]{1,4}){0,3}$/),
        (a, b) => {
          if (isSubset(a, b) && isSubset(b, a)) return a === b;
          return true;
        },
      ),
      { numRuns: 500 },
    );
  });

  it('literal ⊆ ** always holds for any literal of any depth', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z]{1,4}(\/[a-z]{1,4}){0,5}$/),
        (lit) => isSubset(lit, '**'),
      ),
      { numRuns: 300 },
    );
  });
});
