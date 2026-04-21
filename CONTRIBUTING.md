# Contributing

Thanks for considering a contribution to `hx-mcp-tbac`.

## Clean-room boundary

This implementation is **clean-room** relative to Hawcx's proprietary HAAP codebase. When contributing:

1. Work from [`spec/0000-tbac-task-based-access-control-r40.md`](spec/0000-tbac-task-based-access-control-r40.md) only.
2. Do **not** reference, port, or copy from any `haap-*` source, test vectors, or proprietary constants.
3. The CI check `guard:no-haap` scans clean-room source files only (under `packages/` and `test-vectors/`). Documentation that discusses HAAP alignment (`docs/haap-alignment-note.md`, `R40_MIGRATION.md`, and the HKDF domain-string migration comment in `packages/tbac-core-ts/src/crypto/hkdf.ts`) is expected to reference both string families; the SEP text itself references HAAP by design per §12.
4. All crypto primitives use maintained audited libraries (`@noble/curves`, `@noble/hashes`, `@noble/ciphers`). Do not hand-roll primitives.

## Development workflow

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm lint
pnpm guard:no-haap
```

- Every public function must have a test alongside it.
- Do not merge with failing CI or dropped coverage.
- For changes that touch the verification cascade, keep the verify-then-decrypt ordering test green — its purpose is to detect accidental reversal.

## Commit messages

Conventional prefixes: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`. Keep subject ≤ 72 chars; use the body for rationale and SEP section references.

## License and IP

By contributing, you agree to license your contribution under Apache 2.0 (matching this repository) and affirm that your contribution is your original work or you have the right to submit it.
