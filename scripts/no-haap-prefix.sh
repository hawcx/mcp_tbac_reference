#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Clean-room guard. Fails if the literal "haap-" appears in source files
# outside exempted paths. The exemptions cover documentation that explicitly
# discusses the HAAP relationship (by design, not by contamination), the
# guard script itself, and the single HKDF migration comment.
set -euo pipefail

HITS=$(git grep -nI 'haap-' -- \
  'packages/**/*.ts' \
  'test-vectors/**/*.ts' \
  'test-vectors/**/*.json' \
  ':!packages/tbac-core-ts/src/crypto/hkdf.ts' || true)

if [ -n "$HITS" ]; then
  echo "ERROR: forbidden 'haap-' prefix appears in clean-room source:"
  echo "$HITS"
  exit 1
fi
echo "OK: no 'haap-' prefix leaks in source."
