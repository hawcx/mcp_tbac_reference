#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fail if any literal "haap-" appears in tracked content outside exempted paths.
# Exempted: this script itself, the copied SEP (which references HAAP by design),
# the relationship-to-haap documentation file, and the HAAP alignment migration note.
set -euo pipefail

if git grep -nI 'haap-' \
  -- ':!scripts/no-haap-prefix.sh' \
     ':!spec/*' \
     ':!docs/relationship-to-haap.md' \
     ':!R40_MIGRATION.md' \
     ':!packages/tbac-core-ts/src/crypto/hkdf.ts'; then
  echo "ERROR: forbidden 'haap-' prefix appears outside exempted paths."
  echo "This repo is clean-room and uses 'tbac-*' domain strings only."
  exit 1
fi
echo "OK: no 'haap-' prefix leaks."
