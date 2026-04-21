# Audit history

This directory archives the independent audit reports that informed the
implementation's iteration between initial scaffold and SEP submission
readiness. The reports are kept for provenance; they are **not** normative
and they may reference code paths, file names, or behaviors that no longer
exist (each audit round drove fixes that changed the repo).

Reports, in chronological order:

| File | Date | Round | What it found |
|---|---|---|---|
| `CLEAN_ROOM_AUDIT_REPORT_2026-04-21.md` | 2026-04-21 | Initial clean-room posture review | No direct code-copy; several runtime/security gaps flagged |
| `TBAC_AUDIT_REPORT_2026-04-21.md` | 2026-04-21 | First security + conformance pass | Step 13 under-enforcement, `allowed_parameters` canonicalization, T3/intent validation, branding |
| `TBAC_AUDIT_REPORT_2026-04-21_FINAL.md` | 2026-04-21 | Post-remediation re-pass | §8.1 literal-prefix conformance bug |
| `TBAC_AUDIT_RERUN_2026-04-21_HEAD_9cfdb29.md` | 2026-04-21 | Verification against HEAD `9cfdb29` | Docstring drift only |
| `TBAC_AUDIT_REPORT_2026-04-21_FINAL_CLEAN.md` | 2026-04-21 | Final signoff against `9cfdb29` | All findings resolved |

For the code-level fixes each report drove, see the commit messages on
`main`: `git log --oneline -- packages/ docs/ scripts/`.
