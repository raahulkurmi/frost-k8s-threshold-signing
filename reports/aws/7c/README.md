# reports/aws/7c/ (retired path)

Until the Phase 12 audit, three AWS sessions wrote their evidence to the same files in this
directory, and each session overwrote the previous one (audit finding G-2). The evidence
now lives in one directory per session, restored from git history:

| Session | Dates (UTC) | Directory | Restored from |
|---|---|---|---|
| Phase 7C (tokens, scale-up, lever, stress; NOTES N67–N74) | 2026-09-27 | `reports/aws/7c-session1/` | manifests a0173b4; bootstrap checks 0ee7228 (after the N69 rename); POSTPROCESSING.md, nginx-capture-verify.txt moved |
| N76/N77 evaluation (NOTES N78) | 2026-10-03 09:22–15:37 | `reports/aws/n76-session/` | 18ac3ac |
| v2 evaluation (NOTES N81) | 2026-10-03 17:19–21:44 | `reports/aws/v2-session/` | a000c9b (the files that were here at the freeze, 37f3c5e) |

Each directory also holds that session's security-group log (`sg-rules.txt`), recovered from
the operator-side log (audit G-4). Older NOTES entries that cite `reports/aws/7c/<file>` refer
to the session of that entry (N68–N70: 7c-session1; N78: n76-session; N81: v2-session); see
NOTES N84. New sessions write to `reports/aws/7c-sessions/<UTC>/` (`deploy/aws/provision-7c.sh`
EVIDENCE_DIR), and the scripts refuse to overwrite committed evidence.
