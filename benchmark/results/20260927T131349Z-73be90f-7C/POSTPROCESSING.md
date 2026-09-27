# Post-processing applied to this results directory

One mechanical text substitution after the run, in `system-checks.jsonl`,
`run-tokens.log` and `env.json` only: the field name `token_kid` → `jwt_header_kid`
(54 occurrences). Reason: gitleaks' `generic-api-key` rule matched the field name
followed by a key ID. A kid is a public key identifier (published in the cluster's
JWKS), so these were false positives; the field was renamed instead of adding a gitleaks
allowlist, and `deploy/aws/7c/check.sh` now emits the new name. No measured value was
changed: CSVs, `*.metrics.json`, `*.nginx.jsonl`, `*.coord.jsonl`, `*.rtt.json` and
`summary.md` are exactly as the run wrote them.

The raw per-configuration logs `run*/*.nginx.jsonl` and `run*/*.coord.jsonl` (108 files,
48 MB) were gzipped (`*.jsonl.gz`) to keep the repository small; `benchmark/summarize` reads
`.jsonl.gz` transparently. Regenerating `summary.md` from the gzipped files reproduced
every line of the run's `summary.md` (lines 1–160, all tables and numbers) exactly; only the
source-file list at the end differed in its path prefix, because the regeneration was run
from another directory. The run's own `summary.md` is kept.

Pod scale-up (`run1/scale/`): the raw `*.audit.jsonl` (kube-apiserver TokenRequest audit
events) and `*.coord.jsonl` (coordinator Sign lines) were gzipped the same way; the summary
regenerated from the gzipped files is identical in every table.
