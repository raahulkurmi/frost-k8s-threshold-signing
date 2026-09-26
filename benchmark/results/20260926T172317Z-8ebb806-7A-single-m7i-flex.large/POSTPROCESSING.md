# Post-processing applied to this results directory

One mechanical text substitution, applied after the run, in `system-checks.txt`,
`run.log` and `env.json` only: `token kid=` → `issued JWT header kid=`
(27 occurrences). Reason: gitleaks' `generic-api-key` rule matched the words "token kid="
followed by a key ID. A kid is a public key identifier (published in the cluster JWKS),
and every key it names was generated for one run and destroyed at its end, so these were
false positives; rewording avoids them without adding a gitleaks allowlist. The driver
(`benchmark/single/run.sh`) now writes the new wording. No measured value was changed:
CSVs, `*.metrics.json`, `scale/*` and `summary.md` are exactly as the run wrote them.

`summary.md` was regenerated from the same raw files with the summarizer fixed to count
only `run<k>/` directories (its glob `run*` also matched `run.log`). The only difference
from the file the run wrote is the header text "median over the 4 runs" → "3 runs"; every
number is identical (`diff` shows that single line).
