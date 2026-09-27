# Post-processing in reports/aws/7c

`bootstrap-checks.jsonl`: the field name `token_kid` was renamed to `jwt_header_kid` after
the fact (mechanical, every line; no value changed). gitleaks' `generic-api-key` rule
matched the field name followed by a key ID (a public identifier published in the JWKS),
which failed CI's gitleaks tree scan and T11 from commit a0173b4 onwards. `check.sh` now
emits the new name (NOTES N69).
