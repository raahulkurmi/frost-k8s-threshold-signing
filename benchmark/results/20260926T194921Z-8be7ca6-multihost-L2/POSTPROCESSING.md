# Post-processing applied to this results directory

`summary.md` was regenerated from the same raw files (same title, note and inputs, read
back from the file the run wrote) after two summarizer changes:
1. an **N49 check** section was added (same thresholds as Phase 7A; one run per
   configuration). `diff` against the run's own file shows only that added section plus
   change 2.
2. the pod scale-up rows show **"not captured"** in the coordinator latency, coordinator
   sign-failure and signer-503 columns. The run's file showed `– / –`, `0`, `0` there,
   which was wrong: those logs were never captured (NOTES N61). For T every TokenRequest
   passes through a coordinator, so an empty coordinator log next to audited TokenRequests
   means "not captured", and the summarizer now says so.
No measured value was changed. Time to Ready, TokenRequests per rep, token errors and token
latency (all from the kube-apiserver audit log) are unaffected.
Invalid events during this run: 0 (`invalid-events.jsonl` is empty).
