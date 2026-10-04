# Pass G: claims audit (docs vs reality) — findings

Auditor: fresh session, did not write the code. Repo copy: `clone-G`, detached at freeze
`37f3c5e2de5e847817482bc0a5354e653338a8b2`. No tracked file was modified (`git status --short`
empty after all runs). No cloud resource touched. `gh` used read-only (run view/list,
public kubernetes/kubernetes issues/PRs/contents). Raw evidence under `out/raw/G-*.txt`.

Summary counts: critical 0, high 6, medium 13, low 16, info 9 (44 findings).

What held up (verified, not findings): every cited results directory regenerates its
committed `summary.md` byte-for-byte with the repo's own summarizer (7C, lever, 7C-stress,
N76 slots/noregress/stress/storm, v2 stress-storm, v2 noregress with HEAD summarizer; 7A
with summarizer@c76eee9; 7B with summarizer@45ff8fb and HEAD; L1 post-fix with
summarizer@713776d) apart from the source-path list (`out/raw/G-regen-results.txt`);
v2 rules R1–R5 and the §7 QUORUM_ABORT rule are byte-identical between 293a919 and the
freeze, 293a919 is an ancestor of d07a8e7/a000c9b/eccc5a8 and predates the v2 cluster
(17:19Z) and data (17:47Z) (`G-v2-prereg.txt`, `G-v2-doc-diff.txt`); PRIORITY_ADMISSION.md
§5 is byte-identical at b672ab7 (pre-data), 4c8823a (data) and the freeze
(`G-prio-v1-prereg.txt`); the N70 stress rule (07bf7d8, 15:32Z) predates the stress run
(19:17Z); N76 and N82 test edits change only constructor/config lines, no assertion
(`G-n76-test-diff.txt`, `G-n82-test-diff.txt`); all six cited CI runs exist and are
`success` on the stated SHAs (`G-ci-runs.txt`); all legacy file:line quotes in
CLAIMS_AUDIT/REVIEW_RESPONSE match (`G-legacy-lines.txt`); every local commit hash cited in
the markdown exists; upstream issue/PR states match as of 2026-10-04 (`G-upstream.txt`).

---

### G-1: make-repro step logs cited as evidence were never committed (28 citations)
- Severity: high
- Location: reports/REPRO.md:21-27; reports/aws/REPRO-attempt1-FAIL.md:21-27; reports/aws/REPRO-attempt2-FAIL.md:22-28; reports/aws/REPRO-ec2-m7i-flex.large-ap-south-1.md:22-28; NOTES.md:769 (N56 cites REPRO-attempt1-FAIL.md as its evidence)
- Evidence:
  ```
  $ git log --all --oneline -- 'reports/repro-logs/*'      -> (empty: never committed)
  $ grep -n repro-logs .gitignore                           -> reports/repro-logs/
  $ grep -rn "99 signer\|want 100" reports/                 -> (no match)
  $ sed -n 28,33p reports/aws/REPRO-attempt1-FAIL.md        -> "Overall: **FAIL**" / empty e2e summary
  $ gh api repos/.../actions/runs/36157069748/artifacts     -> repro 21116 bytes, expires 2026-12-24
  ```
- Why it matters: every step result (PASS/FAIL, durations) in four REPRO reports points at a log that is gitignored. N56's failure text ("all: 99 signer requests, want 100"), which justified changing a test assertion, appears nowhere in the repository. The only surviving copy of the GitHub-runner logs is a CI artifact that expires on 2026-12-24; the EC2 logs exist nowhere.
- Suggested fix: commit the `reports/repro-logs/` contents for each kept REPRO report (gitleaks-scanned, under `reports/aws/repro-logs-<attempt>/`), or download the CI artifact now and commit it; otherwise mark each Log column "not retained".

### G-2: 7C and N76 evidence files were overwritten by later sessions; citations now point at v2-session data
- Severity: high
- Location: reports/INDEPENDENCE.md:163-182; NOTES.md:1065-1071 (N68), NOTES.md:1393 (N78); reports/PAPER_INPUTS.md:45
- Evidence (`out/raw/G-7c-manifest-overwrite.txt`):
  ```
  a0173b4 t5:    commit=02ae373 kid=EV_rkpqm binary=0dd3fa23    <- what INDEPENDENCE §7C / N68 describe
  a0173b4 tsame: commit=02ae373 kid=wvQG_NBR binary=1f744909
  18ac3ac t5/tsame: commit=f745ae2 kid=9gu_VGBe / Eu4bZ_v5 binary=f07f701f   <- what N78 describes
  a000c9b t5/tsame: commit=d07a8e7 kid=g1TN11q0 / XQC677lh binary=eb324efc   <- what is in the tree at 37f3c5e
  $ jq -r '[.system,.jwt_header_kid[0:8]]|@tsv' reports/aws/7c/bootstrap-checks.jsonl  -> 5XNTs7NT, NaAGGKX4, g1TN11q0, XQC677lh (v2 session)
  ```
- Why it matters: INDEPENDENCE.md says its Phase 7C section is "written by hand from the files listed", but those files now describe a different cluster (v2, 2026-10-03). A reader checking the cited files finds contradicting kids, commits and binary hashes. The 7C and N76 provenance survives only in git history.
- Suggested fix: keep per-session copies (`reports/aws/7c/`, `reports/aws/n76/`, `reports/aws/v2/`) restored from a0173b4/0ee7228 and 18ac3ac, and update every citation to the session-specific path.

### G-3: NOTES N68 names a non-existent directory as "the real run"
- Severity: high
- Location: NOTES.md:1072-1073
- Evidence:
  ```
  NOTES.md:1073 "...the real run is `benchmark/results/20260927T123218Z-7faa09c-7C`."
  $ git cat-file -e 37f3c5e:benchmark/results/20260927T123218Z-7faa09c-7C  -> fatal (missing)
  NOTES.md:1079 (N69): "An earlier attempt (`…20260927T123218Z-7faa09c-7C-ABORTED-switch-alarm`, not committed and not used)"
  ```
- Why it matters: the pointer names the aborted, uncommitted attempt. The run actually used is `20260927T131349Z-73be90f-7C`. This is the "33 cited logs never committed" pattern again.
- Suggested fix: correct N68 to point at `20260927T131349Z-73be90f-7C` and say the 123218Z run was aborted (N69).

### G-4: The security-group rule log for 7C, N76 and v2 is not committed; INDEPENDENCE cites a gitignored file
- Severity: high
- Location: reports/INDEPENDENCE.md:166 (and its bullet "Network (security groups)" :183-188); NOTES.md:774 (N57)
- Evidence:
  ```
  INDEPENDENCE.md:166 "the security-group log `deploy/aws/state/sg-rules.txt` (operator-side, gitignored; rules quoted below)"
  $ git log --all --oneline -- 'deploy/aws/state/*'   -> (empty)
  $ wc -l reports/aws/sg-rules.txt                    -> 11 (all 2026-09-26, 7A/7B)
  $ grep -c 2026-09-27 reports/aws/sg-rules.txt       -> 0 ; grep -c 2026-10-03 -> 0
  ```
- Why it matters: the network-isolation claims for T-5-region/T-same-region (port 8441 only from coordinator /32, coordinator ports only from control plane) have no committed evidence. "Rules quoted below" is prose, not a quotation of rules. L1–L5 were not re-run in 7C (INDEPENDENCE.md:189-193), so these SG rules are the only isolation evidence for 7C.
- Suggested fix: commit the operator-side SG log for each session (as was done for 7B in 3f345b7), or downgrade the 7C network bullet to "not evidenced in the repository".

### G-5: README calls the signers "independent", which no tested deployment provides
- Severity: high (wording that misstates a security property)
- Location: README.md:5-7
- Evidence: README.md:6-7 "...combined from signature shares that at least 3 of 5 **independent signers** produce". reports/INDEPENDENCE.md:3-6 "still **not** independence of operators, providers, credentials or software"; README.md:55-59 itself says independence is required and absent.
- Why it matters: the opening sentence asserts the one property the evidence explicitly denies (Level 1: one physical host; Level 2/7C: one account, operator, build, dealer).
- Suggested fix: "...from signature shares that at least 3 of 5 signers produce; each signer holds one share and applies its own policy. Signer independence is a deployment property; see Trust assumptions."

### G-6: The N60 "rule for operator network drops" did not exist before the event it was applied to
- Severity: high (post-hoc rule presented as pre-existing; affects an isolation test verdict)
- Location: NOTES.md:820-823 (N60 "Per the rule for operator network drops, L2 was re-run once"); reports/INDEPENDENCE.md:134; reports/REVIEW_RESPONSE.md:28
- Evidence (`out/raw/G-n60-timing.txt`):
  ```
  event: 2026-09-26 ~19:33Z; last commit before it: b2f63ca 2026-09-26T19:08:35Z
  $ git grep -n -i 'network drop\|operator drop\|re-run once' b2f63ca -- .   -> (none)
  first appearance: ebabdb1 2026-09-26T19:42:09Z ("L2 invalid: operator network drop", adds --recheck-l2)
  L2 recheck dir: l2-recheck-20260926T194211Z-ebabdb1 (2 s after that commit); N60 text: 0d1aaaf 19:49:41Z
  docs/instructions/CLAUDE_CODE_ADDENDUM_make-it-solid.md: no re-run rule
  ```
- Why it matters: the rule and the code to run only L2 again were written after the FAIL, and the re-run used that new code. The failing log is kept and disclosed (good), but "per the rule" implies a pre-registered procedure. Also, during a network drop the "blocked path" checks pass vacuously, so the e2e run gave no L2 evidence at all. The re-run is the only L2 evidence.
- Suggested fix: reword N60 to "a re-run rule was adopted after the event (ebabdb1, 19:42Z); the L2 FAIL stands as recorded and the PASS comes from a single re-run with the refactored check". If the rule was agreed verbally before the event, record who agreed it and when.

### G-7: "0 % errors in every configuration" for 7C is contradicted by the summary; N69 also names the wrong system
- Severity: medium
- Location: reports/CLAIMS_AUDIT.md:25 ("0 % errors in every configuration"); reports/REVIEW_RESPONSE.md:22 (R6 "0 % errors"); reports/PAPER_INPUTS.md:44 ("0 % errors in all 72 configurations"); NOTES.md:1082-1083
- Evidence: `benchmark/results/20260927T131349Z-73be90f-7C/summary.md:131` `T-5region-strict-c50 | run3 | 1000 | 3 | 0.3` and `:153` `T-sameregion-strict-c50 | run1 | 1000 | 1 | 0.1`; the "Errors:" list confirms both are `threshold not met`; N49-3 FAIL at :76/:78 depends on these failed p95 values (2622.4 / 2653.5). NOTES.md:1083 says "Strict T-same-region at c=50 had 3 deadline timeouts in 3000", but the summary has T-5-region with 3 and T-same-region with 1.
- Why it matters: this is a headline result fed into the paper, and it contradicts the summary's own per-run table and the N49 verdict it sits next to.
- Suggested fix: "median-of-runs error rate 0.0 % in every configuration; 4 failed requests in 72,000 (T-5-region strict c=50: 3, T-same-region strict c=50: 1, all deadline)". Fix N69 to match.

### G-8: Throttling % and RSA wall-time numbers are transposed in N78, N81, PAPER_INPUTS and PRIORITY_ADMISSION
- Severity: medium
- Location: NOTES.md:1449-1451 (N78), NOTES.md:1559-1561 (N81); reports/PAPER_INPUTS.md:49; docs/PRIORITY_ADMISSION.md §7 ("Throttling (≈ 92 % of wall time)")
- Evidence: in the "Open question" tables, `20261003T125216Z-18ac3ac-N76-stress/summary.md:120-143` gives RSA ms (median) 91.7–95.1 and throttled % 85.1–128.4. `20261003T174726Z-a000c9b-v2-stress-storm/summary.md:101-124` gives RSA ms 92.1–93.8 (excluding v2nb storm, 36.8) and throttled % 76.7–129.2. The docs say "throttled ≈ 92 % of wall time; RSA wall time 85–128 [129] ms per share". The "85–128/129" is the throttled-% column and "≈ 92" is the RSA-ms column.
- Why it matters: this is a quantitative explanation given to the paper as fact. "% of wall time" values above 100 % also mean the throttled metric is not a fraction of wall time, so the stated "≈ 92 % of wall time" reading is not supported by the metric.
- Suggested fix: "RSA wall time ≈ 92–95 ms per share (median) for ≈ 17 ms of CPU; cgroup throttled_usec / wall time 77–129 % (the metric can exceed 100 %; definition to be checked)".

### G-9: README status and evidence text is stale (single host, preliminary, Phase 7A pending)
- Severity: medium
- Location: README.md:11-14; README.md:55-59; README.md:101; README.md:105-109
- Evidence: README.md:12-13 "security results rest on a single physical machine (the multi-host evidence is multi-VM on one host), benchmark numbers are preliminary". :101 "Benchmarks (**preliminary**) | `benchmark/multihost/run.sh`". :105-109 "All benchmark results so far are labelled **preliminary: arm64...** ... (Phase 7A, pending)". Against these: 7A exists (`20260926T172317Z-8ebb806-7A-...`), 7B Level 2 exists (`20260926T194921Z-8be7ca6-multihost-L2`, `reports/multihost/e2e-20260926T191044Z-b2f63ca/`), and 7C is labelled final (NOTES N74).
- Why it matters: the front page contradicts every report it links to and hides the final numbers and the Level 2 deployment.
- Suggested fix: rewrite the status box and the Tests-and-evidence rows to name 7A (single host, CPU-contended), 7B (Level 2, T only, one run), 7C (final), with their labels, and Level 1/Level 2 independence wording from INDEPENDENCE.md.

### G-10: README says coordinators "verify every share"; the default (optimistic) does not
- Severity: medium
- Location: README.md:42-45 (vs README.md:123 and :137-144, NOTES N65)
- Evidence: README.md:43-44 "They fan the signing input out to the signers, verify every share (Shoup proof), combine ≥ 3 valid shares..."; cmd/grpc-proxy/main.go:22 `VERIFY_STRATEGY optional, optimistic (default, N65)`; N65 says the honest steady state is "0 share verifications per token".
- Why it matters: this is a security-mechanism description that is false for the default configuration. Unforgeability still rests on the final `rsa.VerifyPKCS1v15` (coordinator.go:462), but attribution and per-share checking happen only after a failed combine.
- Suggested fix: "combine shares and verify the final RS256 signature against the group key before returning it; shares are verified individually only after a failed combine, for suspects, or in strict mode (N65)".

### G-11: THREAT_MODEL has stale status statements (Level 2 "not done", N76 "evaluation pending", Level 1 rates)
- Severity: medium
- Location: docs/THREAT_MODEL.md:46-47 ("(Phase 7B)" as future); :166 ("Level 2 (separate regions/providers) | – | **not done**"); :271-272 ("The only observed rates are the preliminary Level 1 benchmarks (≤ 22 successful req/s)"); :276 ("**N76 additions (implemented; evaluation pending).**"); :7 ("Phase 9's compromise tests (C*)", while §7 says no adversarial test code exists)
- Evidence: Level 2 done (INDEPENDENCE.md:1-12, REVIEW_RESPONSE R12). N76 evaluated (NOTES N78, N81; README.md:126). 7C plateau ≈ 70 tokens/s (`20260927T131349Z-73be90f-7C/summary.md:40-45`). THREAT_MODEL.md:170-171 "no adversarial test code was written".
- Why it matters: this is the threat model's deployment table and the flooding analysis; both understate what was done and use the wrong capacity figure.
- Suggested fix: add the Level 2 row with its label, replace the C7 rate sentence with the 7C plateau, and change "evaluation pending" to "evaluated, not recommended (N78, N81)".

### G-12: THREAT_MODEL still describes a single shared `coordinator` client identity, which N76 removed
- Severity: medium
- Location: docs/THREAT_MODEL.md:16 (asset table "mTLS keys: `coordinator`, ..."); :35 ("The coordinator presents SAN `coordinator`"); :240 ("The mTLS `lb`/`coordinator` keys")
- Evidence: internal/tlsconf/tlsconf.go:23 `CoordinatorName(k) = "coordinator-%d"`, :47 rejects anything that is not exactly one `DNS:coordinator-<1..64>`; scripts/gen-certs.sh:8,90; NOTES N76 "the shared `coordinator` is refused"; README.md:127.
- Why it matters: the hop-by-hop authentication table is the core of §1 and no longer matches the code. The per-replica identity is what bounds a compromised replica.
- Suggested fix: update §0/§1/§C4 to `coordinator-<k>` (one per replica, each replica mounts only its own key).

### G-13: CLAIMS_AUDIT row 11 still states the withdrawn N72 slot attribution; row 14 says Level 2 "not done"
- Severity: medium
- Location: reports/CLAIMS_AUDIT.md:25 ("lever check ... attributes the plateau to the signers' admission slots × per-share service time, not CPU saturation (N72)"); reports/CLAIMS_AUDIT.md:33 ("Level 2: not done")
- Evidence: NOTES.md:1404-1406 (N78) "The ≈ 70/s plateau **is** signer CPU ... N72's slot attribution is withdrawn"; `20261003T101319Z-18ac3ac-N76-slots/summary.md:54-58` "slot inference NOT SUPPORTED"; my own recomputation from raw `cpu-signer*.txt.gz` gives 196.5 % measured-window CPU (out/raw, work/cpuwin.py). PAPER_INPUTS.md:44/:49 were updated, but CLAIMS_AUDIT was not. Level 2: REVIEW_RESPONSE.md:28, INDEPENDENCE.md.
- Why it matters: the claims audit is the document the paper relies on, and it contradicts the corrected record. N72 itself (NOTES.md:1159-1182) also carries no in-place pointer to its withdrawal.
- Suggested fix: replace the N72 clause with the N78 result. Update row 14 to Level 2 (7B) with its label. Add "(withdrawn in N78)" to the N72 heading.

### G-14: Legacy "bimodal 35/69 ms" and "70 ms = slow-mode run" explanation is overstated by its own cited files
- Severity: medium
- Location: reports/CLAIMS_AUDIT.md:25; reports/REVIEW_RESPONSE.md:22 (R6); reports/PAPER_INPUTS.md:42
- Evidence (`G-legacy-lines.txt`): `benchmark_20260608_224047.txt:42-44` is section "[7] Signer Failure Tolerance — Killing signer-4 and signer-5... Token with 3/5 signers: 70ms". It is a failure-scenario measurement, not a normal slow-mode run. `baseline_benchmark_20260619_201519.txt`: cold start 41/61/60/57/69 ms; warm path 30–48 ms (P95 48). The 57–61 ms values are not on either mode. In `frost_benchmark_20260619_200532.txt` the single 69 ms warm value is warm run 1, and the cold start includes 84 and 3141 ms. The quoted lines themselves (":37 Avg: 36ms … P95: 69ms", ":44 70ms") are accurate.
- Why it matters: the paper is told to explain the reviewer's inconsistency with a mechanism ("bimodal ... in the in-tree baseline too") that the cited data support only weakly. The 70 ms figure comes from a different experimental condition.
- Suggested fix: "36 ms is the warm-path average of 20 runs (one 69 ms outlier); 70 ms is a single token measured with 2 of 5 signers killed. They measure different conditions; both are superseded."

### G-15: Upstream KEP-740 framing omits "community fixes proposed, none merged" and a closed community PR
- Severity: medium
- Location: reports/CLAIMS_AUDIT.md:23-24; reports/PAPER_INPUTS.md:54; reports/REVIEW_RESPONSE.md:33 (R17)
- Evidence (`G-upstream.txt`): #141669 open, labels `kind/documentation,sig/auth,needs-triage`, 4 comments. #141670 open, needs-triage, 1 comment. PR #141687 open, merged=false, author `anupamojha-eng` (a community contributor, linked from the #141669 thread). PR **#141673** "docs: specify ECDSA signature encoding" (author `alinaqvi1129`) is **closed, merged=false** (2026-09-15) and is not mentioned anywhere in the repo (`git grep 141673` returns nothing). R17's point column keeps the addendum paraphrase "fixes by maintainers". The status column's wording is "any fix is the maintainers' decision".
- Why it matters: the required framing is "found and reported upstream; documentation gaps; awaiting triage; community fixes proposed, none merged". The docs never say that community fixes were proposed, list only one of the two PRs, and the R17 paraphrase could be read as "fixed by maintainers". Nothing claims the issues were fixed or that KEP-740 has defects (good: CA rows 9-10 classify them as a documentation gap/implementer error).
- Suggested fix: add to CA 9/10, PAPER_INPUTS:54 and R17: "Both issues: open, needs-triage (documentation gaps). Community PRs: #141673 (closed unmerged), #141687 (open, needs-ok-to-test). None merged." Drop "fixes by maintainers" from the R17 paraphrase or put it in quotes as the addendum's words.

### G-16: deploy/multihost/README.md says Level 2 is "Not done" and calls netem delay "emulated RTT"
- Severity: medium
- Location: deploy/multihost/README.md:10, :28, :60-73
- Evidence: :10 "Level 2 | ... | **Not done.** Scripts are ready. The transport ... would be swapped for `ssh/scp`"; :60 "## Level 2: what you would do (not done)"; :28 "with 0/20/60/150 ms emulated RTT on the far hosts". Against these: N58 (ssh transport implemented), 7B Level 2, N45 ("The configured netem delay is a **knob, not a measurement**").
- Why it matters: this is stale, and it breaks the netem wording rule (configured delay presented as RTT).
- Suggested fix: "0/20/60/150 ms configured netem delay (a knob; rows are labelled by measured RTT, N45)" and a Level 2 row pointing to 7B and INDEPENDENCE.md.

### G-17: N73 claims a prediction was "written down before the first stress configuration finished"; git shows it only after the data
- Severity: medium
- Location: NOTES.md:1201-1204
- Evidence (`G-n70-rule-timing.txt`): the stress run starts 2026-09-27T19:17:42Z (dir name / run-stress.log). Data commit a436567 is at 19:40:31Z. The "13.4" prediction and N72 first appear in 88473b0 at 19:53:26Z. No committed file before the data contains it.
- Why it matters: the claim presents the prediction as pre-registered, but the repository cannot show that. Contrast the N70 decision rule, which is committed before the run (07bf7d8, 15:32Z).
- Suggested fix: "prediction ≈ 13.4/s (recorded in the session before the run finished; not committed until 88473b0, after the data)", or drop the timing claim.

### G-18: 7C signer binaries differ between T systems although both manifests record the same commit
- Severity: medium
- Location: NOTES.md:1065-1067 (N68); reports/INDEPENDENCE.md:180-182
- Evidence: `git show a0173b4:reports/aws/7c/deploy-manifest-{t5,tsame}.json` shows `git_commit` 02ae373 for both (deployed 10:18:46Z and 10:37:05Z), with binary sha256 0dd3fa23… vs 1f744909…. N68 explains the difference as "built ... at different commits". The CI list shows no commit between 02ae373 (10:07Z) and 4fd66c0 (10:54Z).
- Why it matters: with the same HEAD, a differing binary means the build tree or flags differed (likely a dirty tree). The stated explanation contradicts the manifests, so the provenance of the code that ran in 7C is not pinned.
- Suggested fix: record `vcs.modified` / `go version -m` output for each deployed binary in the manifest. Correct N68 to "same recorded commit; cause of the difference not determined (possibly uncommitted changes)".

### G-19: Several quoted numbers exist only in raw files, not in any script-generated summary.md (violates README.md:106-107)
- Severity: medium
- Location: reports/PAPER_INPUTS.md:46 ("coordinator host 80–89 % CPU in strict vs ~20 % optimistic"); NOTES.md:854, 886; reports/PAPER_INPUTS.md:44 ("≥ 1096/1100 tokens"); NOTES.md:1171-1173; PAPER_INPUTS.md:46 RTT list
- Evidence: the 7B `summary.md` has no coordinator-CPU column. The raw `metrics.json` give strict 86.3–88.9 % (all5), 79.7–80.5 % (far c=50) and 67.1–69.9 % (far c=10) (`G-7B-coordcpu.txt`). The hedge counts 1097/1096/1097 of 1100 come from raw `coord.jsonl.gz` (my count). The RTT list comes from INDEPENDENCE.md (gen-independence, script-generated, OK).
- Why it matters: the repo's own rule says "Every number quoted anywhere must have a row in a script-generated summary.md". The values are reproducible from raw data, but "80–89 %" omits the 67–70 % far-quorum c=10 cases it summarises.
- Suggested fix: add coordinator-CPU and hedge-fired columns to the summarizer, or cite the raw files and the exact range.

### G-20: N78 "offered load rises 4–6×" for variant b is contradicted
- Severity: low
- Location: NOTES.md:1419-1420
- Evidence: `20261003T125216Z-18ac3ac-N76-stress/summary.md` b vs n48 offered/s: c=100 209.8/54.2 = 3.9×, c=150 327.4/110.4 = 3.0×, c=200 340.2/141.5 = 2.4×. docs/PRIORITY_ADMISSION_V2.md §7 and N79 say "2–3×".
- Suggested fix: "2.4–3.9×".

### G-21: N78 "126 (ab) and 277 (abs) refusals per 1000 at c=10" mixes a median with a worst run
- Severity: low
- Location: NOTES.md:1430
- Evidence: per-run errors at c=10: ab 126 / 28 / 166 (median 126); abs 0 / 277 / 36 (median 36). The summary shows abs errors 3.6 %.
- Suggested fix: "median 126 (ab) and 36 (abs, worst run 277)".

### G-22: N56 loosened a test assertion after an EC2 failure; NOTES describes it as per-token but the code checks totals
- Severity: low
- Location: NOTES.md:758-769; internal/coordinator/fanout_test.go (c46daba)
- Evidence: `git show c46daba`: `if total != 4*reqs` became `if total < 3*reqs || total > 4*reqs`, and `if all != 5*reqs` became `if all < 3*reqs || all > 5*reqs`. A `res.Contacted != 5` check was added for `all` (hedged already had `!= 4`). NOTES says "server-side total within [3, contacted] **per token**", but the code bounds only the aggregate. The property "5 requests per token" is now asserted only through the coordinator's self-reported `Result.Contacted`.
- Why it matters: the change is disclosed and reasonable, but it is a mid-run weakening, and the failure output that motivated it is not in the repo (G-1).
- Suggested fix: fix the NOTES wording. Optionally count contacted requests at the transport (client side) as an independent check.

### G-23: PRIORITY_ADMISSION_V2.md §7/§8 still say the QUORUM_ABORT code change is pending
- Severity: low
- Location: docs/PRIORITY_ADMISSION_V2.md §7 "Interim. The code default (on) is unchanged until this rule is applied"; §8 "The code change awaits a go-ahead; it was not made in the evaluation session"
- Evidence: 37f3c5e (N82) changed the default (cmd/grpc-proxy/main.go:33 `QUORUM_ABORT optional, off (default)`). The doc header was updated in the same commit, but §7/§8 were not.
- Suggested fix: append "(applied in N82, 37f3c5e)" to both.

### G-24: THREAT_MODEL C1 cites a wrong code line
- Severity: low
- Location: docs/THREAT_MODEL.md:197
- Evidence: cites `internal/coordinator/coordinator.go:485` for the `MaxResponseBytes+1` read. The read is at coordinator.go:644 (`io.LimitReader(resp.Body, wire.MaxResponseBytes+1)`); :485 is the collect loop.
- Suggested fix: cite :644-651.

### G-25: CLAIMS_AUDIT row 9 says the proto is "unchanged on master" while also citing a later commit that changed the file
- Severity: low
- Location: reports/CLAIMS_AUDIT.md:23; reports/PAPER_INPUTS.md:52
- Evidence: `diff` of api.proto v1.36.5 vs master shows only lines 38–42 reformatted (gofmt, 693b7b3). The `claims` wording is unchanged, but its line numbers on master are 48–51, not 50–53.
- Suggested fix: "the `claims` comment is unchanged on master (file reformatted elsewhere by 693b7b3; lines shift by −2)".

### G-26: REPRO.md says make repro "will also run" on the 7A VM; it did
- Severity: low
- Location: reports/REPRO.md:61
- Evidence: reports/aws/REPRO-ec2-m7i-flex.large-ap-south-1.md (PASS, attempt 3, f9c4c58).
- Suggested fix: point to that file.

### G-27: THREAT_MODEL §3 clock-skew figures have no committed raw evidence
- Severity: low
- Location: docs/THREAT_MODEL.md:91-93 ("clocks up to 39,124 s (about 10.9 h) behind"); NOTES.md:529-536
- Evidence: `git grep -l 39124` matches only NOTES.md (the other hits are coincidental numeric CSV values). No signer audit log from those windows is committed.
- Suggested fix: commit the relevant audit-log excerpt, or mark it as "observed; log not retained".

### G-28: Some e2e numbers live only in GitHub Actions logs (expire)
- Severity: low
- Location: reports/PAPER_INPUTS.md:35 (E6/E7 341 ms/E8 0/15, "CI e2e log (run 36151825518)"), :15 (CI run 36154065231)
- Evidence: verified with `gh run view --log` (`G-ci-runs.txt`: "PASS E7 issuance recovered 341ms"). Not in any committed file (reports/gates has no copy for these runs).
- Suggested fix: commit the e2e log excerpt as was done for 36275189321 (`reports/gates/overload-fix-ci-e2e-run36275189321-bfab4d9.log`).

### G-29: KEY_CEREMONY rotation section points at "open issues in NOTES.md" that do not exist
- Severity: low
- Location: docs/KEY_CEREMONY.md:73-75
- Evidence: `grep -n -i rotation NOTES.md` finds only unrelated "rotate"/"rotated" uses (fan-out rotation, log rotation).
- Suggested fix: add a NOTES entry for multi-key FetchKeys/rotation, or remove the pointer.

### G-30: HISTORY_PURGE gives the wrong commit for the accidental `.summarize` binary
- Severity: low
- Location: reports/HISTORY_PURGE.md:39
- Evidence: `git log --all --format=%h -- benchmark/results/20260925T094221Z-4385a48-multihost-L1/.summarize` returns 6ebb013 (removed) and 9bb1f16 (added), not "dc9b396 (removed in the next commit)". The purge command path itself is correct.
- Suggested fix: "9bb1f16 (removed in 6ebb013)".

### G-31: N59 ratio "1.5–1.7× later than B0" does not match the summary
- Severity: low
- Location: NOTES.md:800-801
- Evidence: 7A `summary.md:148-153`: 26.3/15.7 = 1.68 (50 pods), 57.2/39.6 = 1.44 (100 pods).
- Suggested fix: "1.4–1.7×".

### G-32: 7C summary label records commit 1e77bee while NOTES and the directory say 73be90f
- Severity: low
- Location: benchmark/results/20260927T131349Z-73be90f-7C/summary.md:3 ("commit 1e77bee"); NOTES.md:1077 ("commit 73be90f")
- Evidence: env.json:3 `git_commit 1e77bee…`; run-scale.log:122 shows the summary was regenerated in the scale phase at 1e77bee (after the N71 fix). Token runs ran at 73be90f.
- Suggested fix: have the summarizer note both commits (tokens 73be90f, scale 1e77bee).

### G-33: Run-time summaries for 7B and v2-noregress were replaced, not kept
- Severity: low
- Location: benchmark/results/20260926T194921Z-8be7ca6-multihost-L2/POSTPROCESSING.md; benchmark/results/20261003T200008Z-a000c9b-v2-noregress/POSTPROCESSING.md
- Evidence: both POSTPROCESSING files say summary.md was regenerated after a summarizer change. `git log` on each summary.md shows a single commit, so the run's own file was never committed. (Mitigation: I regenerated both from raw data and got identical files.)
- Suggested fix: keep the run-time summary as `summary.run-time.md` whenever a summary is regenerated.

### G-34: Committed 7C-stress summary leaks the operator's absolute home path
- Severity: low
- Location: benchmark/results/20260927T191742Z-bc0ff05-7C-stress/summary.md:107-125
- Evidence: "Source CSVs (under `~/Desktop/frost-k8s-threshold-signing/benchmark/../...`". The other summaries are path-stripped by run.sh's `sed`.
- Suggested fix: strip the prefix (cosmetic and privacy only; no numbers change).

### G-35: Level 1 count wording differs between THREAT_MODEL sections
- Severity: low
- Location: docs/THREAT_MODEL.md:135 ("four VMs on one Mac") vs :165 ("native binaries on 3 VMs (2+2+1)")
- Evidence: deploy/multihost/README.md:9 has 4 VMs total (tk8s + 3 signer VMs).
- Suggested fix: "3 signer VMs plus the coordinator VM, all on one Mac".

### G-36: Mid-run assertion and rule changes recorded correctly (no loosening in N76/N82)
- Severity: info
- Location: NOTES.md:1283-1287, 1572-1582
- Evidence: in `git show 8032da3` and `37f3c5e` on test files, the removed lines are only coordinator constructors. Assertions are unchanged, and `TestQuorumAbortOffByDefault` was added. A history-wide scan of removed `if …(==|!=|<|>)`/`t.Fatal` lines in `*_test.go` found loosening only in c46daba (G-22). The other removals replace superseded code paths (4ff02d3 N48, b672ab7 N77, 50985da N33) or strengthen checks (d07a8e7 adds `Controller != "v2"`; 8032da3 per-replica certs).

### G-37: v2 pre-registration verified; the QUORUM_ABORT generalisation is a design choice worth stating
- Severity: info
- Location: docs/PRIORITY_ADMISSION_V2.md §6-§7; NOTES.md:1554-1557
- Evidence: rules are byte-identical at 293a919 and 37f3c5e. Ancestry and timestamps are in order (293a919 16:32Z, d07a8e7 17:11Z, CI green 17:17Z, cluster 17:19Z, data 17:47Z). N81's thresholds equal the 293a919 text (R1 0.8/10 %, R2 +0.5, R3 1.3, R4 2×, §7 +0.2/1.2×/−0.05). The §7 rule compares v2 with v2nb, both under priority admission, and its result sets the default for n48 admission, a configuration it did not measure.
- Suggested fix: state in N82 that the abort default is decided on priority-admission data. N78's b-vs-n48 storm (4.4 vs 3.8, 40 vs 30 s) is the closest n48 evidence.

### G-38: Overload-control framing is correct (evaluated, not adopted)
- Severity: info
- Location: README.md:125-126; docs/THREAT_MODEL.md:287-294; reports/PAPER_INPUTS.md:48, :50; NOTES N78, N81, N82
- Evidence: every mention says "evaluated, not recommended" / "not adopted" / rules failed. The one exception is the stale THREAT_MODEL.md:276-285 paragraph, which describes priority-admission bounds in the present tense under "implemented; evaluation pending" (G-11).

### G-39: Removed test still cited (historical)
- Severity: info
- Location: NOTES.md:589 (N46 `TestAdmissionControlShedsImmediately`)
- Evidence: the function was removed in 4ff02d3 (N48 replaced immediate shedding). N46 is historical. Only cited test name missing from the tree (`G-evidence-missing.txt`).

### G-40: Current summarizer is not backward compatible with 7A
- Severity: info
- Location: benchmark/summarize (HEAD) on `20260926T172317Z-8ebb806-7A-single-m7i-flex.large`
- Evidence: HEAD adds a "Final comparison" table that reports "largest size every system reached (0 pods)". summarizer@c76eee9 reproduces the committed 7A summary exactly.
- Suggested fix: pin the summarizer commit in each results dir (env.json) so regeneration is unambiguous.

### G-41: CLAIMS_AUDIT row 8 formula is an approximation that is 17 % off at p = 0.1
- Severity: info
- Location: reports/CLAIMS_AUDIT.md:22; reports/PAPER_INPUTS.md:31
- Evidence: exact P(≥3 of 5) at p = 0.1 is 0.00856, so the ratio is 11.7, not 10. At p = 0.05 the exact ratio is 43.7 vs 40. The text says "≈ ... for small p", which is fair.
- Suggested fix: optionally give exact values next to the approximation.

### G-42: Actual key ceremonies did not follow KEY_CEREMONY.md's isolated-machine procedure
- Severity: info
- Location: docs/KEY_CEREMONY.md:39-65 vs reports/INDEPENDENCE.md:26-28
- Evidence: "The operator (dealer) machine is a single laptop". `deploy.sh` runs the ceremony on the operator machine (deploy/multihost/README.md:22).
- Suggested fix: state in INDEPENDENCE/PAPER_INPUTS that the test ceremonies ran on the operator laptop (an acceptable test setup, but not the documented procedure).

### G-43: Level 2 ICMP statements are inconsistent
- Severity: info
- Location: NOTES.md:788-789 (N58 "Inbound ICMP is not allowed on the signer hosts") vs reports/INDEPENDENCE.md:54 (nftables `icmp type echo-request accept comment "ping for RTT measurement"`)
- Evidence: the host firewall allows ping from the coordinator. The SG presumably blocks it (not evidenced, G-4).
- Suggested fix: say which layer blocks ICMP.

### G-44: Uncommitted, undocumented aborted lever attempt in the operator workspace
- Severity: info
- Location: (operator working copy, untracked) benchmark/results/20260927T184144Z-1e77bee-7C-lever/
- Evidence: run-lever.log ends with "FATAL: working tree has uncommitted changes". The directory has no data and is not mentioned in NOTES (the two other ABORTED directories are mentioned in N69/N71).
- Suggested fix: mention it or delete it. It has no effect on any result.
