package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEvalCfg writes one configuration: reqs requests spaceMs apart, the first
// okN successful; every successful request has 5 computed shares (3 combined),
// every failed one failAllows computed shares; prioSheds priority refusals at
// signer 1; signer CPU cpu (% of one vCPU) for 5 signers.
func writeEvalCfg(t *testing.T, rd, lab string, reqs, okN, failAllows, prioSheds int, latMs, cpu float64) {
	writeEvalCfgSpaced(t, rd, lab, reqs, okN, failAllows, prioSheds, latMs, cpu, 100)
}

func writeEvalCfgSpaced(t *testing.T, rd, lab string, reqs, okN, failAllows, prioSheds int, latMs, cpu, spaceMs float64) {
	t.Helper()
	base := filepath.Join(rd, lab)
	var csv, co strings.Builder
	audits := make([]strings.Builder, 6)
	csv.WriteString("label,seq,start_unix_ns,latency_ns,ok,error\n")
	for i := 0; i < reqs; i++ {
		id := fmt.Sprintf("%s-%03d", lab, i)
		ok := i < okN
		fmt.Fprintf(&csv, "%s,%d,%d,%d,%d,%s\n", lab, i, int64(1_790_000_000_000_000_000)+int64(float64(i)*spaceMs*1e6), int64(latMs*1e6), map[bool]int{true: 1, false: 0}[ok], map[bool]string{true: "", false: "x"}[ok])
		allows := failAllows
		if ok {
			allows = 5
			fmt.Fprintf(&co, `{"msg":"signed","request_id":%q,"combined":[1,2,3],"latency_ms":%.0f}`+"\n", id, latMs)
		} else {
			fmt.Fprintf(&co, `{"msg":"sign failed","request_id":%q,"latency_ms":%.0f}`+"\n", id, latMs)
		}
		for s := 1; s <= allows; s++ {
			fmt.Fprintf(&audits[s], `{"signer_id":%d,"request_id":%q,"decision":"allow"}`+"\n", s, id)
		}
	}
	for i := 0; i < prioSheds; i++ {
		fmt.Fprintf(&audits[1], `{"signer_id":1,"request_id":"p%d","decision":"shed","reason":"overloaded: signer 1: priority below admission level 30000 (admitted fraction 0.542)"}`+"\n", i)
	}
	must := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(base+".csv", csv.String())
	must(base+".coord.jsonl", co.String())
	for s := 1; s <= 5; s++ {
		must(fmt.Sprintf("%s.audit-signer%d.jsonl", base, s), audits[s].String())
	}
	var sg []string
	for s := 1; s <= 5; s++ {
		sg = append(sg, fmt.Sprintf(`{"signer_id":%d,"process_cpu_pct":%.1f,"host_busy_pct":50}`, s, cpu))
	}
	must(base+".metrics.json", fmt.Sprintf(`{"cpu_busy_pct": 10, "cpu_steal_pct": 0, "load1": 1, "load5": 1, "signers": [%s], "signer_cpu_mean_pct": %.1f, "signer_cpu_max_pct": %.1f}`, strings.Join(sg, ","), cpu, cpu))
}

func TestEvalSection(t *testing.T) {
	dir := t.TempDir()
	rd := filepath.Join(dir, "run1")
	os.MkdirAll(rd, 0o755)
	st := "T-sameregion-optimistic"
	// stress: n48 collapses (40 % ok, failed requests computed 2 shares each); ab does not.
	for _, c := range []int{10, 50, 100} {
		ok := 100
		if c >= 50 {
			ok = 40
		}
		writeEvalCfg(t, rd, fmt.Sprintf("%s@n48-c%d", st, c), 100, ok, 2, 0, 700, 23)
		okAB := 100
		if c >= 50 {
			okAB = 90
		}
		writeEvalCfg(t, rd, fmt.Sprintf("%s@ab-c%d", st, c), 100, okAB, 0, 30, 700, 23)
	}
	// no regression: equal at c=1; at c=10 ab has a priority refusal -> FAIL.
	writeEvalCfg(t, rd, "T-5region-optimistic@n48-c1", 50, 50, 0, 0, 150, 10)
	writeEvalCfg(t, rd, "T-5region-optimistic@ab-c1", 50, 50, 0, 0, 151, 10)
	writeEvalCfg(t, rd, "T-5region-optimistic@n48-c10", 50, 50, 0, 0, 150, 10)
	writeEvalCfg(t, rd, "T-5region-optimistic@ab-c10", 50, 50, 0, 1, 150, 10)
	// slots: 4 slots -> requests 75 ms apart instead of 100 (≈ 1.3x goodput), more signer CPU.
	writeEvalCfgSpaced(t, rd, st+"@slots2-c50", 200, 200, 0, 0, 700, 130, 100)
	writeEvalCfgSpaced(t, rd, st+"@slots4-c50", 200, 200, 0, 0, 700, 180, 75)
	// §6 instrumentation for n48 c=50: requests span 1_790_000_000 s .. +10.6 s;
	// samples every second from -3 s to +14 s: 23 % CPU inside the window, 40 %
	// outside it; throttled 50 % of wall time; 4 queue samples (2 idle, 1 waiting).
	var cs strings.Builder
	t0 := 1_790_000_000.0
	cpu := 0.0
	for k := -3; k <= 14; k++ {
		ts := t0 + float64(k)
		rate := 0.40e9
		if ts > t0 && ts <= t0+11 {
			rate = 0.23e9
		}
		cpu += rate
		fmt.Fprintf(&cs, "%.0f %.0f %d %.0f\n", ts*1e9, cpu, k+3, float64(k+3)*0.5e6)
	}
	os.WriteFile(filepath.Join(rd, st+"@n48-c50.cpu-signer1.txt"), []byte(cs.String()), 0o644)
	os.WriteFile(filepath.Join(rd, st+"@n48-c50.signer1.log.jsonl"), []byte(
		`{"msg":"queue sample","waiting":0,"busy_slots":0,"rsa_estimate_ms":80}`+"\n"+
			`{"msg":"queue sample","waiting":0,"busy_slots":0,"rsa_estimate_ms":90}`+"\n"+
			`{"msg":"queue sample","waiting":3,"busy_slots":1,"rsa_estimate_ms":100}`+"\n"+
			`{"msg":"queue sample","waiting":0,"busy_slots":1,"rsa_estimate_ms":110}`+"\n"+
			`{"msg":"sign-share","rsa_ms":17}`+"\n"+`{"msg":"sign-share","rsa_ms":19}`+"\n"), 0o644)
	out := filepath.Join(dir, "summary.md")
	if err := runSingle(dir, "t", "", out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	for _, want := range []string{
		// whole sampled window (-3..14 s): 4.93 s CPU / 17 s = 29.0 %; measured window (0..10 s): 23.0 %; throttled 50.0 %; RSA 18.0; estimate 95.0; idle 50 %, waiting 25 %
		"| T-sameregion-optimistic@n48-c50 | 29.0 | 23.0 | 50.0 | 18.0 | 95.0 | 50.0 | 25.0 |",
		"N76 evaluation: stress test before/after",
		// n48 c=50: wasted = 60*2 / (40*5 + 60*2) = 37.5 %; collapse per N70 rule
		"| n48 | 50 | 1 |", "| 37.5 |", "| **yes** |",
		"for **n48**: **NOT MET**", "for **ab**: **MET**",
		"**Decision (§5.1): A+B meets the pre-registered success rule.**",
		"| T-5region-optimistic | 1 |", "PASS |", "**FAIL** |",
		"rule NOT MET (see FAIL rows)",
		"inference test (admission slots)",
		"slot inference SUPPORTED",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q", want)
		}
	}
	if strings.Contains(s, "## Stress test (CPU-capped signers, SIGNER_MAX_CONCURRENT=1): STRESS TEST") {
		t.Error("the N73 stress table mixed in the N76 variant rows")
	}
	if t.Failed() {
		t.Log(s)
	}
}
