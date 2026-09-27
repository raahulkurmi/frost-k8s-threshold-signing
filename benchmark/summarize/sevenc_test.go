package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRun writes one configuration: N requests of lat ms each (client side),
// and for B1/T nginx lines (request_time = nginxMs), for T coordinator lines
// (n2c, q, coord ms), plus 2 warm-up requests before the measured window that
// must be excluded from the breakdown.
func writeRun(t *testing.T, dir, sys string, c int, lat, nginxMs, n2c, q, coord float64, nginx, coordLines bool) {
	t.Helper()
	lab := fmt.Sprintf("%s-c%d", sys, c)
	base := filepath.Join(dir, lab)
	const t0 = int64(1_790_000_000_000_000_000)
	var csv, ng, co strings.Builder
	csv.WriteString("label,seq,start_unix_ns,latency_ns,ok,error\n")
	emit := func(i int, start int64) {
		id := fmt.Sprintf("%032x", i+1000*c+len(sys))
		end := float64(start)/1e9 + nginxMs/1000
		fmt.Fprintf(&ng, `{"src":"nginx","msec":"%.3f","request_time":"%.3f","request_id":"%s","uri":"/externaljwt.v1.ExternalJWTSigner/Sign"}`+"\n", end, nginxMs/1000, id)
		fmt.Fprintf(&co, `{"msg":"signed","time":"2026-09-27T10:00:00Z","latency_ms":%.1f,"nginx_request_id":"%s","nginx_to_coordinator_ms":%.1f,"queued_before_sign_ms":%.1f}`+"\n", coord, id, n2c, q)
	}
	for w := 0; w < 2; w++ { // warm-up: before the first measured request
		emit(-1-w, t0-int64(10e9))
	}
	for i := 0; i < 20; i++ {
		start := t0 + int64(i)*int64(1e9)
		fmt.Fprintf(&csv, "%s,%d,%d,%d,1,\n", lab, i, start, int64(lat*1e6))
		emit(i, start)
	}
	must := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(base+".csv", csv.String())
	must(base+".metrics.json", `{"cpu_busy_pct": 50, "cpu_steal_pct": 0, "load1": 1, "load5": 1}`)
	if nginx {
		must(base+".nginx.jsonl", ng.String())
	}
	if coordLines {
		must(base+".coord.jsonl", co.String())
	}
}

func writeScale(t *testing.T, dir, sys string, size, rep int, ms float64, reqs int) {
	t.Helper()
	base := filepath.Join(dir, fmt.Sprintf("%s-n%d-rep%d", sys, size, rep))
	j := fmt.Sprintf(`{"system": %q, "replicas": %d, "rep": %d, "ms_to_all_ready": %.0f, "all_ready": true, "ready_replicas": %d, "cpu_busy_pct": 90, "cpu_steal_pct": 0, "load1": 2, "load5": 1, "cooldown_s": 30, "load1_at_start": 0.8, "cooldown_reached": true}`, sys, size, rep, ms, size)
	var a strings.Builder
	for i := 0; i < reqs; i++ {
		a.WriteString(`{"stage":"ResponseComplete","requestReceivedTimestamp":"2026-09-27T10:00:00.000000Z","stageTimestamp":"2026-09-27T10:00:00.020000Z","user":{"username":"system:node:w1"},"objectRef":{"resource":"serviceaccounts","subresource":"token"},"responseStatus":{"code":201}}` + "\n")
	}
	os.WriteFile(base+".json", []byte(j), 0o644)
	os.WriteFile(base+".audit.jsonl", []byte(a.String()), 0o644)
}

func TestSevenCSummary(t *testing.T) {
	dir := t.TempDir()
	for r := 1; r <= 3; r++ {
		rd := filepath.Join(dir, fmt.Sprintf("run%d", r))
		os.MkdirAll(rd, 0o755)
		for _, c := range []int{1, 10, 50} {
			writeRun(t, rd, "B0", c, 10, 0, 0, 0, 0, false, false)
			writeRun(t, rd, "B1", c, 12, 8, 0, 0, 0, true, false)
			writeRun(t, rd, "T-5region-optimistic", c, 30, 25, 1, 0.5, 20, true, true)
		}
	}
	sd := filepath.Join(dir, "run1", "scale")
	os.MkdirAll(sd, 0o755)
	for rep := 1; rep <= 3; rep++ {
		writeScale(t, sd, "B0", 200, rep, 40000, 200)
		writeScale(t, sd, "B1", 200, rep, 41000, 200)
		writeScale(t, sd, "T-5region-optimistic", 200, rep, 50000, 300)
		writeScale(t, sd, "B0-anchor", 200, rep, 44000, 200)
	}
	out := filepath.Join(dir, "summary.md")
	if err := runSingle(dir, "t", "", out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	for _, want := range []string{
		// final comparison: T at c=1 is 30 ms vs B0 10 ms -> +20.0 (3.00x); scale 50 s vs 40 s; 300/200 = 1.50 TokenRequests per pod
		"| T-5region-optimistic | 30.0 | +20.0 (3.00×) | 30.0 | +20.0 (3.00×) |",
		"| 50.0 | +10.0 (1.25×) | 1.50 | 0 |",
		"| B1 | 12.0 | +2.0 (1.20×) |",
		// breakdown: 60 joined of 60 nginx lines (3 runs x 20; warm-up excluded); nginx 25 = 1 + 0.5 + 20 + 3.5; outside nginx 30 - 25 = 5
		"| T-5region-optimistic | 1 | 30.0 | 25.0 / 25.0 | 1.0 / 1.0 | 0.5 / 0.5 | 20.0 / 20.0 | 3.5 / 3.5 | 5.0 | 60 / 60 |",
		"| B1 | 1 | 12.0 | 8.0 / 8.0 | – | – | – | – | 4.0 | 0 / 60 |",
		// drift: 44 s vs 40 s -> +4.0, 1.10x
		"| 200 | 40.0 [40.0–40.0] | 44.0 [44.0–44.0] | +4.0 | 1.10× | 1.00 / 1.00 |",
		// coordinator columns in the per-run table
		"| 20.0 / 20.0 | 10.0 | 0 |",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q", want)
		}
	}
	if t.Failed() {
		t.Log(s)
	}
}
