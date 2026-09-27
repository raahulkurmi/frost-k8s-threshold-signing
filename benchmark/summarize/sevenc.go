package main

// Phase 7C sections of the -single summary (NOTES N67):
//   finalSection     B0 vs B1 vs T variants: latency difference vs B0 (ms and
//                    ratio) at c=1 and c=50, goodput, errors, and from the pod
//                    scale-up time to all Ready and TokenRequests per pod
//   breakdownSection the c1 timing breakdown: nginx and coordinator lines joined by
//                    nginx request_id, pooled over runs, at c=1/10/50
//   driftSection     B0 vs B0-anchor pod scale-up per size (drift between sessions)
// Everything is computed from the raw files; nothing is typed by hand.

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
)

func sysOrder(s string) string { // B0, B0-anchor, B1, T-5region-*, T-sameregion-*
	switch {
	case s == "B0":
		return "0"
	case strings.HasPrefix(s, "B0"):
		return "1" + s
	case strings.HasPrefix(s, "B1"):
		return "2" + s
	case strings.HasPrefix(s, "T-5region"):
		return "3" + s
	}
	return "4" + s
}

// finalSection needs the per-config medians (med) and the scale aggregates.
func finalSection(systems []string, med func(label string, f func(c cell) float64) float64, byCfg map[string][]cell, dir string) string {
	has := func(l string) bool { _, ok := byCfg[l]; return ok }
	if !has("B0-c1") {
		return ""
	}
	sort.SliceStable(systems, func(i, j int) bool { return sysOrder(systems[i]) < sysOrder(systems[j]) })
	p50 := func(c cell) float64 { return c.st.median }
	gp := func(c cell) float64 { return c.st.goodput }
	er := func(c cell) float64 { return errPct(c.st) }
	sc, keys := loadScale(dir)
	// largest scale-up size measured (not skipped) for every system that has scale data
	size := 0
	sizes := map[int]map[string]bool{}
	for _, k := range keys {
		if a := sc[k]; a != nil && len(a.reps) > 0 {
			if sizes[k.size] == nil {
				sizes[k.size] = map[string]bool{}
			}
			sizes[k.size][k.sys] = true
		}
	}
	for s, m := range sizes {
		all := true
		for _, sys := range systems {
			if strings.HasPrefix(sys, "B0-") {
				continue
			}
			if !m[sys] {
				all = false
			}
		}
		if all && s > size {
			size = s
		}
	}
	diff := func(x, b float64) string {
		if math.IsNaN(x) || math.IsNaN(b) || b == 0 {
			return "–"
		}
		return fmt.Sprintf("%+.1f (%.2f×)", x-b, x/b)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n## Final comparison (median of runs)\n\nLatency = client-side median over successful requests; Δ vs B0 in ms and as a ratio. Goodput = successful tokens/s over the whole run. Pod scale-up at the largest size every system reached (%d pods): time from `kubectl scale` to all Ready (median of repetitions) and kubelet TokenRequests per pod (audit log).\n\n", size)
	fmt.Fprintf(&b, "| System | c=1 median ms | Δ vs B0 (ms, ×) | c=50 median ms | Δ vs B0 (ms, ×) | goodput c=10 /s | goodput c=50 /s | errors c=50 %% | time to all Ready @%d (s) | Δ vs B0 (s, ×) | TokenRequests per pod @%d | token errors @%d |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n", size, size, size)
	b0c1, b0c50 := med("B0-c1", p50), med("B0-c50", p50)
	var b0ready float64 = math.NaN()
	if a := sc[scaleKey{"B0", size}]; a != nil {
		b0ready = median(a.ms)
	}
	for _, sys := range systems {
		if strings.HasPrefix(sys, "B0-") {
			continue
		}
		c1, c50 := med(sys+"-c1", p50), med(sys+"-c50", p50)
		ready, perPod, tokErr := math.NaN(), math.NaN(), "–"
		if a := sc[scaleKey{sys, size}]; a != nil && size > 0 {
			ready = median(a.ms)
			perPod = median(a.req) / float64(size)
			tokErr = fmt.Sprint(a.tokErr)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", sys,
			f1(c1), diff(c1, b0c1), f1(c50), diff(c50, b0c50), f1(med(sys+"-c10", gp)), f1(med(sys+"-c50", gp)), f1(med(sys+"-c50", er)),
			f1(ready), diff(ready, b0ready), func() string {
				if math.IsNaN(perPod) {
					return "–"
				}
				return fmt.Sprintf("%.2f", perPod)
			}(), tokErr)
	}
	return b.String()
}

type nginxLine struct {
	Msec        string `json:"msec"`
	RequestTime string `json:"request_time"`
	RequestID   string `json:"request_id"`
}

type joined struct{ total, n2c, q, coord, rest float64 }

// joinRun joins one configuration's nginx and coordinator lines, keeping requests
// that arrived at nginx at or after the first measured client request. B1 has no
// coordinator Sign lines: its records carry only the nginx total (coord fields NaN).
func joinRun(base string, measuredStartNs int64) (recs []joined, nginxTotals []float64) {
	byID := map[string]nginxLine{}
	for _, l := range readLines(base + ".nginx.jsonl") {
		var n nginxLine
		if json.Unmarshal([]byte(l), &n) != nil {
			continue
		}
		var end, rt float64
		if _, err := fmt.Sscanf(n.Msec, "%f", &end); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(n.RequestTime, "%f", &rt); err != nil {
			continue
		}
		if int64((end-rt)*1e9) < measuredStartNs {
			continue
		}
		byID[n.RequestID] = n
		nginxTotals = append(nginxTotals, rt*1000)
	}
	for _, l := range readLines(base + ".coord.jsonl") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		id, _ := m["nginx_request_id"].(string)
		n, ok := byID[id]
		if !ok {
			continue
		}
		var rt float64
		fmt.Sscanf(n.RequestTime, "%f", &rt)
		n2c, _ := m["nginx_to_coordinator_ms"].(float64)
		q, _ := m["queued_before_sign_ms"].(float64)
		co, _ := m["latency_ms"].(float64)
		recs = append(recs, joined{total: rt * 1000, n2c: n2c, q: q, coord: co, rest: rt*1000 - n2c - q - co})
	}
	return recs, nginxTotals
}

func firstStartNs(csvPath string) int64 {
	var first int64
	for i, l := range readLines(csvPath) {
		if i == 0 {
			continue
		}
		f := strings.Split(l, ",")
		if len(f) < 3 {
			continue
		}
		var v int64
		fmt.Sscanf(f[2], "%d", &v)
		if first == 0 || v < first {
			first = v
		}
	}
	return first
}

func breakdownSection(dir string, runs []string, systems []string, med func(label string, f func(c cell) float64) float64) string {
	var rows []string
	for _, sys := range systems {
		for _, c := range []int{1, 10, 50} {
			lab := fmt.Sprintf("%s-c%d", sys, c)
			var all []joined
			var ng []float64
			found := false
			for _, rd := range runs {
				base := filepath.Join(rd, lab)
				if !exists(base + ".nginx.jsonl") {
					continue
				}
				found = true
				r, n := joinRun(base, firstStartNs(base+".csv"))
				all = append(all, r...)
				ng = append(ng, n...)
			}
			if !found {
				continue
			}
			pick := func(f func(j joined) float64) []float64 {
				var xs []float64
				for _, j := range all {
					xs = append(xs, f(j))
				}
				sort.Float64s(xs)
				return xs
			}
			mp := func(xs []float64) string {
				if len(xs) == 0 {
					return "–"
				}
				return fmt.Sprintf("%s / %s", f1(pct(xs, 50)), f1(pct(xs, 95)))
			}
			sort.Float64s(ng)
			client := med(lab, func(c cell) float64 { return c.st.median })
			outside := "–"
			if len(ng) > 0 && !math.IsNaN(client) {
				outside = f1(client - pct(ng, 50))
			}
			rows = append(rows, fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %s | %s | %s | %d / %d |", sys, c, f1(client), mp(ng),
				mp(pick(func(j joined) float64 { return j.n2c })), mp(pick(func(j joined) float64 { return j.q })),
				mp(pick(func(j joined) float64 { return j.coord })), mp(pick(func(j joined) float64 { return j.rest })), outside, len(all), len(ng)))
		}
	}
	if len(rows) == 0 {
		return ""
	}
	return "\n## Timing breakdown (c1, NOTES N64): where a TokenRequest's time goes\n\nPooled over runs; median / p95 ms. nginx total = nginx `$request_time`; nginx→coordinator = coordinator gRPC arrival − nginx proxy time; queued = coordinator Sign start − arrival; coordinator = Sign latency; rest = nginx total − the three (nginx processing + return path). **Outside nginx** = client median − nginx-total median (kube-apiserver, network to the load generator, client). Joined = requests with both an nginx and a coordinator line (B1 has no coordinator Sign lines: nginx only). Warm-up excluded.\n\n| System | c | client median | nginx total | nginx→coordinator | queued before Sign | coordinator Sign | rest | outside nginx | joined / nginx lines |\n|---|---:|---:|---|---|---|---|---|---:|---|\n" + strings.Join(rows, "\n") + "\n"
}

func driftSection(dir string) string {
	sc, keys := loadScale(dir)
	var sizes []int
	for _, k := range keys {
		if k.sys == "B0-anchor" {
			sizes = append(sizes, k.size)
		}
	}
	if len(sizes) == 0 {
		return ""
	}
	sort.Ints(sizes)
	mm := func(xs []float64) string {
		if len(xs) == 0 {
			return "–"
		}
		lo, hi := math.Inf(1), math.Inf(-1)
		for _, x := range xs {
			lo, hi = math.Min(lo, x), math.Max(hi, x)
		}
		return fmt.Sprintf("%s [%s–%s]", f1(median(xs)), f1(lo), f1(hi))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n### B0 drift between sessions (anchor re-run)\n\nB0 (session 1) and B0-anchor (session 2, interleaved with T-same-region) on the same cluster: time to all Ready, median [min–max] of repetitions.\n\n| Replicas | B0 session 1 (s) | B0 anchor session 2 (s) | Δ median (s) | ratio | TokenRequests per pod s1 / s2 |\n|---:|---:|---:|---:|---:|---|\n")
	for _, n := range sizes {
		a, c := sc[scaleKey{"B0", n}], sc[scaleKey{"B0-anchor", n}]
		if a == nil || c == nil {
			continue
		}
		d, r := median(c.ms)-median(a.ms), median(c.ms)/median(a.ms)
		fmt.Fprintf(&b, "| %d | %s | %s | %+.1f | %.2f× | %.2f / %.2f |\n", n, mm(a.ms), mm(c.ms), d, r, median(a.req)/float64(n), median(c.req)/float64(n))
	}
	return b.String()
}
