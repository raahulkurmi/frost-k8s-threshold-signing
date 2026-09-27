package main

// Lever check and stress test sections of the -single summary (NOTES N70).
//   signerCPUSection  configurations whose metrics.json carry per-signer CPU
//                     (systemd CPUUsageNSec of each signer process, % of one vCPU):
//                     goodput next to signer CPU, median of runs
//   stressSection     configurations with signer audit logs (<label>.audit-signer<i>.jsonl.gz):
//                     shed per signer, shares computed per token, shares wasted on
//                     failed requests, surplus shares beyond the t combined, and the
//                     pre-registered DAGOR decision rule (fixed before the run):
//                       collapse = goodput < 0.8 x peak goodput AND >= 20 % of computed
//                       shares were for requests that failed; otherwise "not observed".

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type signerMetrics struct {
	Signers []struct {
		ID      int     `json:"signer_id"`
		CPU     float64 `json:"process_cpu_pct"`
		HostCPU float64 `json:"host_busy_pct"`
	} `json:"signers"`
	Mean float64 `json:"signer_cpu_mean_pct"`
	Max  float64 `json:"signer_cpu_max_pct"`
}

func readSignerMetrics(path string) (*signerMetrics, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var m signerMetrics
	if json.Unmarshal(b, &m) != nil || len(m.Signers) == 0 {
		return nil, false
	}
	return &m, true
}

func signerCPUSection(runs, cfgs []string, byCfg map[string][]cell, med func(string, func(c cell) float64) float64) string {
	var rows []string
	for _, l := range cfgs {
		var means, maxs, host []float64
		per := map[int][]float64{}
		for _, rd := range runs {
			m, ok := readSignerMetrics(filepath.Join(rd, l+".metrics.json"))
			if !ok {
				continue
			}
			means, maxs = append(means, m.Mean), append(maxs, m.Max)
			var hs []float64
			for _, s := range m.Signers {
				per[s.ID] = append(per[s.ID], s.CPU)
				hs = append(hs, s.HostCPU)
			}
			host = append(host, median(hs))
		}
		if len(means) == 0 {
			continue
		}
		var ids []int
		for id := range per {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		var ps []string
		for _, id := range ids {
			ps = append(ps, fmt.Sprintf("%d: %s", id, f1(median(per[id]))))
		}
		rows = append(rows, fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %s | %s |", l, len(means),
			f1(med(l, func(c cell) float64 { return c.st.goodput })), f1(med(l, func(c cell) float64 { return c.st.offered })),
			f1(median(means)), f1(median(maxs)), strings.Join(ps, ", "), f1(median(host))))
	}
	if len(rows) == 0 {
		return ""
	}
	return "\n## Signer CPU (lever check, stress test)\n\nSigner CPU = each signer process's CPU time (systemd `CPUUsageNSec`) over the configuration window, **% of one vCPU** (a t3.micro has 2 vCPU, so 200 % is the host maximum); median of runs. Goodput and offered load in tokens/s, median of runs.\n\n| Configuration | runs | goodput | offered | signer CPU mean % | signer CPU max % | per signer (id: %) | signer host busy % (median) |\n|---|---:|---:|---:|---:|---:|---|---:|\n" + strings.Join(rows, "\n") + "\n"
}

type stressRun struct {
	requests, failed, computed, wastedFailed, surplus, cancelled int
	shed                                                         map[int]int
}

func stressOne(base string) (stressRun, bool) {
	r := stressRun{shed: map[int]int{}}
	// coordinator view: request -> failed? and combined count
	failed := map[string]bool{}
	combined := map[string]int{}
	for _, l := range readLines(base + ".coord.jsonl") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		id, _ := m["request_id"].(string)
		switch m["msg"] {
		case "signed":
			r.requests++
			if c, ok := m["combined"].([]any); ok {
				combined[id] = len(c)
			}
		case "sign failed":
			r.requests++
			r.failed++
			failed[id] = true
		}
	}
	allowed := map[string]int{}
	found := false
	for i := 1; i <= 9; i++ {
		lines := readLines(fmt.Sprintf("%s.audit-signer%d.jsonl", base, i))
		if lines == nil {
			continue
		}
		found = true
		for _, l := range lines {
			var e struct {
				Signer   int    `json:"signer_id"`
				Request  string `json:"request_id"`
				Decision string `json:"decision"`
			}
			if json.Unmarshal([]byte(l), &e) != nil {
				continue
			}
			switch e.Decision {
			case "allow":
				r.computed++
				allowed[e.Request]++
			case "shed":
				r.shed[e.Signer]++
			case "cancelled":
				r.cancelled++
			}
		}
	}
	if !found {
		return r, false
	}
	for id, n := range allowed {
		switch {
		case failed[id]:
			r.wastedFailed += n
		case combined[id] > 0 && n > combined[id]:
			r.surplus += n - combined[id]
		}
	}
	return r, true
}

func stressSection(runs, cfgs []string, med func(string, func(c cell) float64) float64) string {
	type row struct {
		label                                          string
		conc                                           int
		gp, off, err, perTok, wasted, surplus, shedTot float64
		shedPer                                        map[int][]float64
		n                                              int
	}
	var rows []row
	for _, l := range cfgs {
		var perTok, wasted, surplus, shedTot []float64
		shedPer := map[int][]float64{}
		n := 0
		for _, rd := range runs {
			s, ok := stressOne(filepath.Join(rd, l))
			if !ok || s.requests == 0 {
				continue
			}
			n++
			perTok = append(perTok, float64(s.computed)/float64(s.requests))
			wf, sp := math.NaN(), math.NaN()
			if s.computed > 0 {
				wf, sp = 100*float64(s.wastedFailed)/float64(s.computed), 100*float64(s.surplus)/float64(s.computed)
			}
			wasted, surplus = append(wasted, wf), append(surplus, sp)
			tot := 0
			for id := 1; id <= 5; id++ {
				shedPer[id] = append(shedPer[id], float64(s.shed[id]))
				tot += s.shed[id]
			}
			shedTot = append(shedTot, float64(tot))
		}
		if n == 0 {
			continue
		}
		c := 0
		if m := singleRe.FindStringSubmatch(l); m != nil {
			fmt.Sscanf(m[2], "%d", &c)
		}
		rows = append(rows, row{label: l, conc: c, n: n,
			gp: med(l, func(x cell) float64 { return x.st.goodput }), off: med(l, func(x cell) float64 { return x.st.offered }),
			err: med(l, func(x cell) float64 { return errPct(x.st) }), perTok: median(perTok), wasted: median(wasted),
			surplus: median(surplus), shedTot: median(shedTot), shedPer: shedPer})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].conc < rows[j].conc })
	peak := 0.0
	for _, r := range rows {
		peak = math.Max(peak, r.gp)
	}
	var b strings.Builder
	b.WriteString("\n## Stress test (CPU-capped signers, SIGNER_MAX_CONCURRENT=1): STRESS TEST, not a realistic workload\n\nPer configuration, median of runs. **Computed shares** = signer audit `allow` entries (a share is computed after admission; NOTES N70); **wasted on failed** = computed shares for requests the coordinator failed; **surplus** = computed shares beyond the t combined into a successful token (fan-out all computes up to 5); **shed** = signer audit `shed` entries (HTTP 503). **Decision rule (fixed before the run):** DAGOR-style priority-consistent admission is indicated only if goodput < 0.8 × peak goodput **and** ≥ 20 % of computed shares were wasted on failed requests; otherwise \"not observed\".\n\n")
	b.WriteString("| c | runs | offered /s | goodput /s | goodput / peak | errors % | computed shares per request | wasted on failed % | surplus % | shed (all signers) | shed per signer (1..5) | collapse per rule |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|\n")
	any := false
	for _, r := range rows {
		ratio := r.gp / peak
		collapse := ratio < 0.8 && r.wasted >= 20
		any = any || collapse
		var sp []string
		for id := 1; id <= 5; id++ {
			sp = append(sp, f1(median(r.shedPer[id])))
		}
		verdict := "no"
		if collapse {
			verdict = "**yes**"
		}
		fmt.Fprintf(&b, "| %d | %d | %s | %s | %.2f | %s | %.2f | %s | %s | %s | %s | %s |\n", r.conc, r.n, f1(r.off), f1(r.gp), ratio, f1(r.err),
			r.perTok, f1(r.wasted), f1(r.surplus), f1(r.shedTot), strings.Join(sp, " / "), verdict)
	}
	if any {
		b.WriteString("\n**Decision: goodput collapse with a high wasted-share fraction OBSERVED**: DAGOR-style priority-consistent admission is indicated (to be designed; not implemented).\n")
	} else {
		b.WriteString("\n**Decision: goodput collapse with a high wasted-share fraction NOT OBSERVED** in this stress test.\n")
	}
	return b.String()
}
