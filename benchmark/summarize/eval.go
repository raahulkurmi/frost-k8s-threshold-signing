package main

// N76 evaluation sections of the -single summary (docs/PRIORITY_ADMISSION.md §5).
// Configuration labels carry the variant after '@' (<system>@<variant>-c<N>):
//   n48    today: N48 admission, no quorum-impossible abort
//   b      quorum-impossible abort only
//   ab     abort + priority-consistent admission
//   slots<k>  N48, no abort, SIGNER_MAX_CONCURRENT=k (admission-slots inference test)
// Every rule below was fixed in docs/PRIORITY_ADMISSION.md before any run.

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type evalRow struct {
	sys, variant            string
	conc, n                 int
	gp, off, errp, p50      float64
	perTok, wasted, surplus float64
	shedKind                map[string]float64
	denied, cpu             float64
	priorityRefusals        float64 // median per run, all signers
	hasAudit                bool
}

func splitVariant(sys string) (base, variant string) {
	if i := strings.LastIndex(sys, "@"); i >= 0 {
		return sys[:i], sys[i+1:]
	}
	return sys, ""
}

func evalRows(runs, cfgs []string, med func(string, func(c cell) float64) float64) []evalRow {
	var rows []evalRow
	for _, l := range cfgs {
		m := singleRe.FindStringSubmatch(l)
		if m == nil || !strings.Contains(m[1], "@") {
			continue
		}
		base, v := splitVariant(m[1])
		c, _ := strconv.Atoi(m[2])
		r := evalRow{sys: base, variant: v, conc: c, shedKind: map[string]float64{}}
		r.gp = med(l, func(x cell) float64 { return x.st.goodput })
		r.off = med(l, func(x cell) float64 { return x.st.offered })
		r.errp = med(l, func(x cell) float64 { return errPct(x.st) })
		r.p50 = med(l, func(x cell) float64 { return x.st.median })
		var perTok, wasted, surplus, denied, prio, cpu []float64
		kinds := map[string][]float64{}
		for _, rd := range runs {
			if sm, ok := readSignerMetrics(filepath.Join(rd, l+".metrics.json")); ok {
				cpu = append(cpu, sm.Mean)
			}
			s, ok := stressOne(filepath.Join(rd, l))
			if !ok || s.requests == 0 {
				continue
			}
			r.n++
			r.hasAudit = true
			perTok = append(perTok, float64(s.computed)/float64(s.requests))
			wf, sp := math.NaN(), math.NaN()
			if s.computed > 0 {
				wf, sp = 100*float64(s.wastedFailed)/float64(s.computed), 100*float64(s.surplus)/float64(s.computed)
			}
			wasted, surplus = append(wasted, wf), append(surplus, sp)
			denied = append(denied, float64(s.denied))
			prio = append(prio, float64(s.shedKind["priority"]+s.shedKind["fair_share"]))
			for _, k := range []string{"priority", "fair_share", "queue_full", "no_slot", "too_late", "other"} {
				kinds[k] = append(kinds[k], float64(s.shedKind[k]))
			}
		}
		r.perTok, r.wasted, r.surplus, r.denied, r.priorityRefusals, r.cpu = median(perTok), median(wasted), median(surplus), median(denied), median(prio), median(cpu)
		for k, xs := range kinds {
			r.shedKind[k] = median(xs)
		}
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].sys != rows[j].sys {
			return rows[i].sys < rows[j].sys
		}
		if rows[i].variant != rows[j].variant {
			return variantOrder(rows[i].variant) < variantOrder(rows[j].variant)
		}
		return rows[i].conc < rows[j].conc
	})
	return rows
}

func variantOrder(v string) string {
	switch v {
	case "n48":
		return "0"
	case "b":
		return "1"
	case "ab":
		return "2"
	}
	if k, err := strconv.Atoi(strings.TrimPrefix(v, "slots")); err == nil {
		return fmt.Sprintf("3%03d", k)
	}
	return "4" + v
}

// evalSection renders the stress before/after, no-regression and slots tables.
func evalSection(runs, cfgs []string, med func(string, func(c cell) float64) float64) string {
	rows := evalRows(runs, cfgs, med)
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	// ---- stress before/after (rows with audit data and c >= 50 somewhere)
	type key struct{ sys, v string }
	groups := map[key][]evalRow{}
	var order []key
	for _, r := range rows {
		k := key{r.sys, r.variant}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	stress := false
	for _, k := range order {
		if (k.v == "n48" || k.v == "b" || k.v == "ab") && groups[k][0].hasAudit && maxConc(groups[k]) >= 100 {
			stress = true
		}
	}
	if stress {
		b.WriteString("\n## N76 evaluation: stress test before/after (label: stress test (CPU-capped signers CPUQuota=25%, SIGNER_MAX_CONCURRENT=1))\n\n")
		b.WriteString("Variants: **n48** = today (N48 admission, no quorum-impossible abort); **b** = quorum-impossible abort only; **ab** = abort + priority-consistent admission. Median of runs; peak = the variant's own highest goodput. Sheds by reason (all signers, median per run): priority / fair share (N76 stage) and queue full / no slot in time / slot too late (N48). **Rules fixed before the run (docs/PRIORITY_ADMISSION.md §5.1):** collapse (DAGOR rule, N70) = goodput < 0.8 × peak and ≥ 20 % of computed shares wasted; **success** for a variant = at every c ≥ 50, goodput ≥ 0.8 × peak **and** wasted-on-failed ≤ 10 %.\n\n")
		b.WriteString("| variant | c | runs | offered /s | goodput /s | goodput / peak | errors % | computed shares per request | wasted on failed % | surplus % | sheds: priority / fair share / queue full / no slot / too late | signer CPU % | collapse (N70 rule) |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|\n")
		verdicts := map[string]string{}
		for _, k := range order {
			if !(k.v == "n48" || k.v == "b" || k.v == "ab") || !groups[k][0].hasAudit || maxConc(groups[k]) < 100 {
				continue
			}
			g := groups[k]
			peak := 0.0
			for _, r := range g {
				peak = math.Max(peak, r.gp)
			}
			success := true
			for _, r := range g {
				ratio := r.gp / peak
				collapse := ratio < 0.8 && r.wasted >= 20
				if r.conc >= 50 && !(ratio >= 0.8 && r.wasted <= 10) {
					success = false
				}
				fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %.2f | %s | %.2f | %s | %s | %s / %s / %s / %s / %s | %s | %s |\n", k.v, r.conc, r.n, f1(r.off), f1(r.gp), ratio, f1(r.errp),
					r.perTok, f1(r.wasted), f1(r.surplus), f1(r.shedKind["priority"]), f1(r.shedKind["fair_share"]), f1(r.shedKind["queue_full"]), f1(r.shedKind["no_slot"]), f1(r.shedKind["too_late"]),
					f1(r.cpu), map[bool]string{true: "**yes**", false: "no"}[collapse])
			}
			verdicts[k.v] = map[bool]string{true: "**MET**", false: "**NOT MET**"}[success]
		}
		b.WriteString("\n")
		for _, v := range []string{"n48", "b", "ab"} {
			if x, ok := verdicts[v]; ok {
				fmt.Fprintf(&b, "- Success rule (every c ≥ 50: goodput ≥ 0.8 × peak and wasted ≤ 10 %%) for **%s**: %s\n", v, x)
			}
		}
		if x, ok := verdicts["ab"]; ok {
			if strings.Contains(x, "NOT") {
				b.WriteString("\n**Decision (§5.1): A+B is not effective at these parameters** (reported as is; not re-tuned under this label).\n")
			} else {
				b.WriteString("\n**Decision (§5.1): A+B meets the pre-registered success rule.**\n")
			}
		}
	}
	// ---- no regression: X@n48 vs X@ab without CPU caps (c <= 50)
	type pair struct{ n48, ab *evalRow }
	pairs := map[string]map[int]*pair{}
	var psys []string
	for i := range rows {
		r := &rows[i]
		if maxConc(groups[key{r.sys, r.variant}]) > 50 || (r.variant != "n48" && r.variant != "ab") {
			continue
		}
		if pairs[r.sys] == nil {
			pairs[r.sys] = map[int]*pair{}
			psys = append(psys, r.sys)
		}
		p := pairs[r.sys][r.conc]
		if p == nil {
			p = &pair{}
			pairs[r.sys][r.conc] = p
		}
		if r.variant == "n48" {
			p.n48 = r
		} else {
			p.ab = r
		}
	}
	var nr strings.Builder
	allPass, any := true, false
	for _, s := range psys {
		var cs []int
		for c := range pairs[s] {
			cs = append(cs, c)
		}
		sort.Ints(cs)
		for _, c := range cs {
			p := pairs[s][c]
			if p.n48 == nil || p.ab == nil {
				continue
			}
			any = true
			gr := p.ab.gp / p.n48.gp
			d := p.ab.p50 - p.n48.p50
			tol := math.Max(0.05*p.n48.p50, 2)
			ok := math.Abs(gr-1) <= 0.05 && math.Abs(d) <= tol && p.ab.errp == 0 && p.n48.errp == 0 && (!p.ab.hasAudit || p.ab.priorityRefusals == 0)
			if !p.ab.hasAudit {
				ok = false // the rule needs the priority-refusal count
			}
			allPass = allPass && ok
			fmt.Fprintf(&nr, "| %s | %d | %s | %s | %.3f | %s | %s | %+.1f (tol ± %.1f) | %s / %s | %s | %s |\n", s, c, f1(p.n48.gp), f1(p.ab.gp), gr, f1(p.n48.p50), f1(p.ab.p50), d, tol,
				f1(p.n48.errp), f1(p.ab.errp), func() string {
					if !p.ab.hasAudit {
						return "not captured"
					}
					return f1(p.ab.priorityRefusals)
				}(), map[bool]string{true: "PASS", false: "**FAIL**"}[ok])
		}
	}
	if any {
		b.WriteString("\n## N76 evaluation: no regression (label: 7C configuration, no-regression check)\n\nUncapped signers, N48 defaults. **Rule fixed before the run (§5.2):** A+B (ab) vs today (n48) in the same session: goodput within ± 5 %, median latency within ± 5 % or ± 2 ms (whichever is larger), 0 errors, **0 priority refusals** (signer audit, all signers).\n\n| system | c | goodput n48 /s | goodput ab /s | ratio | median n48 ms | median ab ms | Δ median ms | errors % n48 / ab | priority + fair-share refusals (ab) | rule |\n|---|---:|---:|---:|---:|---:|---:|---|---|---:|---|\n")
		b.WriteString(nr.String())
		fmt.Fprintf(&b, "\n**Decision (§5.2): no regression %s.**\n", map[bool]string{true: "— every pair PASSES", false: "rule NOT MET (see FAIL rows)"}[allPass])
	}
	// ---- admission-slots inference test
	var slots []evalRow
	for _, r := range rows {
		if strings.HasPrefix(r.variant, "slots") {
			slots = append(slots, r)
		}
	}
	if len(slots) > 0 {
		b.WriteString("\n## N76 evaluation: inference test (admission slots)\n\nUncapped signers, N48, no abort; SIGNER_MAX_CONCURRENT = k. Median of runs. **Rule fixed before the run (§5.3):** the slot inference (N72) is **supported** iff goodput(4 slots) ≥ 1.2 × goodput(2 slots) **and** signer CPU(4) > signer CPU(2); otherwise **not supported**.\n\n| system | slots | c | goodput /s | vs 2 slots | median ms | errors % | signer CPU % (of one vCPU) |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
		by := map[string]evalRow{}
		for _, r := range slots {
			by[r.sys+"/"+r.variant] = r
		}
		for _, r := range slots {
			base, ok := by[r.sys+"/slots2"]
			rel := "–"
			if ok && base.gp > 0 {
				rel = fmt.Sprintf("%.2f×", r.gp/base.gp)
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %s | %s | %s |\n", r.sys, strings.TrimPrefix(r.variant, "slots"), r.conc, f1(r.gp), rel, f1(r.p50), f1(r.errp), f1(r.cpu))
		}
		for _, s := range uniqueSys(slots) {
			two, ok2 := by[s+"/slots2"]
			four, ok4 := by[s+"/slots4"]
			if !ok2 || !ok4 {
				continue
			}
			sup := four.gp >= 1.2*two.gp && four.cpu > two.cpu
			fmt.Fprintf(&b, "\n**Decision (§5.3) for %s: slot inference %s** (goodput 4/2 = %.2f×, signer CPU %s → %s %%).\n", s,
				map[bool]string{true: "SUPPORTED", false: "NOT SUPPORTED"}[sup], four.gp/two.gp, f1(two.cpu), f1(four.cpu))
		}
	}
	return b.String()
}

func maxConc(rs []evalRow) int {
	m := 0
	for _, r := range rs {
		m = max(m, r.conc)
	}
	return m
}

func uniqueSys(rs []evalRow) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		if !seen[r.sys] {
			seen[r.sys] = true
			out = append(out, r.sys)
		}
	}
	return out
}

// ---- §6 open question (N73): why did capped signers use less CPU than their quota?

type cpuSample struct{ ts, cpu, thrUsec float64 }

func readCPUSamples(path string) []cpuSample {
	var out []cpuSample
	for _, l := range readLines(path) {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		var s cpuSample
		var n float64
		if _, err := fmt.Sscanf(f[0]+" "+f[1]+" "+f[2]+" "+f[3], "%f %f %f %f", &s.ts, &s.cpu, &n, &s.thrUsec); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}

// windowRates returns CPU % of one vCPU and throttled % of wall time between the
// first sample at or after from and the last sample at or before to (unix ns).
func windowRates(ss []cpuSample, from, to float64) (cpu, thr float64, ok bool) {
	var a, b *cpuSample
	for i := range ss {
		if a == nil && ss[i].ts >= from {
			a = &ss[i]
		}
		if ss[i].ts <= to {
			b = &ss[i]
		}
	}
	if a == nil || b == nil || b.ts-a.ts < 2e9 {
		return 0, 0, false
	}
	dt := b.ts - a.ts
	return 100 * (b.cpu - a.cpu) / dt, 100 * (b.thrUsec - a.thrUsec) * 1000 / dt, true
}

func lastEndNs(csvPath string) float64 {
	var last float64
	for i, l := range readLines(csvPath) {
		if i == 0 {
			continue
		}
		f := strings.Split(l, ",")
		if len(f) < 4 {
			continue
		}
		var st, lat float64
		fmt.Sscanf(f[2], "%f", &st)
		fmt.Sscanf(f[3], "%f", &lat)
		last = math.Max(last, st+lat)
	}
	return last
}

func openQuestionSection(runs, cfgs []string) string {
	var rows []string
	for _, l := range cfgs {
		var whole, meas, thr, rsa, est, idle, queued []float64
		found := false
		for _, rd := range runs {
			base := filepath.Join(rd, l)
			from, to := float64(firstStartNs(base+".csv")), lastEndNs(base+".csv")
			for id := 1; id <= 5; id++ {
				ss := readCPUSamples(fmt.Sprintf("%s.cpu-signer%d.txt", base, id))
				if len(ss) == 0 {
					continue
				}
				found = true
				if c, _, ok := windowRates(ss, 0, math.Inf(1)); ok {
					whole = append(whole, c)
				}
				if c, t, ok := windowRates(ss, from, to); ok {
					meas, thr = append(meas, c), append(thr, t)
				}
				var r, e []float64
				ni, nq, n := 0, 0, 0
				for _, line := range readLines(fmt.Sprintf("%s.signer%d.log.jsonl", base, id)) {
					var m map[string]any
					if json.Unmarshal([]byte(line), &m) != nil {
						continue
					}
					switch m["msg"] {
					case "sign-share":
						if v, ok := m["rsa_ms"].(float64); ok {
							r = append(r, v)
						}
					case "queue sample":
						n++
						w, _ := m["waiting"].(float64)
						bs, _ := m["busy_slots"].(float64)
						if w == 0 && bs == 0 {
							ni++
						}
						if w > 0 {
							nq++
						}
						if v, ok := m["rsa_estimate_ms"].(float64); ok {
							e = append(e, v)
						}
					}
				}
				if len(r) > 0 {
					rsa = append(rsa, median(r))
				}
				if len(e) > 0 {
					est = append(est, median(e))
				}
				if n > 0 {
					idle, queued = append(idle, 100*float64(ni)/float64(n)), append(queued, 100*float64(nq)/float64(n))
				}
			}
		}
		if !found {
			continue
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |", l, f1(median(whole)), f1(median(meas)), f1(median(thr)), f1(median(rsa)), f1(median(est)), f1(median(idle)), f1(median(queued))))
	}
	if len(rows) == 0 {
		return ""
	}
	return "\n## Open question (N73): signer CPU below the quota (instrumentation, docs/PRIORITY_ADMISSION.md §6)\n\nPer configuration, median over signers and runs. Signer CPU from 1 Hz samples of systemd `CPUUsageNSec` (% of one vCPU): over the whole sampled window, and over the **measured window only** (first to last measured request, hypothesis c). Throttled = cgroup `cpu.stat` `throttled_usec` as % of wall time (hypothesis a), with the per-share RSA time and the signer's RSA estimate (N48 uses the estimate). Queue samples (10 Hz): % with no request waiting and no slot busy (idle), and % with requests waiting (hypothesis b). Reported as measured; no explanation is drawn here.\n\n| configuration | signer CPU % (whole) | signer CPU % (measured window) | throttled % | RSA ms (median) | RSA estimate ms (median) | queue idle % | queue waiting % |\n|---|---:|---:|---:|---:|---:|---:|---:|\n" + strings.Join(rows, "\n") + "\n"
}
