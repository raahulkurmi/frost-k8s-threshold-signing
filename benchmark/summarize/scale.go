package main

// Pod scale-up section of the -single summary. Inputs under DIR/run*/scale/:
//   <sys>-n<size>-rep<k>.json         written by benchmark/single/run.sh
//   <sys>-n<size>-rep<k>.audit.jsonl  kube-apiserver audit events (TokenRequest only)
//   <sys>-n<size>-rep<k>.coord.jsonl  T only: coordinator "signed"/"sign failed" lines
//   <sys>-n<size>-skipped.json        a size that did not fit, with the reason
// Token latency = stageTimestamp - requestReceivedTimestamp of each
// ResponseComplete TokenRequest made by a kubelet (user system:node:*); pooled
// over the repetitions of a (system, size).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type scaleRep struct {
	System        string   `json:"system"`
	Replicas      int      `json:"replicas"`
	Rep           int      `json:"rep"`
	MsToAllReady  float64  `json:"ms_to_all_ready"`
	AllReady      bool     `json:"all_ready"`
	ReadyReplicas int      `json:"ready_replicas"`
	CPUBusyPct    float64  `json:"cpu_busy_pct"`
	Load1         float64  `json:"load1"`
	CooldownS     *float64 `json:"cooldown_s"`
	Load1AtStart  *float64 `json:"load1_at_start"`
	CooldownOK    *bool    `json:"cooldown_reached"`
	Skipped       bool     `json:"skipped"`
	Reason        string   `json:"reason"`
}

type auditEvent struct {
	Stage    string `json:"stage"`
	Received string `json:"requestReceivedTimestamp"`
	StageTS  string `json:"stageTimestamp"`
	User     struct {
		Username string `json:"username"`
	} `json:"user"`
	ObjectRef struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// auditStats returns kubelet TokenRequest latencies (ms) and the error count.
func auditStats(path string) (lat []float64, reqs, errs int) {
	for _, l := range readLines(path) {
		var e auditEvent
		if json.Unmarshal([]byte(l), &e) != nil || e.Stage != "ResponseComplete" ||
			e.ObjectRef.Resource != "serviceaccounts" || e.ObjectRef.Subresource != "token" ||
			!strings.HasPrefix(e.User.Username, "system:node:") {
			continue
		}
		reqs++
		if e.ResponseStatus.Code >= 400 {
			errs++
		}
		a, err1 := time.Parse(time.RFC3339Nano, e.Received)
		b, err2 := time.Parse(time.RFC3339Nano, e.StageTS)
		if err1 == nil && err2 == nil && e.ResponseStatus.Code < 400 {
			lat = append(lat, float64(b.Sub(a).Microseconds())/1000)
		}
	}
	return
}

// coordStats parses coordinator log lines: latency of "signed", count of
// "sign failed", and occurrences of "HTTP 503" (signer overloaded/shed).
func coordStats(path string) (lat []float64, fails, n503 int, present bool) {
	lines := readLines(path)
	if _, err := os.Stat(path); err == nil {
		present = true
	}
	for _, l := range lines {
		n503 += strings.Count(l, "HTTP 503")
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		switch m["msg"] {
		case "signed":
			if v, ok := m["latency_ms"].(float64); ok {
				lat = append(lat, v)
			}
		case "sign failed":
			fails++
		}
	}
	return
}

func scaleSection(dir string) string {
	files, _ := filepath.Glob(filepath.Join(dir, "run[0-9]*", "scale", "*.json"))
	if len(files) == 0 {
		return ""
	}
	sort.Strings(files)
	type key struct {
		sys  string
		size int
	}
	type agg struct {
		reps                []scaleRep
		cool, coolLoad      []float64
		coolMissed          int
		ms, cpu, load, req  []float64
		auditLat, coordLat  []float64
		tokErr, cFail, n503 int
		coord, notReady     bool
		skipped             string
	}
	byKey := map[key]*agg{}
	var keys []key
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r scaleRep
		if json.Unmarshal(b, &r) != nil {
			continue
		}
		k := key{r.System, r.Replicas}
		a := byKey[k]
		if a == nil {
			a = &agg{}
			byKey[k] = a
			keys = append(keys, k)
		}
		if r.Skipped {
			a.skipped = r.Reason
			continue
		}
		a.reps = append(a.reps, r)
		a.ms = append(a.ms, r.MsToAllReady/1000)
		a.cpu = append(a.cpu, r.CPUBusyPct)
		a.load = append(a.load, r.Load1)
		if r.CooldownS != nil && r.Load1AtStart != nil {
			a.cool = append(a.cool, *r.CooldownS)
			a.coolLoad = append(a.coolLoad, *r.Load1AtStart)
			if r.CooldownOK != nil && !*r.CooldownOK {
				a.coolMissed++
			}
		}
		if !r.AllReady {
			a.notReady = true
		}
		base := strings.TrimSuffix(f, ".json")
		lat, reqs, errs := auditStats(base + ".audit.jsonl")
		a.auditLat = append(a.auditLat, lat...)
		a.req = append(a.req, float64(reqs))
		a.tokErr += errs
		cl, cf, c5, present := coordStats(base + ".coord.jsonl")
		if present {
			a.coord = true
			a.coordLat = append(a.coordLat, cl...)
			a.cFail += cf
			a.n503 += c5
		}
	}
	sysRank := func(s string) string { // B0, B1, then T variants
		return map[bool]string{true: "0" + s, false: "1" + s}[strings.HasPrefix(s, "B")]
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].size != keys[j].size {
			return keys[i].size < keys[j].size
		}
		return sysRank(keys[i].sys) < sysRank(keys[j].sys)
	})
	minmax := func(xs []float64) string {
		if len(xs) == 0 {
			return "–"
		}
		lo, hi := math.Inf(1), math.Inf(-1)
		for _, x := range xs {
			lo, hi = math.Min(lo, x), math.Max(hi, x)
		}
		return fmt.Sprintf("%.1f–%.1f", lo, hi)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n## Pod scale-up (B0 vs B1 vs T)\n\nA Deployment of pause pods, each with one projected service account token (automount off), scaled from 0 on an otherwise idle cluster. **Time to Ready** = from the `kubectl scale` command until `readyReplicas` equals the target (median of repetitions, [min–max]). **Token latency** = kube-apiserver audit `stageTimestamp − requestReceivedTimestamp` of each kubelet TokenRequest, pooled over the repetitions (nearest-rank). **Coordinator** columns (T only) come from the coordinators' `signed` / `sign failed` log lines; **signer 503s** counts `HTTP 503` (signer at capacity/shed) in those lines. CPU = host busy %% over the scale window.\n\n")
	fmt.Fprintf(&b, "| Replicas | System | reps | time to all Ready (s): median [min–max] | TokenRequests per rep (median) | token errors (all reps) | token latency p50 / p95 / max (ms) | coordinator latency p50 / p95 (ms) | coordinator sign failures | signer 503s | CPU busy %% (median) | load1 (median) | cooldown before rep (s): median [min–max]; load1 at start (median) | note |\n|---:|---|---:|---|---:|---:|---|---|---:|---:|---:|---:|---|---|\n")
	for _, k := range keys {
		a := byKey[k]
		if a.skipped != "" && len(a.reps) == 0 {
			fmt.Fprintf(&b, "| %d | %s | 0 | – | – | – | – | – | – | – | – | – | – | SKIPPED: %s |\n", k.size, k.sys, a.skipped)
			continue
		}
		sort.Float64s(a.auditLat)
		sort.Float64s(a.coordLat)
		coordCol, failCol, c503 := "–", "–", "–"
		if a.coord {
			coordCol = fmt.Sprintf("%s / %s", f1(pct(a.coordLat, 50)), f1(pct(a.coordLat, 95)))
			failCol, c503 = fmt.Sprint(a.cFail), fmt.Sprint(a.n503)
		}
		note := ""
		if a.notReady {
			note = "**not all Ready within 900 s in some repetition**"
		}
		coolCol := "15 s fixed idle (7A procedure)"
		if len(a.cool) > 0 {
			coolCol = fmt.Sprintf("%s [%s]; load1 %s", f1(median(a.cool)), minmax(a.cool), f1(median(a.coolLoad)))
			if a.coolMissed > 0 {
				coolCol += fmt.Sprintf("; **%d rep(s) hit the 300 s cap before load1 < threshold**", a.coolMissed)
			}
		}
		fmt.Fprintf(&b, "| %d | %s | %d | %s [%s] | %s | %d | %s / %s / %s | %s | %s | %s | %s | %s | %s | %s |\n",
			k.size, k.sys, len(a.reps), f1(median(a.ms)), minmax(a.ms), f1(median(a.req)), a.tokErr,
			f1(pct(a.auditLat, 50)), f1(pct(a.auditLat, 95)), f1(func() float64 {
				if len(a.auditLat) == 0 {
					return math.NaN()
				}
				return a.auditLat[len(a.auditLat)-1]
			}()), coordCol, failCol, c503, f1(median(a.cpu)), f1(median(a.load)), coolCol, note)
	}
	return b.String()
}
