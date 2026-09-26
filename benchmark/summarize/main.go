// Command summarize turns tokenbench CSVs into summary.md. Every number in
// summary.md is computed here from the raw rows and RTT measurements;
// nothing is typed by hand.
//
//	summarize -title "..." -note "..." -out summary.md [TAG=]run1.csv [TAG=]run2.csv ...
//	summarize -single DIR -title "..." -note "..." -out DIR/summary.md   (Phase 7A, single.go)
//
// TAG groups rows (e.g. pre-N43-fix, post-N43-fix). For each CSV the measured
// RTT is read from <csv without .csv>.rtt.json (measured DURING the run) or,
// failing that, rtt-L<N>ms.json in the same directory (measured BEFORE the
// run). The quorum RTT is the 3rd-smallest per-signer RTT: a 3-of-5 quorum
// waits for the 3rd share.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type stats struct {
	tag, label                               string
	n, errs                                  int
	median, p95, p99, mean, stddev, min, max float64 // ms
	throughput                               float64 // goodput: successful req/s over the successful window
	offered                                  float64 // all completions (ok + error) / whole run window
	goodput                                  float64 // successful req/s over the WHOLE run window
	failP95                                  float64 // p95 latency of failed requests (ms)
	firstErr                                 string
	rttQuorum                                float64 // ms, NaN if unknown
	rttSource                                string
	cfgDelay, conc                           int
}

var labelRe = regexp.MustCompile(`L(\d+)ms-c(\d+)`)

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	k := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if k < 0 {
		k = 0
	}
	return sorted[k]
}

// quorumRTT reads a JSON list of per-signer measurements and returns the
// 3rd-smallest RTT. Accepts "rtt_ms" (during-run) or "ping_avg_ms" (pre-run).
func quorumRTT(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return math.NaN(), false
	}
	var rows []map[string]any
	if json.Unmarshal(b, &rows) != nil {
		return math.NaN(), false
	}
	var xs []float64
	for _, r := range rows {
		for _, k := range []string{"rtt_ms", "ping_avg_ms"} {
			if v, ok := r[k].(float64); ok {
				xs = append(xs, v)
				break
			}
		}
	}
	if len(xs) < 3 {
		return math.NaN(), false
	}
	sort.Float64s(xs)
	return xs[2], true
}

func load(tag, path string) ([]*stats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	hdr, err := r.Read()
	if err != nil || strings.Join(hdr, ",") != "label,seq,start_unix_ns,latency_ns,ok,error" {
		return nil, fmt.Errorf("%s: unexpected header %v", path, hdr)
	}
	lat := map[string][]float64{}
	flat := map[string][]float64{}
	first, last := map[string]int64{}, map[string]int64{}
	afirst, alast := map[string]int64{}, map[string]int64{}
	out := map[string]*stats{}
	var order []string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		l := rec[0]
		st, ok := out[l]
		if !ok {
			st = &stats{tag: tag, label: l, rttQuorum: math.NaN(), cfgDelay: -1, conc: -1}
			if m := labelRe.FindStringSubmatch(l); m != nil {
				st.cfgDelay, _ = strconv.Atoi(m[1])
				st.conc, _ = strconv.Atoi(m[2])
			}
			out[l] = st
			order = append(order, l)
		}
		st.n++
		start, _ := strconv.ParseInt(rec[2], 10, 64)
		ln, _ := strconv.ParseInt(rec[3], 10, 64)
		if afirst[l] == 0 || start < afirst[l] {
			afirst[l] = start
		}
		if e := start + ln; e > alast[l] {
			alast[l] = e
		}
		if rec[4] != "1" {
			flat[l] = append(flat[l], float64(ln)/1e6)
			st.errs++
			if st.firstErr == "" {
				st.firstErr = rec[5]
			}
			continue
		}
		lat[l] = append(lat[l], float64(ln)/1e6)
		if first[l] == 0 || start < first[l] {
			first[l] = start
		}
		if e := start + ln; e > last[l] {
			last[l] = e
		}
	}
	var res []*stats
	for _, l := range order {
		st := out[l]
		xs := lat[l]
		sort.Float64s(xs)
		fx := flat[l]
		sort.Float64s(fx)
		st.failP95 = pct(fx, 95)
		if w := float64(alast[l]-afirst[l]) / 1e9; w > 0 {
			st.offered = float64(st.n) / w
			st.goodput = float64(len(xs)) / w
		}
		if len(xs) > 0 {
			var sum float64
			for _, x := range xs {
				sum += x
			}
			st.mean = sum / float64(len(xs))
			var sq float64
			for _, x := range xs {
				sq += (x - st.mean) * (x - st.mean)
			}
			if len(xs) > 1 {
				st.stddev = math.Sqrt(sq / float64(len(xs)-1))
			}
			st.median, st.p95, st.p99 = pct(xs, 50), pct(xs, 95), pct(xs, 99)
			st.min, st.max = xs[0], xs[len(xs)-1]
			if w := float64(last[l]-first[l]) / 1e9; w > 0 {
				st.throughput = float64(len(xs)) / w
			}
		} else {
			st.median, st.p95, st.p99, st.mean, st.stddev, st.min, st.max = math.NaN(), math.NaN(), math.NaN(), math.NaN(), math.NaN(), math.NaN(), math.NaN()
		}
		side := strings.TrimSuffix(path, ".csv") + ".rtt.json"
		if v, ok := quorumRTT(side); ok {
			st.rttQuorum, st.rttSource = v, "during run"
		} else if st.cfgDelay >= 0 {
			if v, ok := quorumRTT(filepath.Join(filepath.Dir(path), fmt.Sprintf("rtt-L%dms.json", st.cfgDelay))); ok {
				st.rttQuorum, st.rttSource = v, "before run (idle)"
			}
		}
		if st.rttSource == "" {
			st.rttSource = "not measured"
		}
		res = append(res, st)
	}
	return res, nil
}

func f1(x float64) string {
	if math.IsNaN(x) {
		return "–"
	}
	return fmt.Sprintf("%.1f", x)
}

func main() {
	title := flag.String("title", "Benchmark summary", "title")
	note := flag.String("note", "", "labelling note printed under the title")
	outPath := flag.String("out", "summary.md", "output")
	single := flag.String("single", "", "Phase 7A mode: results DIR with run<k>/<label>.csv (see single.go)")
	flag.Parse()
	if *single != "" {
		if err := runSingle(*single, *title, *note, *outPath); err != nil {
			fmt.Fprintln(os.Stderr, "summarize:", err)
			os.Exit(1)
		}
		return
	}
	var all []*stats
	var sources []string
	for _, a := range flag.Args() {
		tag, path := "", a
		if i := strings.Index(a, "="); i > 0 && !strings.Contains(a[:i], "/") {
			tag, path = a[:i], a[i+1:]
		}
		st, err := load(tag, path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "summarize:", err)
			os.Exit(1)
		}
		all = append(all, st...)
		sources = append(sources, fmt.Sprintf("- `%s`%s", path, map[bool]string{true: " (" + tag + ")", false: ""}[tag != ""]))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", *title)
	if *note != "" {
		fmt.Fprintf(&b, "> %s\n\n", *note)
	}
	fmt.Fprintf(&b, "Generated by `benchmark/summarize` from the raw CSVs and RTT measurements listed at the end. Latencies in ms; percentiles are nearest-rank over successful requests; **goodput** = successful requests / (last end − first start over ALL requests of the run); offered = all completed requests over the same window; failed p95 = p95 latency of failed requests. **Measured quorum RTT** = 3rd-smallest per-signer RTT from the coordinator host (a 3-of-5 quorum waits for the 3rd share); the configured netem delay is a knob, not a measurement (NOTES N45). Every configuration run is listed, including the worst.\n\n")

	// Side-by-side comparison keyed by (configured delay, concurrency).
	type key struct{ d, c int }
	var keys []key
	byKey := map[key]map[string]*stats{}
	var tags []string
	seenTag := map[string]bool{}
	for _, s := range all {
		k := key{s.cfgDelay, s.conc}
		if byKey[k] == nil {
			byKey[k] = map[string]*stats{}
			keys = append(keys, k)
		}
		t := s.tag
		if t == "" {
			t = "run"
		}
		byKey[k][t] = s
		if !seenTag[t] {
			seenTag[t] = true
			tags = append(tags, t)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].c != keys[j].c {
			return keys[i].c < keys[j].c
		}
		return keys[i].d < keys[j].d
	})
	if len(tags) > 1 {
		fmt.Fprintf(&b, "## Side by side\n\nEach cell: measured quorum RTT → median / p95 latency of successful requests, error %%, **goodput** (successful tokens/s over the whole run), p95 of failed requests (fail-fast check).\n\n| Concurrency | Configured netem (ms) |")
		for _, t := range tags {
			fmt.Fprintf(&b, " %s |", t)
		}
		fmt.Fprintf(&b, "\n|---:|---:|")
		for range tags {
			fmt.Fprintf(&b, "---|")
		}
		fmt.Fprintln(&b)
		for _, k := range keys {
			fmt.Fprintf(&b, "| %d | %d |", k.c, k.d)
			for _, t := range tags {
				s := byKey[k][t]
				if s == nil {
					fmt.Fprintf(&b, " – |")
					continue
				}
				fmt.Fprintf(&b, " RTT %s → %s / %s ms, **%.1f%% err**, goodput **%s**/s, fail-p95 %s ms |", f1(s.rttQuorum), f1(s.median), f1(s.p95), 100*float64(s.errs)/float64(s.n), f1(s.goodput), f1(s.failP95))
			}
			fmt.Fprintln(&b)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "## All configurations\n\n| Set | Measured quorum RTT (ms) | RTT measured | Configured netem (ms) | Configuration | N | errors | error %% | median | p95 | p99 | mean | stddev | min | max | goodput (ok/s, whole run) | offered (all/s) | failed p95 |\n|---|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	var errNotes []string
	for _, s := range all {
		cd := "–"
		if s.cfgDelay >= 0 {
			cd = strconv.Itoa(s.cfgDelay)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d | %d | %.1f | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			map[bool]string{true: s.tag, false: "–"}[s.tag != ""], f1(s.rttQuorum), s.rttSource, cd, s.label, s.n, s.errs, 100*float64(s.errs)/float64(s.n),
			f1(s.median), f1(s.p95), f1(s.p99), f1(s.mean), f1(s.stddev), f1(s.min), f1(s.max), f1(s.goodput), f1(s.offered), f1(s.failP95))
		if s.errs > 0 {
			errNotes = append(errNotes, fmt.Sprintf("- `%s%s`: %d errors; first: `%s`", map[bool]string{true: s.tag + "/", false: ""}[s.tag != ""], s.label, s.errs, s.firstErr))
		}
	}
	if len(errNotes) > 0 {
		fmt.Fprintf(&b, "\nErrors:\n%s\n", strings.Join(errNotes, "\n"))
	}
	fmt.Fprintf(&b, "\nSource CSVs:\n%s\n", strings.Join(sources, "\n"))
	if err := os.WriteFile(*outPath, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "summarize:", err)
		os.Exit(1)
	}
}
