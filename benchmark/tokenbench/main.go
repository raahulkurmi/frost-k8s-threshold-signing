// Command tokenbench measures end-to-end ServiceAccount TokenRequest latency
// through the Kubernetes API with client-go (no kubectl process overhead).
//
//	tokenbench -kubeconfig ~/.kube/config -context kind-tk8s -n 1000 -warmup 100 -c 10 -out run.csv -label T-c10
//
// It writes one CSV row per measured request (warm-up requests are discarded):
//
//	label,seq,start_unix_ns,latency_ns,ok,error
//
// Storm mode (N77, retry amplification): -storm-pods B simulated pods start at
// once; pod i requests a token for service account <storm-sa-prefix><i> in
// -storm-namespace (one identity per pod) and retries until issued or
// -storm-giveup. A fraction -storm-aggressive retries every
// -storm-aggressive-interval; the rest use the kubelet's volume-operation
// backoff (k8s.io/kubernetes pkg/util/goroutinemap/exponentialbackoff at
// v1.36.5: 500 ms, doubling, capped at 2m2s). The CSV then has one row per
// attempt (seq = pod index), and -pods-out gets one JSON line per pod.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type row struct {
	seq     int64
	start   time.Time
	latency time.Duration
	err     error
}

func main() {
	kubeconfig := flag.String("kubeconfig", os.Getenv("HOME")+"/.kube/config", "kubeconfig")
	kctx := flag.String("context", "", "kubeconfig context")
	n := flag.Int("n", 1000, "measured requests")
	warm := flag.Int("warmup", 100, "discarded warm-up requests")
	conc := flag.Int("c", 1, "concurrent workers")
	ns := flag.String("namespace", "default", "namespace")
	sa := flag.String("sa", "default", "service account (with -sa-count: name prefix)")
	saCount := flag.Int("sa-count", 0, "if > 0: request i uses service account <sa><i mod sa-count> (distinct identities, N77)")
	exp := flag.Int64("expiration", 600, "token expirationSeconds")
	out := flag.String("out", "", "CSV output path (required)")
	label := flag.String("label", "", "configuration label written in every row (required)")
	stormPods := flag.Int("storm-pods", 0, "storm mode: number of simulated pods (0 = off)")
	stormNS := flag.String("storm-namespace", "storm", "storm mode: namespace of the per-pod service accounts")
	stormPrefix := flag.String("storm-sa-prefix", "pod-", "storm mode: service account name prefix")
	stormAggr := flag.Float64("storm-aggressive", 0.2, "storm mode: fraction of pods that retry at a fixed short interval")
	stormAggrIv := flag.Duration("storm-aggressive-interval", 250*time.Millisecond, "storm mode: aggressive retry interval")
	stormGiveUp := flag.Duration("storm-giveup", 20*time.Minute, "storm mode: a pod stops retrying after this long")
	podsOut := flag.String("pods-out", "", "storm mode: per-pod JSON lines output (required with -storm-pods)")
	flag.Parse()
	if *out == "" || *label == "" || strings.ContainsAny(*label, ",\n") {
		fmt.Fprintln(os.Stderr, "tokenbench: -out and a comma-free -label are required")
		os.Exit(2)
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = *kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: *kctx}).ClientConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tokenbench:", err)
		os.Exit(1)
	}
	// Disable client-side throttling so the tool is never the bottleneck.
	cfg.QPS, cfg.Burst = 1e6, 1e6
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tokenbench:", err)
		os.Exit(1)
	}

	req := func(ctx context.Context, i int64) error {
		name := *sa
		if *saCount > 0 {
			name = fmt.Sprintf("%s%d", *sa, i%int64(*saCount))
		}
		_, err := cs.CoreV1().ServiceAccounts(*ns).CreateToken(ctx, name,
			&authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: exp}}, metav1.CreateOptions{})
		return err
	}
	run := func(total int, record bool) []row {
		var next atomic.Int64
		rows := make([]row, 0, total)
		var mu sync.Mutex
		var wg sync.WaitGroup
		for w := 0; w < *conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := next.Add(1)
					if i > int64(total) {
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					st := time.Now()
					err := req(ctx, i)
					lat := time.Since(st)
					cancel()
					if record {
						mu.Lock()
						rows = append(rows, row{seq: i, start: st, latency: lat, err: err})
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
		return rows
	}

	var rows []row
	var elapsed time.Duration
	if *stormPods > 0 {
		if *podsOut == "" {
			fmt.Fprintln(os.Stderr, "tokenbench: -storm-pods needs -pods-out")
			os.Exit(2)
		}
		rows, elapsed = storm(cs, *stormPods, *stormNS, *stormPrefix, *stormAggr, *stormAggrIv, *stormGiveUp, *exp, *podsOut)
	} else {
		run(*warm, false)
		wall := time.Now()
		rows = run(*n, true)
		elapsed = time.Since(wall)
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tokenbench:", err)
		os.Exit(1)
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"label", "seq", "start_unix_ns", "latency_ns", "ok", "error"})
	errs := 0
	for _, r := range rows {
		ok, msg := "1", ""
		if r.err != nil {
			ok, msg, errs = "0", strings.ReplaceAll(r.err.Error(), "\n", " "), errs+1
		}
		_ = w.Write([]string{*label, strconv.FormatInt(r.seq, 10), strconv.FormatInt(r.start.UnixNano(), 10), strconv.FormatInt(r.latency.Nanoseconds(), 10), ok, msg})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "tokenbench:", err)
		os.Exit(1)
	}
	f.Close()
	fmt.Printf("%s: %d requests (+%d warm-up) at c=%d in %v; %d errors -> %s\n", *label, len(rows), *warm, *conc, elapsed.Round(time.Millisecond), errs, *out)
}

// kubelet volume-operation backoff (exponentialbackoff at v1.36.5).
const (
	kubeletInitialBackoff = 500 * time.Millisecond
	kubeletMaxBackoff     = 2*time.Minute + 2*time.Second
)

// nextBackoff is exponentialbackoff's step: 500 ms first, then doubling, capped.
func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return kubeletInitialBackoff
	}
	if d *= 2; d > kubeletMaxBackoff {
		return kubeletMaxBackoff
	}
	return d
}

type podResult struct {
	Pod      int     `json:"pod"`
	Class    string  `json:"class"` // polite (kubelet backoff) | aggressive
	Attempts int     `json:"attempts"`
	FirstNs  int64   `json:"first_unix_ns"`
	Issued   bool    `json:"issued"`
	IssuedNs int64   `json:"issued_unix_ns,omitempty"`
	WaitMs   float64 `json:"wait_ms"` // first attempt -> issued (or -> give-up)
}

func storm(cs *kubernetes.Clientset, pods int, ns, prefix string, aggr float64, aggrIv, giveUp time.Duration, exp int64, podsOut string) ([]row, time.Duration) {
	var mu sync.Mutex
	var rows []row
	res := make([]podResult, pods)
	nAggr := int(float64(pods)*aggr + 0.5)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < pods; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			class := "polite"
			if i < nAggr { // priorities are keyed hashes of the SA name, so the index carries no priority
				class = "aggressive"
			}
			r := podResult{Pod: i, Class: class, FirstNs: time.Now().UnixNano()}
			backoff := time.Duration(0)
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				st := time.Now()
				_, err := cs.CoreV1().ServiceAccounts(ns).CreateToken(ctx, fmt.Sprintf("%s%d", prefix, i),
					&authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: &exp}}, metav1.CreateOptions{})
				lat := time.Since(st)
				cancel()
				r.Attempts++
				mu.Lock()
				rows = append(rows, row{seq: int64(i), start: st, latency: lat, err: err})
				mu.Unlock()
				if err == nil {
					r.Issued, r.IssuedNs = true, time.Now().UnixNano()
					break
				}
				if time.Since(time.Unix(0, r.FirstNs)) > giveUp {
					break
				}
				if class == "aggressive" {
					time.Sleep(aggrIv)
					continue
				}
				backoff = nextBackoff(backoff)
				time.Sleep(backoff)
			}
			end := time.Now().UnixNano()
			if r.Issued {
				end = r.IssuedNs
			}
			r.WaitMs = float64(end-r.FirstNs) / 1e6
			res[i] = r
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	f, err := os.Create(podsOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tokenbench:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(f)
	issued := 0
	for _, r := range res {
		_ = enc.Encode(r)
		if r.Issued {
			issued++
		}
	}
	f.Close()
	fmt.Printf("storm: %d pods (%d aggressive), %d issued, %d attempts in %v\n", pods, nAggr, issued, len(rows), elapsed.Round(time.Millisecond))
	return rows, elapsed
}
