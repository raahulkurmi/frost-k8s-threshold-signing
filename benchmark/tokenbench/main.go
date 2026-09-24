// Command tokenbench measures end-to-end ServiceAccount TokenRequest latency
// through the Kubernetes API with client-go (no kubectl process overhead).
//
//	tokenbench -kubeconfig ~/.kube/config -context kind-tk8s -n 1000 -warmup 100 -c 10 -out run.csv -label T-c10
//
// It writes one CSV row per measured request (warm-up requests are discarded):
//
//	label,seq,start_unix_ns,latency_ns,ok,error
package main

import (
	"context"
	"encoding/csv"
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
	sa := flag.String("sa", "default", "service account")
	exp := flag.Int64("expiration", 600, "token expirationSeconds")
	out := flag.String("out", "", "CSV output path (required)")
	label := flag.String("label", "", "configuration label written in every row (required)")
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

	req := func(ctx context.Context) error {
		_, err := cs.CoreV1().ServiceAccounts(*ns).CreateToken(ctx, *sa,
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
					err := req(ctx)
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

	run(*warm, false)
	wall := time.Now()
	rows := run(*n, true)
	elapsed := time.Since(wall)

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
