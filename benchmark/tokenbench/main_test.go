package main

import (
	"testing"
	"time"
)

// The storm's polite pods follow the kubelet's volume-operation backoff
// (pkg/util/goroutinemap/exponentialbackoff at v1.36.5): 500 ms, doubling, 2m2s cap.
func TestKubeletBackoffSchedule(t *testing.T) {
	var d time.Duration
	var got []time.Duration
	for i := 0; i < 11; i++ {
		d = nextBackoff(d)
		got = append(got, d)
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 64 * time.Second, 122 * time.Second, 122 * time.Second, 122 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: %v, want %v (all: %v)", i, got[i], want[i], got)
		}
	}
}
