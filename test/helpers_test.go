// Package test holds the Phase 6 correctness and isolation suite (T1–T12).
// Run with `make test` (and `make test-malicious` for T5).
package test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	externaljwtv1 "k8s.io/externaljwt/apis/v1"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/grpcserver"
	"frost-k8s-threshold-signing/internal/testutil"
)

// repoRoot is the module root (this file lives in <root>/test).
func repoRoot(t testing.TB) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(f))
}

var binDir string

// TestMain builds the real runtime binaries once for T8/T9.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tk8s-bin")
	if err != nil {
		panic(err)
	}
	binDir = dir
	_, f, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(f))
	for _, b := range []string{"grpc-proxy", "signer"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, b), "./cmd/"+b)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			panic("build " + b + ": " + err.Error() + "\n" + string(out))
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// serveGRPC exposes co as ExternalJWTSigner on a Unix socket, as the apiserver
// dials it, and returns a v1 client.
func serveGRPC(t *testing.T, c *testutil.Cluster, co *coordinator.Coordinator) externaljwtv1.ExternalJWTSignerClient {
	t.Helper()
	srv, err := grpcserver.New(co, c.Fx.Meta, 3600, 3600)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "tk") // sun_path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	lis, err := grpcserver.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpcserver.NewGRPC(srv)
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return externaljwtv1.NewExternalJWTSignerClient(conn)
}

func saClaims(t *testing.T) string {
	return testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
}

// runBinary runs a built binary with env only (no inherited environment) and
// returns its exit error and combined output. It must exit within timeout.
func runBinary(t *testing.T, name string, env map[string]string, timeout time.Duration) (error, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(binDir, name))
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%s did not exit within %v (it should fail closed at startup): %s", name, timeout, out.String())
	}
	return err, out.String()
}

func listDir(t *testing.T, dir string) []string {
	var names []string
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			names = append(names, p)
		}
		return nil
	})
	return names
}
