// Command dealer runs the trusted-dealer key ceremony: it generates a t-of-n
// Shoup threshold RSA key and writes public metadata plus one share per signer.
// It never writes the full private key and never prints a share.
//
//	dealer --out out/                       # public-meta.json + share-1..n.json
//	dealer --out out/ --vault               # shares to Vault, public-meta.json to out/
//
// See docs/KEY_CEREMONY.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"frost-k8s-threshold-signing/internal/dealer"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("dealer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "out", "output directory for public-meta.json (and share files unless --vault)")
	bits := fs.Int("modulus-bits", 2048, "RSA modulus size in bits (>= 2048)")
	t := fs.Int("t", 3, "threshold")
	n := fs.Int("n", 5, "number of signers")
	useVault := fs.Bool("vault", false, "write shares to Vault KV v2 (VAULT_ADDR, VAULT_TOKEN) instead of files")
	mount := fs.String("vault-mount", "secret", "Vault KV v2 mount; shares go to <mount>/frost-k8s/signer-<i>")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "dealer: unexpected arguments %v\n", fs.Args())
		return 2
	}
	if err := ceremony(*out, *bits, *t, *n, *useVault, *mount, stdout, getenv); err != nil {
		fmt.Fprintf(stderr, "dealer: %v\n", err)
		return 1
	}
	return 0
}

func ceremony(out string, bits, t, n int, useVault bool, mount string, stdout io.Writer, getenv func(string) string) error {
	if out == "" {
		return errors.New("--out is required")
	}
	vaultAddr, vaultToken := getenv("VAULT_ADDR"), getenv("VAULT_TOKEN")
	if useVault && (vaultAddr == "" || vaultToken == "") {
		return errors.New("--vault requires VAULT_ADDR and VAULT_TOKEN")
	}
	// Refuse before spending minutes on keygen if any output already exists.
	targets := []string{dealer.MetaFileName}
	if !useVault {
		for i := 1; i <= n; i++ {
			targets = append(targets, dealer.ShareFileName(i))
		}
	}
	for _, name := range targets {
		if _, err := os.Lstat(filepath.Join(out, name)); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite key material", filepath.Join(out, name))
		}
	}

	fmt.Fprintf(stdout, "Generating %d-of-%d threshold RSA key, %d-bit modulus (safe primes; this can take minutes)...\n", t, n, bits)
	start := time.Now()
	k, err := dealer.Generate(bits, t, n)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Generated in %v\n", time.Since(start).Round(time.Millisecond))

	var outs []dealer.Output
	if useVault {
		vo, err := dealer.WriteVault(context.Background(), nil, vaultAddr, vaultToken, mount, k)
		if err != nil {
			return err
		}
		outs = append(outs, vo...)
	} else {
		so, err := dealer.WriteShareFiles(out, k)
		if err != nil {
			return err
		}
		outs = append(outs, so...)
	}
	mo, err := dealer.WriteMeta(out, k)
	if err != nil {
		return err
	}
	outs = append([]dealer.Output{mo}, outs...)

	fmt.Fprintf(stdout, "kid: %s\n", k.Meta.KID)
	fmt.Fprintf(stdout, "threshold: %d of %d, modulus: %d bits\n", k.Meta.Threshold, k.Meta.Parties, k.Meta.ModulusBits)
	fmt.Fprintln(stdout, "SHA-256 of outputs:")
	for _, o := range outs {
		fmt.Fprintf(stdout, "  %s  %s\n", o.SHA256, o.Name)
	}
	if !useVault {
		fmt.Fprintf(stdout, "Distribute each share-<i>.json to signer <i> only, then securely delete %s (docs/KEY_CEREMONY.md).\n", out)
	}
	return nil
}
