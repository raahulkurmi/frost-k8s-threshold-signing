// Command probe is a TEST-ONLY e2e helper (never part of a deployment). It
// runs on the VM host or inside a throwaway container on a compose network:
//
//	probe fetchkeys <target> [tls flags]      print a canonical FetchKeys+Metadata summary
//	probe sign <target> <claims-b64> [tls]    call Sign; print the header kid or the error
//	probe connect <host:port> [-timeout 2s]   exit 0 iff a TCP connection is accepted
//
// <target> is unix:///path/signer.sock or host:port. TLS flags: -cert -key -ca
// -servername (plaintext if -ca is empty).
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	externaljwtv1 "k8s.io/externaljwt/apis/v1"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func dial(target string, fs *flag.FlagSet, cert, key, ca, sn *string) externaljwtv1.ExternalJWTSignerClient {
	creds := insecure.NewCredentials()
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			die("read ca: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		cfg := &tls.Config{RootCAs: pool, ServerName: *sn, MinVersion: tls.VersionTLS13}
		if *cert != "" {
			kp, err := tls.LoadX509KeyPair(*cert, *key)
			if err != nil {
				die("load client cert: %v", err)
			}
			cfg.Certificates = []tls.Certificate{kp}
		}
		creds = credentials.NewTLS(cfg)
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		die("dial: %v", err)
	}
	return externaljwtv1.NewExternalJWTSignerClient(conn)
}

func main() {
	if len(os.Args) < 3 {
		die("usage: probe fetchkeys|sign|connect <target> ...")
	}
	cmd, target := os.Args[1], os.Args[2]
	rest := os.Args[3:]
	var claims string
	if cmd == "sign" {
		if len(rest) < 1 {
			die("sign needs <claims-b64>")
		}
		claims, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cert := fs.String("cert", "", "client cert")
	key := fs.String("key", "", "client key")
	ca := fs.String("ca", "", "CA (enables TLS)")
	sn := fs.String("servername", "coordinator-grpc", "TLS server name")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout")
	_ = fs.Parse(rest)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch cmd {
	case "connect":
		c, err := net.DialTimeout("tcp", target, *timeout)
		if err != nil {
			fmt.Printf("connect %s: refused/unreachable (%v)\n", target, err)
			os.Exit(1)
		}
		c.Close()
		fmt.Printf("connect %s: ACCEPTED\n", target)
	case "fetchkeys":
		c := dial(target, fs, cert, key, ca, sn)
		keys, err := c.FetchKeys(ctx, &externaljwtv1.FetchKeysRequest{})
		if err != nil {
			die("FetchKeys: %v", err)
		}
		md, err := c.Metadata(ctx, &externaljwtv1.MetadataRequest{})
		if err != nil {
			die("Metadata: %v", err)
		}
		type k struct {
			KID        string `json:"kid"`
			PKIXSHA256 string `json:"pkix_sha256"`
			Exclude    bool   `json:"exclude_from_oidc_discovery"`
		}
		out := struct {
			Keys          []k    `json:"keys"`
			DataTimestamp string `json:"data_timestamp"`
			RefreshHint   int64  `json:"refresh_hint_seconds"`
			MaxTokenSecs  int64  `json:"max_token_expiration_seconds"`
		}{DataTimestamp: keys.DataTimestamp.AsTime().UTC().Format(time.RFC3339), RefreshHint: keys.RefreshHintSeconds, MaxTokenSecs: md.MaxTokenExpirationSeconds}
		for _, key := range keys.Keys {
			s := sha256.Sum256(key.Key)
			out.Keys = append(out.Keys, k{KID: key.KeyId, PKIXSHA256: hex.EncodeToString(s[:]), Exclude: key.ExcludeFromOidcDiscovery})
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	case "sign":
		c := dial(target, fs, cert, key, ca, sn)
		resp, err := c.Sign(ctx, &externaljwtv1.SignJWTRequest{Claims: claims})
		if err != nil {
			die("Sign: %v", err)
		}
		hdr, _ := base64.RawURLEncoding.DecodeString(resp.Header)
		fmt.Printf("Sign: OK header=%s sig_len=%d\n", strings.TrimSpace(string(hdr)), len(resp.Signature))
	default:
		die("unknown command %q", cmd)
	}
}
