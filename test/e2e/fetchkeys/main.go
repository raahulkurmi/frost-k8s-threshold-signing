// Command fetchkeys calls ExternalJWTSigner.FetchKeys (and Metadata) on one
// target and prints a canonical JSON summary, so e2e can compare replicas.
//
//	fetchkeys unix:///path/signer.sock
//	fetchkeys 172.30.0.11:9090
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	externaljwtv1 "k8s.io/externaljwt/apis/v1"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fetchkeys <target>")
		os.Exit(2)
	}
	conn, err := grpc.NewClient(os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	c := externaljwtv1.NewExternalJWTSignerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keys, err := c.FetchKeys(ctx, &externaljwtv1.FetchKeysRequest{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "FetchKeys:", err)
		os.Exit(1)
	}
	md, err := c.Metadata(ctx, &externaljwtv1.MetadataRequest{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Metadata:", err)
		os.Exit(1)
	}
	type key struct {
		KID        string `json:"kid"`
		PKIXSHA256 string `json:"pkix_sha256"`
		Exclude    bool   `json:"exclude_from_oidc_discovery"`
	}
	out := struct {
		Keys          []key  `json:"keys"`
		DataTimestamp string `json:"data_timestamp"`
		RefreshHint   int64  `json:"refresh_hint_seconds"`
		MaxTokenSecs  int64  `json:"max_token_expiration_seconds"`
	}{DataTimestamp: keys.DataTimestamp.AsTime().UTC().Format(time.RFC3339), RefreshHint: keys.RefreshHintSeconds, MaxTokenSecs: md.MaxTokenExpirationSeconds}
	for _, k := range keys.Keys {
		s := sha256.Sum256(k.Key)
		out.Keys = append(out.Keys, key{KID: k.KeyId, PKIXSHA256: hex.EncodeToString(s[:]), Exclude: k.ExcludeFromOidcDiscovery})
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
