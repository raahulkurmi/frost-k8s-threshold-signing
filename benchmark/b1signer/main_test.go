package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	externaljwtv1 "k8s.io/externaljwt/apis/v1"
)

// The B1 baseline returns a standard RS256 signature over header.claims that
// verifies with the key FetchKeys publishes, and rejects malformed claims like
// the coordinator does.
func TestB1SignsVerifiableRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv, meta, err := newServer(key, 3600, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","sub":"y"}`))
	resp, err := srv.Sign(context.Background(), &externaljwtv1.SignJWTRequest{Claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := srv.FetchKeys(context.Background(), &externaljwtv1.FetchKeysRequest{})
	if err != nil || len(keys.Keys) != 1 || keys.Keys[0].KeyId != meta.KID {
		t.Fatalf("FetchKeys: %v %v", keys, err)
	}
	pub, err := x509.ParsePKIXPublicKey(keys.Keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte(resp.Header + "." + claims))
	if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, d[:], sig); err != nil {
		t.Fatalf("signature does not verify with the FetchKeys key: %v", err)
	}
	if _, err := srv.Sign(context.Background(), &externaljwtv1.SignJWTRequest{Claims: "not base64url!"}); err == nil {
		t.Fatal("malformed claims accepted")
	}
}
