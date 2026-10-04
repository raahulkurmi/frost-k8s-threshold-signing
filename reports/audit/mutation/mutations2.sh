#!/usr/bin/env bash
# Phase 12 Pass C manual mutations. Usage: mutations.sh <copy-dir> <mutation-id>...
# Each mutation is an exact-literal source edit; the full suite is then run:
#   go test -count=1 -timeout 30m ./...   (make test-unit)
#   go test -count=1 -timeout 30m -tags testmalicious -run TestMaliciousSignerExcluded -v ./test/   (make test-malicious)
# Results go to $OUT/<id>.{diff,build,log,summary}. The copy is restored after each run.
set -uo pipefail
export GOTOOLCHAIN=go1.27.1
DIR=$1; shift
OUT=${OUT:-<scratch>/out/mut}
mkdir -p "$OUT"
cd "$DIR" || exit 2

# sub FILE OLD NEW: replace exactly one literal occurrence (fails if 0 or >1).
sub() {
  local f=$1
  OLD=$2 NEW=$3 perl -0777 -e '
    local $/; open my $h, "<", $ARGV[0] or die; my $s = <$h>; close $h;
    my $o = $ENV{OLD}; my $n = () = $s =~ /\Q$o\E/g;
    die "match count $n (want 1) in $ARGV[0] for: $o\n" unless $n == 1;
    $s =~ s/\Q$o\E/$ENV{NEW}/;
    open $h, ">", $ARGV[0] or die; print $h $s; close $h;' "$f"
}

C=internal/coordinator/coordinator.go
S=internal/signer/signer.go
P=internal/policy/policy.go
W=internal/wire/wire.go
G=internal/grpcserver/server.go
T=internal/tlsconf/tlsconf.go
K=internal/keyshare/keyshare.go

apply() {
  case $1 in
  CONTROL*) : ;;
  M1) sub $C $'\t\t\t\t\terr := verifyShare(r.share)\n' $'\t\t\t\t\tvar err error // MUTATION M1: strict skips per-share verification\n' ;;
  M2) sub $C 'err = rsa.VerifyPKCS1v15(c.meta.PublicKey, crypto.SHA256, digest[:], s)' '_ = rsa.VerifyPKCS1v15; err = nil // MUTATION M2: no final signature verification' ;;
  M3a) sub $C 'if valid[r.id] != nil || candidates[r.id] != nil {' 'if false && (valid[r.id] != nil || candidates[r.id] != nil) { // MUTATION M3a' ;;
  M3b) sub $C 'if seen[ep.ID] {' 'if false && seen[ep.ID] { // MUTATION M3b' ;;
  M3c) apply M3a && apply M3b ;;
  M4a) sub $W 'if id < 1 || id > parties {' 'if false && (id < 1 || id > parties) { // MUTATION M4a' ;;
  M4b) sub $C 'if ep.ID < 1 || ep.ID > cfg.Meta.Parties {' 'if false && (ep.ID < 1 || ep.ID > cfg.Meta.Parties) { // MUTATION M4b' ;;
  M4c) apply M4a && apply M4b ;;
  M5a) sub $C 'if leaf := resp.TLS.PeerCertificates[0]; len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != fmt.Sprintf("signer-%d", ep.ID) {' \
              'if leaf := resp.TLS.PeerCertificates[0]; false && (len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != fmt.Sprintf("signer-%d", ep.ID)) { // MUTATION M5a' ;;
  M5b) sub $C 'if sr.SignerID != ep.ID {' 'if false && sr.SignerID != ep.ID { // MUTATION M5b' ;;
  M5c) apply M5a && apply M5b && sub $C 'share, err := sr.Share.ToTcrsa(ep.ID,' 'share, err := sr.Share.ToTcrsa(sr.SignerID, // MUTATION M5c: id from the response
		' ;;
  M6a) sub $S $'\theaderSeg, payloadSeg, err := jwtfmt.SplitSigningInput(req.SigningInput)\n' $'\tif raw, derr := jwtfmt.DecodeSegment(req.SigningInput); derr == nil && len(raw) == 32 { // MUTATION M6a: accept a pre-hashed input\n\t\tdoc, _ := tcrsa.PrepareDocumentHash(s.cfg.Meta.PublicKey.Size(), crypto.SHA256, raw)\n\t\tss, _ := s.cfg.Share.Sign(doc, crypto.SHA256, s.cfg.Meta.Tcrsa)\n\t\treturn &wire.SignShareResponse{SignerID: s.cfg.ID, Share: wire.FromTcrsa(ss), RequestID: req.RequestID}, nil\n\t}\n\theaderSeg, payloadSeg, err := jwtfmt.SplitSigningInput(req.SigningInput)\n' ;;
  M6b) sub $W $'\tRequestID    string `json:"request_id"`\n}' $'\tRequestID    string `json:"request_id"`\n\tDigest       string `json:"digest,omitempty"` // MUTATION M6b\n}' && \
       sub $S $'\theaderSeg, payloadSeg, err := jwtfmt.SplitSigningInput(req.SigningInput)\n' $'\tif raw, derr := jwtfmt.DecodeSegment(req.Digest); derr == nil && len(raw) == 32 { // MUTATION M6b: honour a caller digest\n\t\tdoc, _ := tcrsa.PrepareDocumentHash(s.cfg.Meta.PublicKey.Size(), crypto.SHA256, raw)\n\t\tss, _ := s.cfg.Share.Sign(doc, crypto.SHA256, s.cfg.Meta.Tcrsa)\n\t\treturn &wire.SignShareResponse{SignerID: s.cfg.ID, Share: wire.FromTcrsa(ss), RequestID: req.RequestID}, nil\n\t}\n\theaderSeg, payloadSeg, err := jwtfmt.SplitSigningInput(req.SigningInput)\n' ;;
  M7) sub $S $'\tdecision, err := s.cfg.Policy.Evaluate(payload, start)\n\tif err != nil {' $'\tdecision, err := s.cfg.Policy.Evaluate(payload, start)\n\tif err != nil { // MUTATION M7: policy result ignored\n\t\tdecision, err = &policy.Decision{}, nil\n\t}\n\tif err != nil {' ;;
  M8) sub $P 'if prev, dup := folded[strings.ToLower(k)]; dup {' 'if prev, dup := folded[strings.ToLower(k)]; false && dup { // MUTATION M8: revert N14' ;;
  M9) sub $P 'if d := iat - now.Unix(); d > skew || d < -skew {' 'if d := iat - now.Unix(); false && (d > skew || d < -skew) { // MUTATION M9' ;;
  M10a) sub $K $'\tif dec.More() {\n\t\treturn nil, errors.New("trailing data after JSON object (a share file holds exactly one share)")' $'\tif false && dec.More() { // MUTATION M10a\n\t\treturn nil, errors.New("trailing data after JSON object (a share file holds exactly one share)")' ;;
  M10b) sub cmd/signer/main.go $'\tcase shareFile != "":\n\t\tif s.Share, err = keyshare.Load(shareFile, s.Meta, s.ID); err != nil {\n\t\t\treturn nil, err\n\t\t}' \
                               $'\tcase shareFile != "":\n\t\tfor i, f := range strings.Split(shareFile, ",") { // MUTATION M10b: loads every listed share\n\t\t\tks, lerr := keyshare.Load(f, s.Meta, s.ID+i)\n\t\t\tif lerr != nil {\n\t\t\t\treturn nil, lerr\n\t\t\t}\n\t\t\tif i == 0 {\n\t\t\t\ts.Share = ks\n\t\t\t} else {\n\t\t\t\ts.Extra = append(s.Extra, ks)\n\t\t\t}\n\t\t}' && \
        sub cmd/signer/main.go $'\tShare    *tcrsa.KeyShare\n' $'\tShare    *tcrsa.KeyShare\n\tExtra    []*tcrsa.KeyShare // MUTATION M10b\n' && \
        sub cmd/signer/main.go $'\t"strconv"\n\t"syscall"' $'\t"strconv"\n\t"strings"\n\t"syscall"' ;;
  M11) sub $C $'\t"frost-k8s-threshold-signing/internal/jwtfmt"\n' $'\t"frost-k8s-threshold-signing/internal/jwtfmt"\n\t"frost-k8s-threshold-signing/internal/keyshare" // MUTATION M11\n' && \
       printf '\nvar _ = keyshare.FormatVersion // MUTATION M11\n' >> $C ;;
  M12a|M12b|M12c)
       sub $G $'\t"google.golang.org/grpc"\n' $'\t"crypto/rand"\n\t"crypto/rsa"\n\t"crypto/x509"\n\n\t"google.golang.org/grpc"\n' && \
       printf '\n// MUTATION %s helper: some other RSA public key.\nvar otherPKIX = func() []byte { k, _ := rsa.GenerateKey(rand.Reader, 2048); b, _ := x509.MarshalPKIXPublicKey(&k.PublicKey); return b }()\n' "$1" >> $G
       case $1 in
       M12a) sub $G $'\t\t\tExcludeFromOidcDiscovery: false,\n\t\t}},' $'\t\t\tExcludeFromOidcDiscovery: false,\n\t\t}, {KeyId: "other", Key: otherPKIX}}, // MUTATION M12a: an extra key' ;;
       M12b) sub $G 'Key:                      s.meta.PKIX,' 'Key:                      otherPKIX, // MUTATION M12b: not the group key' ;;
       M12c) sub $G 'KeyId:                    s.meta.KID,' 'KeyId:                    s.meta.KID + "x", // MUTATION M12c' ;;
       esac ;;
  M13a) sub $S $'func (s *Server) admitN48(ctx context.Context) (func(), *Rejection) {\n' $'func (s *Server) admitN48(ctx context.Context) (func(), *Rejection) {\n\tif true { // MUTATION M13a: no admission control\n\t\treturn func() {}, nil\n\t}\n' ;;
  M13b) sub $S 'if budget <= 0 {' 'if false && budget <= 0 { // MUTATION M13b' && \
        sub $S 'if n := s.waiting.Add(1); n > int64(s.cfg.MaxQueue) {' 'if n := s.waiting.Add(1); false && n > int64(s.cfg.MaxQueue) { // MUTATION M13b' && \
        sub $S 't := time.NewTimer(budget)' 't := time.NewTimer(time.Hour) // MUTATION M13b' ;;
  M14a) sub $S $'if err := ctx.Err(); err != nil {\n\t\tentry.Decision, entry.Reason = "cancelled", "before RSA: "' $'if err := ctx.Err(); false && err != nil { // MUTATION M14a\n\t\tentry.Decision, entry.Reason = "cancelled", "before RSA: "' ;;
  M14b) sub $S $'if err := ctx.Err(); err != nil {\n\t\tentry.Decision, entry.Reason = "cancelled", "after queue: "' $'if err := ctx.Err(); false && err != nil { // MUTATION M14b\n\t\tentry.Decision, entry.Reason = "cancelled", "after queue: "' ;;
  M14c) sub $S $'if err := ctx.Err(); err != nil {\n\t\t// Computed too late' $'if err := ctx.Err(); false && err != nil { // MUTATION M14c\n\t\t// Computed too late' ;;
  M14) apply M14a && apply M14b && apply M14c ;;
  M15) sub $G 'return nil, status.Error(codes.Unavailable, ErrMsgThreshold)' 'return nil, status.Error(codes.Unavailable, ErrMsgThreshold+": "+err.Error()) // MUTATION M15: revert N33' ;;
  M16) sub $T 'return exactlyOneSAN(cs.PeerCertificates[0], LBName)' 'return nil // MUTATION M16: no client SAN check on the coordinator listener' ;;
  M17a) sub cmd/grpc-proxy/main.go $'\tcase "", "off":\n\tcase "on":\n' $'\tcase "off":\n\tcase "", "on": // MUTATION M17a: QUORUM_ABORT defaults to on\n' ;;
  M17b) sub $C 'abort: cfg.QuorumAbort}, nil' 'abort: true}, nil // MUTATION M17b: abort on regardless of Config' ;;
  # Extra mutations beyond the required list.
  X1) sub internal/jwtfmt/jwtfmt.go 'if seg != want {' 'if false && seg != want { // MUTATION X1: non-canonical header accepted' ;;
  X2) sub $P 'if !p.audiences[a] {' 'if false && !p.audiences[a] { // MUTATION X2: aud allowlist off' ;;
  X3) sub $P 'if exp-iat > p.cfg.MaxTokenSeconds {' 'if false && exp-iat > p.cfg.MaxTokenSeconds { // MUTATION X3: lifetime cap off' ;;
  X4) sub $C 'if sr.RequestID != reqID {' 'if false && sr.RequestID != reqID { // MUTATION X4: request_id not checked' ;;
  X5) sub $C 'if len(raw) > wire.MaxResponseBytes {' 'if false && len(raw) > wire.MaxResponseBytes { // MUTATION X5: response size unchecked' ;;
  X6) sub $K 'if got := new(big.Int).Exp(v, new(big.Int).SetBytes(si), n); got.Cmp(want) != 0 {' 'if got := new(big.Int).Exp(v, new(big.Int).SetBytes(si), n); false && got.Cmp(want) != 0 { // MUTATION X6' ;;
  X7) sub $S 'if !s.limiter.Allow() {' 'if false && !s.limiter.Allow() { // MUTATION X7: no rate limit' ;;
  X8) sub $S 'd := min(time.Duration(ms)*time.Millisecond, s.cfg.MaxDeadline)' 'd := time.Duration(ms) * time.Millisecond // MUTATION X8: deadline header not capped' ;;
  X9) sub $P 'if gotNS == nil || gotName == nil || *gotNS != ns || *gotName != name {' 'if false && (gotNS == nil || gotName == nil || *gotNS != ns || *gotName != name) { // MUTATION X9' ;;
  X10) sub $P 'if nbf > iat+skew || nbf < iat-skew {' 'if false && (nbf > iat+skew || nbf < iat-skew) { // MUTATION X10' ;;
  X11) sub $T 'return coordinatorSAN(cs.PeerCertificates[0])' 'return nil // MUTATION X11: signer accepts any client cert from the CA' ;;
  X12) sub $S $'\tif err := s.cfg.Audit.Write(entry); err != nil {\n\t\ts.cfg.Logger.Error("audit write failed; refusing to sign"' $'\tif err := s.cfg.Audit.Write(entry); false && err != nil { // MUTATION X12\n\t\ts.cfg.Logger.Error("audit write failed; refusing to sign"' ;;
  X13) sub $P 'if p.denyNS[ns] {' 'if false && p.denyNS[ns] { // MUTATION X13: namespace deny list off' ;;
  X14) sub $P 'if iss == nil || *iss != p.cfg.Issuer {' 'if false && (iss == nil || *iss != p.cfg.Issuer) { // MUTATION X14: issuer unchecked' ;;
  X15) sub cmd/grpc-proxy/main.go 'return nil, fmt.Errorf("TCP_ADDR requires mTLS: %w", err)' 'err = nil; break // MUTATION X15: TCP without mTLS allowed' && \
       sub cmd/grpc-proxy/main.go $'\t} else {\n\t\ttc, terr := tlsconf.CoordinatorGRPCServer(' $'\t} else if s.GRPCCert == "" { // MUTATION X15: plaintext TCP listener\n\t\tlis, err = net.Listen("tcp", s.TCP)\n\t} else {\n\t\ttc, terr := tlsconf.CoordinatorGRPCServer(' ;;
  X16) sub $C $'\tt := c.meta.Threshold\n' $'\tt := c.meta.Threshold - 1 // MUTATION X16: one share fewer\n' ;;
  X17) mkdir -p secrets && printf '{"version":1,"kid":"fake-audit-kid","signer_index":3,"si":"QUJDRA=="}\n' > secrets/share-3.json ;;
  *) echo "unknown mutation $1"; return 1 ;;
  esac
}

for id in "$@"; do
  git checkout -q -- . && git clean -qfd -- internal cmd test; rm -f secrets/share-3.json
  {
    echo "mutation $id  dir $DIR  start $(date -u +%FT%TZ)"
    if ! apply "$id"; then echo "APPLY FAILED"; echo "RESULT $id NOT-APPLIED"; continue; fi
  } > "$OUT/$id.summary" 2>&1
  grep -q "NOT-APPLIED" "$OUT/$id.summary" && { cat "$OUT/$id.summary"; continue; }
  git diff > "$OUT/$id.diff"
  if ! go build ./... > "$OUT/$id.build" 2>&1 || ! go vet ./... >> "$OUT/$id.build" 2>&1 || ! go vet -tags testmalicious ./... >> "$OUT/$id.build" 2>&1; then
    echo "RESULT $id BUILD-OR-VET-FAILED" >> "$OUT/$id.summary"; cat "$OUT/$id.summary"; tail -5 "$OUT/$id.build"; continue
  fi
  if [ -n "${DRY:-}" ]; then echo "RESULT $id DRY-OK" >> "$OUT/$id.summary"; tail -1 "$OUT/$id.summary"; continue; fi
  t0=$(date +%s)
  go test -count=1 -timeout 30m ./... > "$OUT/$id.log" 2>&1; rc1=$?
  go test -count=1 -timeout 30m -tags testmalicious -run 'TestMaliciousSignerExcluded' -v ./test/ >> "$OUT/$id.log" 2>&1; rc2=$?
  {
    echo "unit rc=$rc1 malicious rc=$rc2 seconds=$(( $(date +%s) - t0 ))"
    echo "failing tests:"; grep -E '^\s*--- FAIL' "$OUT/$id.log" | sed 's/ (.*//' | sort -u
    echo "failing packages:"; grep -E '^(FAIL|panic:)' "$OUT/$id.log" | sort -u
    if [ $rc1 -ne 0 ] || [ $rc2 -ne 0 ]; then echo "RESULT $id CAUGHT"; else echo "RESULT $id SURVIVED"; fi
  } >> "$OUT/$id.summary"
  cat "$OUT/$id.summary"
done
git checkout -q -- . && git clean -qfd -- internal cmd test; rm -f secrets/share-3.json
