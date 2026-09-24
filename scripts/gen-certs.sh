#!/usr/bin/env bash
# gen-certs.sh: generate a fresh dev CA and distinct mTLS certs for the
# coordinator and each signer. Output goes to secrets/ (git- and docker-ignored).
#
#   secrets/ca/ca.key              CA private key. Never mounted, never copied into an image.
#   secrets/ca/ca.crt              CA certificate
#   secrets/tls/ca.crt             public copy of the CA cert for mounting
#   secrets/tls/coordinator/       tls.crt + tls.key, SAN DNS:coordinator, EKU clientAuth (coordinator -> signers)
#   secrets/tls/coordinator-grpc/  tls.crt + tls.key, SAN DNS:coordinator-grpc, EKU serverAuth (coordinator gRPC listener)
#   secrets/tls/lb/                tls.crt + tls.key, SAN DNS:lb, EKU clientAuth (nginx -> coordinators)
#   secrets/tls/signer-<i>/        tls.crt + tls.key, SAN DNS:signer-<i>, EKU serverAuth
#
# Usage: scripts/gen-certs.sh [--force] [--signers N] [--out DIR]
set -euo pipefail

OUT="secrets"
SIGNERS=5
FORCE=0
DAYS=365

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --signers) SIGNERS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v openssl >/dev/null || { echo "ERROR: openssl not found" >&2; exit 1; }

if [[ -e "$OUT/ca" || -e "$OUT/tls" ]]; then
  if [[ $FORCE -ne 1 ]]; then
    echo "ERROR: $OUT/ca or $OUT/tls already exists; pass --force to replace (old certs become invalid)" >&2
    exit 1
  fi
  rm -rf "$OUT/ca" "$OUT/tls"
fi

umask 077
mkdir -p "$OUT/ca" "$OUT/tls"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# CA
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca/ca.key"
cat > "$TMP/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca
[dn]
CN = frost-k8s dev CA
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
openssl req -x509 -new -key "$OUT/ca/ca.key" -sha256 -days "$DAYS" \
  -config "$TMP/ca.cnf" -out "$OUT/ca/ca.crt"
cp "$OUT/ca/ca.crt" "$OUT/tls/ca.crt"

# issue <name> <eku>
issue() {
  local name="$1" eku="$2" dir="$OUT/tls/$1"
  mkdir -p "$dir"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/tls.key"
  openssl req -new -key "$dir/tls.key" -subj "/CN=$name" -out "$TMP/$name.csr"
  cat > "$TMP/$name.ext" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = $eku
subjectAltName = DNS:$name
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
  openssl x509 -req -in "$TMP/$name.csr" -CA "$OUT/ca/ca.crt" -CAkey "$OUT/ca/ca.key" \
    -CAcreateserial -CAserial "$TMP/ca.srl" -sha256 -days "$DAYS" \
    -extfile "$TMP/$name.ext" -out "$dir/tls.crt" 2>/dev/null
  openssl verify -CAfile "$OUT/ca/ca.crt" "$dir/tls.crt" >/dev/null
  chmod 600 "$dir/tls.key"
  chmod 644 "$dir/tls.crt"
}

issue coordinator clientAuth
issue coordinator-grpc serverAuth
issue lb clientAuth
for i in $(seq 1 "$SIGNERS"); do
  issue "signer-$i" serverAuth
done
chmod 644 "$OUT/ca/ca.crt" "$OUT/tls/ca.crt"

echo "Generated in $OUT/:"
for crt in "$OUT"/tls/*/tls.crt; do
  printf '  %-28s %s  sha256=%s\n' "${crt#"$OUT"/tls/}" \
    "$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | tail -1 | tr -d ' ')" \
    "$(openssl x509 -in "$crt" -noout -fingerprint -sha256 | cut -d= -f2)"
done
echo "CA private key: $OUT/ca/ca.key (keep offline; never mount or copy into an image)"
