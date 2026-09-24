#!/usr/bin/env bash
# check-images.sh (T13, I3/I4): build the coordinator and signer images and
# prove no secret material is baked into any layer.
#
# For each image it inspects:
#   1. every layer tarball from `docker save` (catches files added then deleted),
#   2. the flattened filesystem from `docker export`,
#   3. `docker history` (build commands),
# and fails on any file named like a share, key, encrypted blob or private
# key, on any file whose CONTENT contains a PEM private key or a share JSON,
# and (signer) on any TLS certificate for a signer identity.
#
# Usage: scripts/check-images.sh [--no-build]
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=1
[[ "${1:-}" == "--no-build" ]] && BUILD=0

COORD_IMG=frost-k8s/coordinator:dev
SIGNER_IMG=frost-k8s/signer:dev
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAIL=0

if [[ $BUILD -eq 1 ]]; then
  docker build -q -f deploy/docker/Dockerfile.proxy -t "$COORD_IMG" . >/dev/null
  docker build -q -f deploy/docker/Dockerfile.signer -t "$SIGNER_IMG" . >/dev/null
fi

# Paths that are part of the stock Alpine base and hold no secrets
# (public CA bundle, the empty /usr/local/share directory, apk metadata).
BASE_OK='^(etc/ssl/|etc/ssl1\.1/|usr/share/|usr/local/share/?$|lib/apk/|etc/apk/)'
NAME_BAD='(^|/)(share[^/]*\.json|share-[0-9]+[^/]*|[^/]*\.key|[^/]*\.pem|[^/]*\.enc|[^/]*\.p12|[^/]*PRIVATE[^/]*|public-meta\.json|policy\.json|ca\.srl|[^/]*\.csr)$'

check_image() {
  local img="$1" role="$2" dir="$WORK/$2"
  mkdir -p "$dir/save" "$dir/fs"
  echo "== $role image $img ($(docker image inspect -f '{{.Id}}' "$img" | cut -c1-19))"

  # 1. every layer
  docker save "$img" -o "$dir/image.tar"
  tar -xf "$dir/image.tar" -C "$dir/save"
  local layers=0
  while IFS= read -r layer; do
    layers=$((layers + 1))
    tar -tf "$layer" 2>/dev/null | sed 's#^\./##' > "$dir/layer.lst" || true
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if [[ "$p" =~ $NAME_BAD ]] && ! [[ "$p" =~ $BASE_OK ]]; then
        echo "  FAIL [$role] layer $(basename "$(dirname "$layer")")/$(basename "$layer"): secret-like path $p"
        FAIL=1
      fi
      if [[ "$role" == signer && "$p" =~ (^|/)(signer-[0-9]+|coordinator)(/|\.crt$|$) ]]; then
        echo "  FAIL [$role] layer contains identity material $p"
        FAIL=1
      fi
    done < "$dir/layer.lst"
  done < <(find "$dir/save" -type f \( -name 'layer.tar' -o -path '*/blobs/sha256/*' \) | while read -r f; do tar -tf "$f" >/dev/null 2>&1 && echo "$f"; done)
  echo "  layers inspected: $layers"

  # 2. flattened filesystem: names and contents
  local cid
  cid=$(docker create "$img")
  docker export "$cid" | tar -x -C "$dir/fs" 2>/dev/null || true
  docker rm "$cid" >/dev/null
  local names
  names=$(cd "$dir/fs" && find . -xdev -type f | sed 's#^\./##' | grep -E "$NAME_BAD" | grep -Ev "$BASE_OK" || true)
  if [[ -n "$names" ]]; then echo "  FAIL [$role] files: $names"; FAIL=1; fi
  local content
  content=$(grep -rlaE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|"si"[[:space:]]*:|"signer_index"[[:space:]]*:|frost-dev-password|frost-dev-token' "$dir/fs" \
    --exclude-dir=proc --exclude-dir=sys 2>/dev/null | sed "s#^$dir/fs/##" || true)
  # The binaries legitimately contain the JSON field NAMES as struct tags;
  # a share VALUE would appear only in a data file. Flag non-binary hits.
  local bad=""
  for f in $content; do
    case "$f" in
      usr/local/bin/*) grep -aqE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|frost-dev-password|frost-dev-token' "$dir/fs/$f" && bad="$bad $f" ;;
      *) bad="$bad $f" ;;
    esac
  done
  if [[ -n "$bad" ]]; then echo "  FAIL [$role] secret-like content in:$bad"; FAIL=1; fi
  if [[ "$role" == signer ]] && find "$dir/fs" -name '*.crt' -path '*frost*' | grep -q .; then
    echo "  FAIL [$role] a TLS certificate is baked into the image"; FAIL=1
  fi
  echo "  files in image: $(cd "$dir/fs" && find . -xdev -type f | wc -l | tr -d ' '), binaries: $(ls "$dir/fs/usr/local/bin" | tr '\n' ' ')"

  # 3. build history
  # Build-context paths only (the builder stage's own /out is not the dealer's out/).
  local hist
  hist=$(docker history --no-trunc --format '{{.CreatedBy}}' "$img" \
    | grep -Ei 'frost-keys|ecdsa-signing|share-[0-9]|\.key\b|\.pem\b|\.enc\b|(^|[ =])(\./)?(secrets|certs|data|out)/' || true)
  if [[ -n "$hist" ]]; then
    echo "  FAIL [$role] build history references secret material: $hist"; FAIL=1
  else
    echo "  history: $(docker history -q "$img" | wc -l | tr -d ' ') entries, no secret references"
  fi
}

check_image "$COORD_IMG" coordinator
check_image "$SIGNER_IMG" signer

if [[ $FAIL -ne 0 ]]; then
  echo "check-images: FAIL"
  exit 1
fi
echo "check-images: PASS (no shares, keys, certs, encrypted blobs or private keys in any layer of either image)"
