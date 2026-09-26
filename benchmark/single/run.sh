#!/usr/bin/env bash
# benchmark/single/run.sh: Phase 7A fair single-host comparison. Runs ON the
# Linux benchmark host (EC2), after scripts/repro.sh has installed the tools and
# built kindest/node:v1.36.5-tk8s.
#
#   B0  stock kind: kube-apiserver signs with its in-tree key
#   B1  single-key external signer (benchmark/b1signer) behind the SAME unix
#       socket + nginx + 3 replicas path as T (NOTES N54)
#   T   threshold 3-of-5: 3 coordinators + 5 signer containers on this host;
#       strategy strict|optimistic x fan-out all|hedged; N48 admission on (defaults)
#
# Each run: B0, then B1, then T (all variants); RUNS full runs. For every
# configuration: tokenbench (client-go CreateToken) with WARMUP discarded + N
# measured requests at each concurrency; host CPU busy/steal % over the
# configuration window and the load average at its end go to
# <label>.metrics.json and into env.json. Before measuring, each system is
# checked: apiserver flags, and the kid of an issued token.
#
# LABEL (every 7A result): single host, 2 vCPU (m7i-flex.large), all components
# co-located; CPU-contended. B0/B1/T share the host, so comparisons stay valid.
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
[[ "$(uname -s)" == Linux ]] || { echo "run on the Linux benchmark host" >&2; exit 1; }

RUNS="${RUNS:-3}" N="${N:-1000}" WARMUP="${WARMUP:-100}"
CONCS="${CONCS:-1 10 20 50}"
STRATEGIES="${STRATEGIES:-strict optimistic}"
FANOUTS="${FANOUTS:-all hedged}"
HEDGE_DELAY="${HEDGE_DELAY:-50ms}"
SYSTEMS="${SYSTEMS:-B0 B1 T}"
LABEL_TEXT="${LABEL_TEXT:-single host, 2 vCPU (m7i-flex.large), all components co-located; CPU-contended}"
export FROST_UID="$(id -u)" GOTOOLCHAIN=go1.27.1 SIGN_DEADLINE=2s
CLUSTER=tk8s KCTX=kind-tk8s
SOCK="$REPO/run/signer.sock"
T_COMPOSE=(docker compose -p tk8s -f deploy/docker-compose.yml)
B1_COMPOSE=(docker compose -p tk8s -f benchmark/single/docker-compose.b1.yml)

imds() { local t; t=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300'); curl -fsS -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/$1"; }
INSTANCE_TYPE="$(imds instance-type 2>/dev/null || echo unknown)"
AZ="$(imds placement/availability-zone 2>/dev/null || echo unknown)"
REGION="$(imds placement/region 2>/dev/null || echo unknown)"

SHA="$(git rev-parse HEAD)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="benchmark/results/$TS-${SHA:0:7}-7A-single-$INSTANCE_TYPE"
mkdir -p "$RES"
exec > >(tee "$RES/run.log") 2>&1
echo "LABEL: $LABEL_TEXT"
echo "instance $INSTANCE_TYPE $REGION/$AZ; commit $SHA; runs $RUNS; N $N after $WARMUP warm-up; c=$CONCS"

die() { echo "FATAL: $*" >&2; exit 1; }
K() { kubectl --context "$KCTX" "$@"; }

cleanup() {
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  "${T_COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  "${B1_COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf secrets audit bin/bench
  sudo rm -rf run
}
trap 'rc=$?; cleanup; echo "cleanup done (generated keys wiped)"; exit $rc' EXIT

echo "== build tools"
mkdir -p bin/bench
( cd benchmark && go build -o "$REPO/bin/bench/tokenbench" ./tokenbench )
go build -o bin/bench/dealer ./cmd/dealer
go build -o bin/bench/probe ./test/e2e/probe
"${T_COMPOSE[@]}" build -q
"${B1_COMPOSE[@]}" build -q
sha256sum bin/bench/tokenbench

# --- per-configuration host metrics ---
cpu_now() { awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }
bench() { # label conc outdir
  local label="$1" c="$2" out="$3" t0 i0 s0 t1 i1 s1
  read -r t0 i0 s0 < <(cpu_now)
  bin/bench/tokenbench -kubeconfig "$HOME/.kube/config" -context "$KCTX" -n "$N" -warmup "$WARMUP" -c "$c" \
    -label "$label" -out "$out/$label.csv"
  read -r t1 i1 s1 < <(cpu_now)
  read -r l1 l5 l15 _ < /proc/loadavg
  awk -v dt=$((t1-t0)) -v di=$((i1-i0)) -v ds=$((s1-s0)) -v l1="$l1" -v l5="$l5" -v l15="$l15" -v lab="$label" -v mem="$(awk '/MemAvailable/{print $2}' /proc/meminfo)" \
    'BEGIN{printf "{\"label\": \"%s\", \"cpu_busy_pct\": %.1f, \"cpu_steal_pct\": %.2f, \"load1\": %s, \"load5\": %s, \"load15\": %s, \"mem_available_kib_at_end\": %s}\n", lab, 100*(1-di/dt), 100*ds/dt, l1, l5, l15, mem}' \
    > "$out/$label.metrics.json"
  echo "   $label: $(tail -n +2 "$out/$label.csv" | awk -F, '{n++; if($5!="1")e++} END{printf "%d rows, %d errors", n, e}'); $(cat "$out/$label.metrics.json")"
}

# --- setup helpers ---
fresh_secrets() {
  rm -rf secrets audit; sudo rm -rf run
  sudo install -d -o root -g root -m 0700 run
  scripts/gen-certs.sh --out secrets >/dev/null
}
wait_socket() {
  local i
  for i in $(seq 1 90); do sudo test -S "$SOCK" && sudo bin/bench/probe fetchkeys "unix://$SOCK" >/dev/null 2>&1 && return 0; sleep 1; done
  die "signer socket did not come up"
}
kind_up() { # config
  kind create cluster --config "$1" --wait 300s >/dev/null
  K wait --for=condition=Ready pods --all -n kube-system --timeout=240s >/dev/null
  local i; for i in $(seq 1 60); do K get sa default >/dev/null 2>&1 && break; sleep 1; done
}
kind_down() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; }
token_kid() { K create token default --duration=600s | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r .kid; }
apiserver_mode() {
  local m; m="$(docker exec "$CLUSTER-control-plane" cat /etc/kubernetes/manifests/kube-apiserver.yaml)"
  if grep -q 'service-account-signing-endpoint=/var/run/frost-k8s/signer.sock' <<<"$m" && ! grep -qE 'service-account-(signing-)?key-file' <<<"$m"; then echo external
  elif grep -q 'service-account-signing-key-file' <<<"$m" && ! grep -q 'signing-endpoint' <<<"$m"; then echo in-tree
  else echo mixed; fi
}
render_ext_kind() { sed "s#__REPO__#$REPO#g" test/e2e/kind-config.yaml.tmpl > "$RES/kind-config-external.yaml"; echo "$RES/kind-config-external.yaml"; }
set_t_variant() { # strategy fanout
  VERIFY_STRATEGY="$1" FANOUT="$2" HEDGE_DELAY="$HEDGE_DELAY" "${T_COMPOSE[@]}" up -d --force-recreate --no-deps grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 >/dev/null 2>&1
  local i ok
  for i in $(seq 1 60); do
    ok=$("${T_COMPOSE[@]}" logs --no-color --no-log-prefix grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 2>/dev/null | grep '"coordinator ready"' | jq -r "select(.strategy==\"$1\" and .fanout==\"$2\") | .kid" | wc -l)
    [[ "$ok" -ge 3 ]] && break; sleep 1
  done
  [[ "$ok" -ge 3 ]] || die "coordinators did not all start with strategy=$1 fanout=$2"
  wait_socket
  sleep 3
}

CHECKS="$RES/system-checks.txt"; : > "$CHECKS"
for run in $(seq 1 "$RUNS"); do
  OUT="$RES/run$run"; mkdir -p "$OUT"
  echo; echo "================ run $run/$RUNS ($(date -u +%T)) ================"
  for sys in $SYSTEMS; do
    case "$sys" in
    B0)
      kind_up benchmark/single/kind-b0.yaml
      mode=$(apiserver_mode); kid=$(token_kid)
      echo "run$run B0: apiserver=$mode token kid=$kid" | tee -a "$CHECKS"
      [[ "$mode" == in-tree ]] || die "B0 apiserver is not using the in-tree key"
      for c in $CONCS; do bench "B0-c$c" "$c" "$OUT"; done
      kind_down;;
    B1)
      fresh_secrets
      mkdir -p secrets/b1; ( umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/b1/key.pem 2>/dev/null )
      "${B1_COMPOSE[@]}" up -d >/dev/null 2>&1; wait_socket
      b1kid=$(sudo bin/bench/probe fetchkeys "unix://$SOCK" 2>/dev/null | jq -r '.keys[0].kid')
      kind_up "$(render_ext_kind)"
      mode=$(apiserver_mode); kid=$(token_kid)
      echo "run$run B1: apiserver=$mode token kid=$kid (b1signer FetchKeys kid=$b1kid)" | tee -a "$CHECKS"
      [[ "$mode" == external && -n "$kid" && "$kid" == "$b1kid" ]] || die "B1 tokens are not signed by b1signer"
      for c in $CONCS; do bench "B1-c$c" "$c" "$OUT"; done
      kind_down; "${B1_COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1;;
    T)
      fresh_secrets
      for i in 1 2 3 4 5; do mkdir -p "audit/signer-$i"; done
      bin/bench/dealer --out secrets/keys >/dev/null
      tkid=$(jq -r .kid secrets/keys/public-meta.json)
      VERIFY_STRATEGY=strict FANOUT=all "${T_COMPOSE[@]}" up -d >/dev/null 2>&1; wait_socket
      kind_up "$(render_ext_kind)"
      mode=$(apiserver_mode); kid=$(token_kid)
      echo "run$run T: apiserver=$mode token kid=$kid (public-meta kid=$tkid)" | tee -a "$CHECKS"
      [[ "$mode" == external && "$kid" == "$tkid" ]] || die "T tokens are not threshold-signed"
      maxc=$("${T_COMPOSE[@]}" logs --no-color --no-log-prefix signer-1 2>/dev/null | grep '"signer ready"' | tail -1 | jq -c '{max_concurrent, max_queue}' 2>/dev/null || echo null)
      echo "run$run T: signer admission $maxc" | tee -a "$CHECKS"
      for st in $STRATEGIES; do for fo in $FANOUTS; do
        set_t_variant "$st" "$fo"
        for c in $CONCS; do bench "T-$st-$fo-c$c" "$c" "$OUT"; done
      done; done
      kind_down; "${T_COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
      rm -rf secrets audit; sudo rm -rf run;;
    esac
  done
done

# --- env.json + summary ---
{
  echo "{"
  echo "  \"label\": \"$LABEL_TEXT\","
  echo "  \"git_commit\": \"$SHA\", \"date_utc\": \"$TS\","
  echo "  \"instance\": {\"type\": \"$INSTANCE_TYPE\", \"region\": \"$REGION\", \"az\": \"$AZ\", \"arch\": \"$(uname -m)\", \"cpu_model\": \"$(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')\", \"vcpus\": $(nproc), \"mem_mib\": $(free -m | awk '/Mem/{print $2}'), \"kernel\": \"$(uname -r)\"},"
  echo "  \"kubernetes\": \"v1.36.5\", \"node_image\": \"$(docker image inspect kindest/node:v1.36.5-tk8s --format '{{.Id}}')\", \"docker\": \"$(docker version --format '{{.Server.Version}}')\", \"kind\": \"$(kind version | cut -d' ' -f2)\", \"go\": \"$(go version | cut -d' ' -f3)\","
  echo "  \"runs\": $RUNS, \"n\": $N, \"warmup\": $WARMUP, \"concurrency\": \"$CONCS\", \"systems\": \"$SYSTEMS\", \"t_strategies\": \"$STRATEGIES\", \"t_fanouts\": \"$FANOUTS\", \"hedge_delay\": \"$HEDGE_DELAY\", \"deadline\": \"$SIGN_DEADLINE\", \"rsa_bits\": 2048, \"t\": 3, \"n_signers\": 5,"
  echo "  \"n48_admission\": \"on (defaults: SIGNER_MAX_CONCURRENT=NumCPU, SIGNER_MAX_QUEUE=64)\", \"signer_admission_logged\": $(grep -h 'signer admission' "$CHECKS" | tail -1 | sed 's/.*admission //' || echo null),"
  echo "  \"client\": \"benchmark/tokenbench (client-go CreateToken, unthrottled) on the same host\","
  echo "  \"system_checks\": $(jq -R . < "$CHECKS" | jq -s .),"
  echo "  \"per_config\": $(for f in "$RES"/run*/*.metrics.json; do jq -c --arg run "$(basename "$(dirname "$f")")" '. + {run: $run}' "$f"; done | jq -s .)"
  echo "}"
} > "$RES/env.json"
jq . "$RES/env.json" >/dev/null || die "env.json invalid"
( cd benchmark && go run ./summarize -single "$REPO/$RES" -title "Phase 7A: B0 vs B1 vs T, single host ($INSTANCE_TYPE, $REGION)" \
  -note "LABEL: $LABEL_TEXT. $RUNS runs; N=$N after $WARMUP warm-up per configuration; commit ${SHA:0:7}." -out "$REPO/$RES/summary.md" )
sed -i "s#$REPO/##g" "$RES/summary.md"
echo "results: $RES"
