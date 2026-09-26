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
# Pod scale-up (run SCALE_RUN only): a Deployment of pause pods, each with one
# projected SA token, scaled 0 -> SCALE_SIZES replicas, SCALE_REPS times per size,
# on an otherwise idle cluster (T: strict, fan-out all). Per repetition:
# scale-command-to-all-Ready time, the apiserver audit events of the TokenRequests
# (latency, errors), for T the coordinators' "signed"/"sign failed" logs (latency,
# signer 503s), and host CPU/load. A size larger than the pods that fit on the
# schedulable nodes is skipped and recorded with the reason.
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
SCALE_RUN="${SCALE_RUN:-1}" SCALE_SIZES="${SCALE_SIZES:-50 100}" SCALE_REPS="${SCALE_REPS:-3}"
LABEL_TEXT="${LABEL_TEXT:-single host, 2 vCPU (m7i-flex.large), all components co-located; CPU-contended}"
export PATH="/usr/local/go/bin:$PATH" FROST_UID="$(id -u)" GOTOOLCHAIN=go1.27.1 SIGN_DEADLINE=2s
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
trap 'rc=$?; [[ $rc -ne 0 ]] && echo "FAILED (rc=$rc) at line $LAST_LINE: $LAST_CMD" >&2; cleanup; echo "cleanup done (generated keys wiped)"; exit $rc' EXIT
set -o functrace
trap 'LAST_LINE=$LINENO LAST_CMD=$BASH_COMMAND' DEBUG

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
token_kid() { # kid from the JWT header of a freshly issued token (base64url, re-padded)
  local h; h=$(K create token default --duration=600s | cut -d. -f1 | tr '_-' '/+') || { echo "token_kid: TokenRequest failed" >&2; return 1; }
  while (( ${#h} % 4 )); do h="$h="; done
  base64 -d <<<"$h" | jq -r .kid
}
apiserver_mode() {
  local m; m="$(docker exec "$CLUSTER-control-plane" cat /etc/kubernetes/manifests/kube-apiserver.yaml)"
  if grep -q 'service-account-signing-endpoint=/var/run/frost-k8s/signer.sock' <<<"$m" && ! grep -qE 'service-account-(signing-)?key-file' <<<"$m"; then echo external
  elif grep -q 'service-account-signing-key-file' <<<"$m" && ! grep -q 'signing-endpoint' <<<"$m"; then echo in-tree
  else echo mixed; fi
}
render_kind() { local o="$RES/$(basename "$1" .tmpl)"; sed "s#__REPO__#$REPO#g" "$1" > "$o"; echo "$o"; }
render_ext_kind() { render_kind benchmark/single/kind-external.yaml.tmpl; }
CP="$CLUSTER-control-plane"
audit_lines() { docker exec "$CP" sh -c 'wc -l < /var/log/kubernetes/audit.log' 2>/dev/null || echo 0; }

# scale_bench SYS OUTDIR [compose...]: pod scale-up benchmark on the current cluster.
scale_bench() {
  local sys="$1" out="$2/scale"; shift 2
  local -a comp=("$@")
  mkdir -p "$out"
  docker exec "$CP" test -f /var/log/kubernetes/audit.log || die "apiserver audit log missing"
  K apply -f benchmark/single/scale-deploy.yaml >/dev/null
  # warm-up (not measured): pull/start the pause image once on the worker
  K scale deploy/scale-pause --replicas=1 >/dev/null
  K wait deploy/scale-pause --for=jsonpath='{.status.readyReplicas}'=1 --timeout=300s >/dev/null
  K scale deploy/scale-pause --replicas=0 >/dev/null
  K wait --for=delete pod -l app=scale-pause --timeout=300s >/dev/null 2>&1 || true
  local nodes fit used
  nodes=$(K get nodes -o json | jq -r '.items[] | select(((.spec.taints // []) | map(.effect=="NoSchedule") | any) | not) | .metadata.name')
  fit=$(K get nodes -o json | jq '[.items[] | select(((.spec.taints // []) | map(.effect=="NoSchedule") | any) | not) | .status.allocatable.pods | tonumber] | add')
  used=$(K get pods -A -o json | jq --arg n "$nodes" '[.items[] | select(.status.phase!="Succeeded" and .status.phase!="Failed") | select(.spec.nodeName as $x | ($n | split("\n")) | index($x))] | length')
  local free=$((fit - used)) size rep
  echo "   scale: schedulable nodes [$(echo $nodes)], allocatable pods $fit, in use $used, free $free"
  for size in $SCALE_SIZES; do
    if [[ $size -gt $free ]]; then
      echo "{\"system\": \"$sys\", \"replicas\": $size, \"skipped\": true, \"reason\": \"only $free pods fit on the schedulable nodes ($fit allocatable, $used in use)\"}" > "$out/$sys-n$size-skipped.json"
      echo "   scale $sys n=$size: SKIPPED (only $free fit)"; continue
    fi
    for rep in $(seq 1 "$SCALE_REPS"); do
      local base="$out/$sys-n$size-rep$rep" off since t0 t1 c0 i0 s0 c1 i1 s1 ready=true l1 l5
      sleep 15   # idle before each repetition
      off=$(audit_lines); since=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
      read -r c0 i0 s0 < <(cpu_now)
      t0=$(date +%s%N)
      K scale deploy/scale-pause --replicas="$size" >/dev/null
      K wait deploy/scale-pause --for=jsonpath='{.status.readyReplicas}'="$size" --timeout=900s >/dev/null || ready=false
      t1=$(date +%s%N)
      read -r c1 i1 s1 < <(cpu_now); read -r l1 l5 _ < /proc/loadavg
      sleep 2   # let the last audit events and coordinator logs flush
      docker exec "$CP" sh -c "tail -n +$((off+1)) /var/log/kubernetes/audit.log" > "$base.audit.jsonl"
      if [[ ${#comp[@]} -gt 0 ]]; then
        "${comp[@]}" logs --no-color --no-log-prefix --since "$since" grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 2>/dev/null | grep -E '"msg":"(signed|sign failed)"' > "$base.coord.jsonl" || true
      fi
      local nready; nready=$(K get deploy scale-pause -o jsonpath='{.status.readyReplicas}'); nready=${nready:-0}
      awk -v sys="$sys" -v n="$size" -v rep="$rep" -v dt="$(( (t1-t0)/1000000 ))" -v ok="$ready" -v nr="$nready" -v ct=$((c1-c0)) -v ci=$((i1-i0)) -v cs=$((s1-s0)) -v l1="$l1" -v l5="$l5" \
        'BEGIN{printf "{\"system\": \"%s\", \"replicas\": %d, \"rep\": %d, \"ms_to_all_ready\": %d, \"all_ready\": %s, \"ready_replicas\": %d, \"cpu_busy_pct\": %.1f, \"cpu_steal_pct\": %.2f, \"load1\": %s, \"load5\": %s}\n", sys, n, rep, dt, ok, nr, 100*(1-ci/ct), 100*cs/ct, l1, l5}' > "$base.json"
      echo "   scale $sys n=$size rep=$rep: $(cat "$base.json"); audit events $(wc -l < "$base.audit.jsonl")"
      [[ $ready == true ]] || K get events --field-selector reason=FailedScheduling -o custom-columns=MSG:.message --no-headers 2>/dev/null | sort | uniq -c | head -3 > "$base.not-ready.txt"
      K scale deploy/scale-pause --replicas=0 >/dev/null
      K wait --for=delete pod -l app=scale-pause --timeout=600s >/dev/null 2>&1 || true
    done
  done
  K delete -f benchmark/single/scale-deploy.yaml --wait=true >/dev/null
}
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
      kind_up "$(render_kind benchmark/single/kind-b0.yaml.tmpl)"
      mode=$(apiserver_mode); kid=$(token_kid)
      echo "run$run B0: apiserver=$mode token kid=$kid" | tee -a "$CHECKS"
      [[ "$mode" == in-tree ]] || die "B0 apiserver is not using the in-tree key"
      for c in $CONCS; do bench "B0-c$c" "$c" "$OUT"; done
      [[ $run == "$SCALE_RUN" ]] && scale_bench B0 "$OUT"
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
      [[ $run == "$SCALE_RUN" ]] && scale_bench B1 "$OUT"
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
      if [[ $run == "$SCALE_RUN" ]]; then set_t_variant strict all; scale_bench T-strict-all "$OUT" "${T_COMPOSE[@]}"; fi
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
  echo "  \"apiserver_audit\": \"all systems: Metadata level for serviceaccounts/token create only (benchmark/single/apiserver-audit-policy/audit-policy.yaml)\","
  echo "  \"scale_up\": {\"run\": $SCALE_RUN, \"sizes\": \"$SCALE_SIZES\", \"reps\": $SCALE_REPS, \"t_variant\": \"strict, fanout all\", \"per_rep\": $(cat "$RES"/run*/scale/*.json 2>/dev/null | jq -s . || echo '[]')},"
  echo "  \"system_checks\": $(jq -R . < "$CHECKS" | jq -s .),"
  echo "  \"per_config\": $(for f in "$RES"/run*/*.metrics.json; do jq -c --arg run "$(basename "$(dirname "$f")")" '. + {run: $run}' "$f"; done | jq -s .)"
  echo "}"
} > "$RES/env.json"
jq . "$RES/env.json" >/dev/null || die "env.json invalid"
( cd benchmark && go run ./summarize -single "$REPO/$RES" -title "Phase 7A: B0 vs B1 vs T, single host ($INSTANCE_TYPE, $REGION)" \
  -note "LABEL: $LABEL_TEXT. $RUNS runs; N=$N after $WARMUP warm-up per configuration; commit ${SHA:0:7}." -out "$REPO/$RES/summary.md" )
sed -i "s#$REPO/##g" "$RES/summary.md"
echo "results: $RES"
