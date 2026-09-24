#!/usr/bin/env bash
# test/e2e/run.sh: Kubernetes e2e for frost-k8s (E1–E8 plus requirements a–d).
#
# Linux + Docker Engine only (refuses Docker Desktop). From a clean slate it:
#   generates certs and a fresh 3-of-5 key, builds and starts 5 signers,
#   3 coordinators and nginx (Unix socket), creates a kind v1.36.5 cluster
#   whose apiserver signs ONLY via that socket, then runs every E-test.
# Output: test/e2e/results/<UTC timestamp>-<short sha>/e2e.log. Full tokens
# are never printed (header and claims only).
#
# Usage: test/e2e/run.sh [--keep]   (--keep leaves the cluster running)
#
# TOPOLOGY=single (default): signers are containers on this host.
# TOPOLOGY=multihost: signers run on other hosts (deploy/multihost/deploy.sh has
#   already placed public-meta + coordinator certs in secrets/); the operator's
#   orchestrator (test/e2e/multihost.sh) serves signer stop/start/audit requests
#   written to $CTL, because only the operator can reach the signer hosts.
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

die() { echo "FATAL: $*" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || die "e2e runs on a Linux host only"
docker info --format '{{.OperatingSystem}}' | grep -qi 'docker desktop' && die "refusing to run on Docker Desktop"

SHA="$(git rev-parse HEAD)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS="test/e2e/results/${TS}-${SHA:0:7}"
mkdir -p "$RESULTS"
exec > >(tee "$RESULTS/e2e.log") 2>&1

export FROST_UID="$(id -u)" GOTOOLCHAIN=go1.27.1 VERIFY_STRATEGY=strict SIGN_DEADLINE=2s
TOPOLOGY="${TOPOLOGY:-single}"
[[ "$TOPOLOGY" == single || "$TOPOLOGY" == multihost ]] || die "TOPOLOGY must be single or multihost"
CTL=/tmp/frost-ctl
CTL_SEQ=0
CLUSTER=tk8s
KCTX="kind-$CLUSTER"
K() { kubectl --context "$KCTX" "$@"; }
if [[ "$TOPOLOGY" == multihost ]]; then
  COMPOSE=(docker compose -p tk8s -f deploy/docker-compose.multihost.yml)
else
  COMPOSE=(docker compose -p tk8s -f deploy/docker-compose.yml)
fi
SOCK="$REPO/run/signer.sock"

declare -a RESULT_LINES=()
FAILED=0
pass() { echo "PASS $1: $2"; RESULT_LINES+=("PASS  $1  $2"); }
fail() { echo "FAIL $1: $2"; RESULT_LINES+=("FAIL  $1  $2"); FAILED=1; }
section() { echo; echo "================ $* ================"; }
now_ms() { date +%s%3N; }

b64d() { local s; s="$(printf '%s' "$1" | tr '_-' '/+')"; while (( ${#s} % 4 )); do s="$s="; done; printf '%s' "$s" | base64 -d; }
jwt_header() { b64d "$(cut -d. -f1 <<<"$1")"; }
jwt_claims() { b64d "$(cut -d. -f2 <<<"$1")"; }
tokenreview() { # token [audience]
  local aud='[]'
  [[ -n "${2:-}" ]] && aud="[\"$2\"]"
  jq -n --arg t "$1" --argjson a "$aud" '{apiVersion:"authentication.k8s.io/v1",kind:"TokenReview",spec:{token:$t,audiences:$a}}' \
    | K create -o json -f -
}
PROBE_IMG=frost-k8s/probe:dev
LBNET=tk8s_lb-net
SIGNET=tk8s_signer-net
LB_TLS=(-cert /tls/lb/tls.crt -key /tls/lb/tls.key -ca /tls/ca.crt)
# probe_on <network> <probe args...>: run the test-only probe in a throwaway
# container attached to <network> ("bridge", a compose network, or
# "container:<name>" to share another container's network namespace).
probe_on() { local net="$1"; shift; docker run --rm --network "$net" --user "$FROST_UID" -v "$REPO/secrets/tls:/tls:ro" "$PROBE_IMG" "$@"; }
# replica_keys <lb-net ip>: FetchKeys on one coordinator replica, as nginx would (mTLS "lb").
replica_keys() { probe_on "$LBNET" fetchkeys "$1:9090" "${LB_TLS[@]}"; }
# sa_claims: a valid, policy-compliant claims segment (so a reachable Sign WOULD succeed).
sa_claims() {
  local now; now=$(date +%s)
  jq -cn --argjson now "$now" '{aud:["https://kubernetes.default.svc.cluster.local"],exp:($now+600),iat:$now,nbf:$now,iss:"https://kubernetes.default.svc.cluster.local",sub:"system:serviceaccount:default:default","kubernetes.io":{namespace:"default",serviceaccount:{name:"default",uid:"00000000-0000-0000-0000-000000000000"}}}' \
    | base64 -w0 | tr '+/' '-_' | tr -d '='
}
# signer_ctl stop|start ID... | audit: control signers wherever they run.
signer_ctl() {
  if [[ "$TOPOLOGY" == single ]]; then
    local verb="$1"; shift
    case "$verb" in
      stop|start) for i in "$@"; do docker "$verb" "tk8s-signer-$i-1" >/dev/null; done ;;
      audit) : ;;  # audit logs are already under audit/ via bind mounts
    esac
    return 0
  fi
  CTL_SEQ=$((CTL_SEQ + 1))
  local n=$CTL_SEQ
  echo "$*" > "$CTL/req-$n.tmp" && mv "$CTL/req-$n.tmp" "$CTL/req-$n"
  for _ in $(seq 1 1200); do
    if [[ -f "$CTL/done-$n" ]]; then
      grep -q '^ok' "$CTL/done-$n" || die "control request $n ($*) failed: $(cat "$CTL/done-$n")"
      return 0
    fi
    sleep 0.1
  done
  die "control request $n ($*) was not served within 120s (is test/e2e/multihost.sh running?)"
}
coord_logs() { "${COMPOSE[@]}" logs --no-color --no-log-prefix grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 2>/dev/null; }

teardown() {
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
# Generated key material (CA key, TLS keys, all 5 shares) must not outlive the
# run in the working tree (I10, T11). Audit logs are kept with the results.
wipe_secrets() {
  [[ -d audit ]] && cp -r audit "$RESULTS/audit" 2>/dev/null || true
  rm -rf secrets audit bin/e2e
  sudo rm -rf run
}
on_exit() {
  local rc=$?
  if [[ $KEEP == 0 ]]; then teardown; wipe_secrets; echo "cluster, stack and generated secrets removed"; fi
  exit $rc
}

section "Environment"
echo "git commit: $SHA"
echo "date (UTC): $TS"
uname -a
echo "cpus: $(nproc)"; free -h | head -2
docker version --format 'docker engine {{.Server.Version}}'
kind version; kubectl version --client | head -1; go version
echo "verify strategy: $VERIFY_STRATEGY, sign deadline: $SIGN_DEADLINE"

section "Setup: fresh certs, key ceremony, signer stack"
teardown
if [[ "$TOPOLOGY" == multihost ]]; then
  # deploy.sh placed ONLY public-meta, coordinator certs and multihost.env here.
  [[ -f secrets/keys/public-meta.json && -f secrets/multihost.env ]] || die "run deploy/multihost/deploy.sh first"
  [[ -z "$(find secrets -name 'share*' -o -name 'ca.key' -o -path '*signer-*')" ]] || die "coordinator host holds share/CA/signer material"
  rm -rf audit bin/e2e; sudo rm -rf run
  set -a; . secrets/multihost.env; set +a
  rm -rf "$CTL"; mkdir -p "$CTL"
else
  rm -rf secrets audit bin/e2e; sudo rm -rf run
fi
trap on_exit EXIT
# run/ holds the signer socket. It must be root:root 0700: nginx forces the
# socket itself to 0666, so the directory is the access control (N36).
sudo install -d -o root -g root -m 0700 run
mkdir -p bin/e2e
for i in 1 2 3 4 5; do mkdir -p "audit/signer-$i"; done
if [[ "$TOPOLOGY" == single ]]; then scripts/gen-certs.sh --out secrets; fi
go build -o bin/e2e/dealer ./cmd/dealer
go build -o bin/e2e/probe ./test/e2e/probe
docker build -q -f test/e2e/Dockerfile.probe -t "$PROBE_IMG" . >/dev/null
if [[ "$TOPOLOGY" == single ]]; then bin/e2e/dealer --out secrets/keys; fi
KID="$(jq -r .kid secrets/keys/public-meta.json)"
if [[ "$TOPOLOGY" == multihost ]]; then
  SIGNER_ADDRS=()
  IFS=, read -r -a _eps <<<"$SIGNER_ENDPOINTS"
  for e in "${_eps[@]}"; do SIGNER_ADDRS+=("${e#*=https://}"); done
else
  SIGNER_ADDRS=(172.30.2.21:8443 172.30.2.22:8443 172.30.2.23:8443 172.30.2.24:8443 172.30.2.25:8443)
fi
echo "topology: $TOPOLOGY; signer addresses: ${SIGNER_ADDRS[*]}"
echo "kid: $KID"
"${COMPOSE[@]}" build -q
"${COMPOSE[@]}" up -d
# The socket is 0600 root:root (nginx umask 077), so host-side calls need root.
for _ in $(seq 1 60); do sudo test -S "$SOCK" && sudo bin/e2e/probe fetchkeys "unix://$SOCK" >/dev/null 2>&1 && break; sleep 1; done
sudo bin/e2e/probe fetchkeys "unix://$SOCK" || die "signer stack did not come up"
"${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.State}}'

section "Setup: kind cluster (apiserver signs only via $SOCK)"
sed "s#__REPO__#$REPO#g" test/e2e/kind-config.yaml.tmpl > "$RESULTS/kind-config.yaml"
kind create cluster --config "$RESULTS/kind-config.yaml" --wait 300s
CP="$CLUSTER-control-plane"
echo "server version: $(K version -o json | jq -r .serverVersion.gitVersion)"
echo "node image: $(docker inspect -f '{{.Image}}' "$CP")"
APISERVER_CMD="$(docker exec "$CP" cat /etc/kubernetes/manifests/kube-apiserver.yaml)"
KCM_CMD="$(docker exec "$CP" cat /etc/kubernetes/manifests/kube-controller-manager.yaml)"
echo "apiserver service-account flags:"; grep -E 'service-account' <<<"$APISERVER_CMD"
echo "controller-manager service-account flags:"; grep -E 'service-account' <<<"$KCM_CMD" || true
if grep -qE 'service-account-(signing-)?key-file' <<<"$APISERVER_CMD" || grep -q 'service-account-private-key-file' <<<"$KCM_CMD"; then
  fail SETUP "an in-tree service account signing/verification key flag is still present"
elif grep -q "service-account-signing-endpoint=/var/run/frost-k8s/signer.sock" <<<"$APISERVER_CMD"; then
  pass SETUP "apiserver uses only --service-account-signing-endpoint; no in-tree SA key flags on apiserver or controller-manager"
else
  fail SETUP "signing endpoint flag missing"
fi
# kubeadm still generates sa.key/sa.pub; delete them to prove nothing uses them.
docker exec "$CP" rm -f /etc/kubernetes/pki/sa.key /etc/kubernetes/pki/sa.pub
echo "deleted /etc/kubernetes/pki/sa.{key,pub} from the control-plane node"
K wait --for=condition=Ready pods --all -n kube-system --timeout=240s
K get pods -n kube-system -o wide

section "E1: kubectl create token default -> RS256, threshold kid"
TOKEN1="$(K create token default)"
H1="$(jwt_header "$TOKEN1")"; C1="$(jwt_claims "$TOKEN1")"
echo "header: $H1"; echo "claims: $C1"
if [[ "$(jq -r .alg <<<"$H1")" == RS256 && "$(jq -r .kid <<<"$H1")" == "$KID" && "$(jq -r 'keys|join(",")' <<<"$H1")" == "alg,kid,typ" ]]; then
  pass E1 "alg=RS256 kid=$KID (equals public-meta.json)"
else fail E1 "header $H1, want RS256 / $KID"; fi

section "E2: TokenReview of that token"
TR="$(tokenreview "$TOKEN1")"
jq -c .status <<<"$TR"
if [[ "$(jq -r .status.authenticated <<<"$TR")" == true && "$(jq -r .status.user.username <<<"$TR")" == system:serviceaccount:default:default ]]; then
  pass E2 "authenticated=true username=system:serviceaccount:default:default"
else fail E2 "$(jq -c .status <<<"$TR")"; fi

section "E3 + (a) + (c): pod with projected token calls the API"
K apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: e3-client
  namespace: default
spec:
  terminationGracePeriodSeconds: 0
  containers:
  - name: curl
    image: curlimages/curl:8.11.1
    command: ["sleep", "7200"]
    volumeMounts:
    - name: projected
      mountPath: /var/run/secrets/tokens
      readOnly: true
  volumes:
  - name: projected
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3607
EOF
K wait --for=condition=Ready pod/e3-client --timeout=240s
API_CODE="$(K exec e3-client -- sh -c 'curl -s -o /tmp/api.json -w "%{http_code}" --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api')"
WHOAMI="$(K exec e3-client -- sh -c 'curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $(cat /var/run/secrets/tokens/token)" -H "Content-Type: application/json" -X POST -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"SelfSubjectReview\"}" https://kubernetes.default.svc/apis/authentication.k8s.io/v1/selfsubjectreviews')"
echo "GET /api with automounted token: HTTP $API_CODE"
echo "SelfSubjectReview with projected token: $(jq -c .status.userInfo <<<"$WHOAMI")"
if [[ "$API_CODE" == 200 && "$(jq -r .status.userInfo.username <<<"$WHOAMI")" == system:serviceaccount:default:default ]]; then
  pass E3 "pod reached the API (HTTP 200) and authenticated as system:serviceaccount:default:default with its projected token"
else fail E3 "HTTP $API_CODE, whoami $(jq -c . <<<"$WHOAMI")"; fi

PTOKEN="$(K exec e3-client -- cat /var/run/secrets/tokens/token)"
PC="$(jwt_claims "$PTOKEN")"
echo "projected token header: $(jwt_header "$PTOKEN")"
echo "projected token claims: $PC"
EXP_IAT=$(( $(jq .exp <<<"$PC") - $(jq .iat <<<"$PC") ))
WARN_IAT=$(( $(jq '.["kubernetes.io"].warnafter // 0' <<<"$PC") - $(jq .iat <<<"$PC") ))
PTR="$(tokenreview "$PTOKEN")"
echo "projected token TokenReview: $(jq -c .status <<<"$PTR")"
echo "projected token exp - iat = ${EXP_IAT}s, warnafter - iat = ${WARN_IAT}s (policy/Metadata max = $(jq .max_token_expiration_seconds deploy/policy.json)s)"
if [[ "$(jq -r .status.authenticated <<<"$PTR")" == true && "$(jq -r '.["kubernetes.io"].pod.name' <<<"$PC")" == e3-client ]]; then
  pass REQ-a "kubelet-projected token issued and passes TokenReview; exp-iat=${EXP_IAT}s warnafter-iat=${WARN_IAT}s"
else fail REQ-a "projected token review $(jq -c .status <<<"$PTR")"; fi

NODE="$(jq -r '.["kubernetes.io"].node.name // empty' <<<"$PC")"
BOUND_OK=1
for spec in "Pod e3-client" "Node ${NODE:-$CLUSTER-worker}" "Secret e3-bound-secret"; do
  set -- $spec
  [[ "$1" == Secret ]] && K create secret generic e3-bound-secret --from-literal=k=v >/dev/null 2>&1 || true
  BT="$(K create token default --bound-object-kind "$1" --bound-object-name "$2" 2>&1)" || { echo "bound $1 token failed: $BT"; BOUND_OK=0; continue; }
  BC="$(jwt_claims "$BT")"
  BR="$(jq -r .status.authenticated <<<"$(tokenreview "$BT")")"
  echo "bound to $1/$2: kubernetes.io=$(jq -c '.["kubernetes.io"]' <<<"$BC") authenticated=$BR"
  [[ "$BR" == true ]] || BOUND_OK=0
done
if [[ $BOUND_OK == 1 && -n "$(jq -r '.["kubernetes.io"].warnafter // empty' <<<"$PC")" ]]; then
  pass REQ-c "policy accepted pod-, node- and secret-bound tokens and warnafter; all pass TokenReview"
else fail REQ-c "a bound token was refused or lacked expected claims"; fi

section "(b) audiences"
AT="$(K create token default --audience frost-e2e-allowed 2>&1)" && AOK=1 || AOK=0
if [[ $AOK == 1 ]]; then
  echo "allowlisted: aud=$(jwt_claims "$AT" | jq -c .aud) review=$(tokenreview "$AT" frost-e2e-allowed | jq -c '.status | {authenticated, audiences}')"
fi
BAD_OUT="$(K create token default --audience not-allowlisted 2>&1)" && BOK=1 || BOK=0
echo "not allowlisted: kubectl exit=$(( 1 - BOK )) output: $BAD_OUT"
sleep 1
BAD_LOG="$(coord_logs | grep '"msg":"sign failed"' | grep 'not-allowlisted' | grep 'is not allowed' | head -1 || true)"
signer_ctl audit
BAD_AUDIT="$(cat audit/signer-*/audit.log | jq -c 'select(.decision=="deny" and (.reason|test("not-allowlisted")))' | head -1)"
echo "coordinator log: $(cut -c1-400 <<<"$BAD_LOG")"
echo "signer audit:    $BAD_AUDIT"
# N33: the requester sees only the generic error; the reason is only in logs.
LEAK=0
for w in not-allowlisted "aud:" "signer-" policy "403" "valid shares"; do grep -qF -- "$w" <<<"$BAD_OUT" && { echo "requester-visible error leaks: $w"; LEAK=1; }; done
if [[ $AOK == 1 && $BOK == 0 && $LEAK == 0 && "$BAD_OUT" == *"token signing failed: threshold not met"* && -n "$BAD_LOG" && -n "$BAD_AUDIT" ]]; then
  pass REQ-b "allowlisted audience issued; non-allowlisted refused with generic error only (N33); reason in coordinator log and signer audit"
else fail REQ-b "allowed=$AOK refused=$(( 1 - BOK )) leak=$LEAK log=${BAD_LOG:+yes} audit=${BAD_AUDIT:+yes}"; fi

section "E4: Deployment with 20 replicas; controllers keep working"
KCM_RESTARTS0="$(K get pod -n kube-system -l component=kube-controller-manager -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
SCHED_RESTARTS0="$(K get pod -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
K create deployment e4-web --image=registry.k8s.io/pause:3.10 --replicas=20
K rollout status deployment/e4-web --timeout=300s
READY="$(K get deployment e4-web -o jsonpath='{.status.readyReplicas}')"
KCM_RESTARTS1="$(K get pod -n kube-system -l component=kube-controller-manager -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
SCHED_RESTARTS1="$(K get pod -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
signer_ctl audit
CTRL_SUBS="$(cat audit/signer-*/audit.log | jq -r 'select(.decision=="allow") | .sub' | grep -E 'kube-system:(deployment|replicaset)-controller' | sort | uniq -c || true)"
echo "readyReplicas=$READY; controller-manager restarts $KCM_RESTARTS0->$KCM_RESTARTS1; scheduler restarts $SCHED_RESTARTS0->$SCHED_RESTARTS1"
echo "threshold-signed controller tokens (signer audit logs, allow decisions):"; echo "$CTRL_SUBS"
echo "scheduler credential: $(docker exec "$CP" sh -c 'grep -c client-certificate-data /etc/kubernetes/scheduler.conf') client-certificate entry in scheduler.conf (x509, not an SA token)"
if [[ "$READY" == 20 && "$KCM_RESTARTS0" == "$KCM_RESTARTS1" && "$SCHED_RESTARTS0" == "$SCHED_RESTARTS1" && -n "$CTRL_SUBS" ]]; then
  pass E4 "20/20 Ready; deployment/replicaset controllers used threshold-signed tokens; no KCM/scheduler restarts"
else fail E4 "ready=$READY kcm $KCM_RESTARTS0->$KCM_RESTARTS1 sched $SCHED_RESTARTS0->$SCHED_RESTARTS1"; fi

section "E5: /openid/v1/jwks serves the group key"
JWKS="$(K get --raw /openid/v1/jwks)"
echo "$JWKS" | jq -c '.keys[] | {kid, kty, alg, use, e, n_prefix: .n[0:16]}'
JWK_N_HEX="$(jq -r '.keys[0].n' <<<"$JWKS" | { read -r n; b64d "$n" | od -An -tx1 | tr -d ' \n'; })"
META_N_HEX="$(jq -r .public_key_pkix secrets/keys/public-meta.json | base64 -d | openssl pkey -pubin -inform DER -noout -text 2>/dev/null | awk '/Modulus/{f=1;next} /Exponent/{f=0} f' | tr -d ' :\n' | sed 's/^00//')"
POD_JWKS_KID="$(K exec e3-client -- sh -c 'curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer $(cat /var/run/secrets/tokens/token)" https://kubernetes.default.svc/openid/v1/jwks' | jq -r '.keys[0].kid')"
echo "jwks modulus == public-meta.json modulus: $([[ "$JWK_N_HEX" == "$META_N_HEX" ]] && echo yes || echo NO)"
echo "jwks fetched from pod with its SA token (system:service-account-issuer-discovery): kid=$POD_JWKS_KID"
if [[ "$(jq '.keys|length' <<<"$JWKS")" == 1 && "$(jq -r '.keys[0].kid' <<<"$JWKS")" == "$KID" && "$(jq -r '.keys[0].alg' <<<"$JWKS")" == RS256 && "$JWK_N_HEX" == "$META_N_HEX" && "$POD_JWKS_KID" == "$KID" ]]; then
  pass E5 "JWKS has exactly the threshold group key (kid $KID, RS256, modulus matches)"
else fail E5 "jwks mismatch"; fi

section "E6: signer failures"
signer_ctl stop 4 5
T6A="$(K create token default --duration=10m 2>&1)" && E6A=1 || E6A=0
echo "2 signers down: issue ok=$E6A kid=$( [[ $E6A == 1 ]] && jwt_header "$T6A" | jq -r .kid)"
signer_ctl stop 3
S=$(now_ms)
E6B_OUT="$(K create token default --duration=10m 2>&1)" && E6B=1 || E6B=0
E6B_MS=$(( $(now_ms) - S ))
echo "3 signers down: issue ok=$E6B after ${E6B_MS}ms; kubectl said: $E6B_OUT"
sleep 1
echo "coordinator log: $(coord_logs | grep '"msg":"sign failed"' | tail -1 | cut -c1-600)"
OLD_REVIEW="$(tokenreview "$TOKEN1" | jq -r .status.authenticated)"
PROJ_REVIEW="$(tokenreview "$PTOKEN" | jq -r .status.authenticated)"
echo "previously issued tokens with 3 signers down: E1 token authenticated=$OLD_REVIEW, projected token authenticated=$PROJ_REVIEW"
if [[ $E6A == 1 && $E6B == 0 && "$E6B_OUT" == *"token signing failed: threshold not met"* && "$E6B_OUT" != *"signer-"* && "$OLD_REVIEW" == true && "$PROJ_REVIEW" == true ]]; then
  pass E6 "2 down: issued; 3 down: refused with threshold error (${E6B_MS}ms); old tokens still authenticate"
else fail E6 "2down=$E6A 3down=$E6B old=$OLD_REVIEW proj=$PROJ_REVIEW"; fi

section "E7: signer restart -> issuance recovers"
signer_ctl_start_t0() { S=$(now_ms); signer_ctl start 3 4 5; }
signer_ctl_start_t0
TRIES=0
until K create token default --duration=10m >/dev/null 2>&1; do TRIES=$((TRIES + 1)); (( TRIES > 600 )) && break; sleep 0.1; done
E7_MS=$(( $(now_ms) - S ))
if [[ "$TOPOLOGY" == single ]]; then READY_TS="$(docker logs tk8s-signer-3-1 2>&1 | grep '"signer ready"' | tail -1 | jq -r .time)"; else READY_TS="(journald on signer hosts; start acknowledged via control channel)"; fi
echo "signer start request -> first successful token: ${E7_MS}ms ($TRIES failed attempts; includes one kubectl process start per attempt$( [[ $TOPOLOGY == multihost ]] && echo '; multihost: also includes control-channel latency (operator polls every 0.5s) and systemctl start over multipass exec'))"
echo "signer-3 last 'signer ready' log: $READY_TS"
if (( TRIES <= 600 )); then pass E7 "issuance recovered ${E7_MS}ms after signer start request"; else fail E7 "did not recover within 60s"; fi

section "E8: coordinator replicas and nginx failover"
REF="$(sudo bin/e2e/probe fetchkeys "unix://$SOCK")"
echo "via socket:   $REF"
SAME=1
for ip in 172.30.1.11 172.30.1.12 172.30.1.13; do
  R="$(replica_keys "$ip")"; echo "replica $ip (mTLS lb, from lb-net): $R"; [[ "$R" == "$REF" ]] || SAME=0
done
docker stop tk8s-grpc-proxy-1-1 tk8s-grpc-proxy-2-1 >/dev/null
T8A="$(K create token default --duration=10m 2>&1)" && E8A=1 || E8A=0
echo "replicas 1,2 stopped: issue ok=$E8A kid=$( [[ $E8A == 1 ]] && jwt_header "$T8A" | jq -r .kid)"
docker start tk8s-grpc-proxy-1-1 tk8s-grpc-proxy-2-1 >/dev/null
sleep 2
FAILS=0; N=0
for r in 1 2 3; do
  timeout 60 docker restart -t 1 "tk8s-grpc-proxy-$r-1" >/dev/null &
  RPID=$!
  for _ in 1 2 3 4 5; do N=$((N + 1)); K create token default --duration=10m >/dev/null 2>&1 || FAILS=$((FAILS + 1)); done
  # Wait for THIS restart only: a bare `wait` also waits for the logging
  # process substitution (exec > >(tee ...)) and never returns (bash >= 5.1).
  wait "$RPID" || echo "restart of replica $r exited $?"
  sleep 1
done
echo "rolling restart of all 3 replicas: $FAILS/$N token requests failed"
for ip in 172.30.1.11 172.30.1.12 172.30.1.13; do
  [[ "$(replica_keys "$ip")" == "$REF" ]] || SAME=0
done
if [[ $SAME == 1 && $E8A == 1 && $FAILS == 0 ]]; then
  pass E8 "3 replicas serve identical FetchKeys; issuance survives 2 replicas down and a rolling restart (0/$N failed)"
else fail E8 "identical=$SAME twoDown=$E8A rollingFails=$FAILS/$N"; fi

section "N1: nothing but nginx (mTLS lb) can call Sign / FetchKeys"
CL="$(sa_claims)"
N1_OK=1
expect_fail() { # description, probe args...
  local d="$1"; shift
  if out="$(probe_on "$@" 2>&1)"; then echo "  UNEXPECTED SUCCESS: $d: $out"; N1_OK=0; else echo "  refused: $d: $(tail -1 <<<"$out" | cut -c1-160)"; fi
}
echo "control (lb-net, lb cert): $(probe_on "$LBNET" sign 172.30.1.11:9090 "$CL" "${LB_TLS[@]}" 2>&1 | cut -c1-120)"
for ip in 172.30.1.11 172.30.1.12 172.30.1.13; do
  expect_fail "default bridge -> $ip Sign (lb cert)"      bridge   sign "$ip:9090" "$CL" "${LB_TLS[@]}"
  expect_fail "default bridge -> $ip FetchKeys (lb cert)" bridge   fetchkeys "$ip:9090" "${LB_TLS[@]}"
  expect_fail "lb-net, no client cert -> $ip Sign"         "$LBNET" sign "$ip:9090" "$CL" -ca /tls/ca.crt
  expect_fail "lb-net, no client cert -> $ip FetchKeys"    "$LBNET" fetchkeys "$ip:9090" -ca /tls/ca.crt
  expect_fail "lb-net, coordinator cert -> $ip Sign"       "$LBNET" sign "$ip:9090" "$CL" -cert /tls/coordinator/tls.crt -key /tls/coordinator/tls.key -ca /tls/ca.crt
  expect_fail "lb-net, signer-1 cert -> $ip FetchKeys"     "$LBNET" fetchkeys "$ip:9090" -cert /tls/signer-1/tls.crt -key /tls/signer-1/tls.key -ca /tls/ca.crt
  expect_fail "lb-net, plaintext gRPC -> $ip Sign"         "$LBNET" sign "$ip:9090" "$CL"
done
for i in 1 2 3 4 5; do
  expect_fail "lb-net -> signer-$i ${SIGNER_ADDRS[$((i-1))]} TCP" "$LBNET" connect "${SIGNER_ADDRS[$((i-1))]}"
done
if [[ "$TOPOLOGY" == multihost ]]; then
  for r in 1 2 3; do
    expect_fail "uplink -> coordinator 172.30.3.1$r:9090 (gRPC bound to lb-net only)" tk8s_uplink connect "172.30.3.1$r:9090"
  done
fi
if [[ $N1_OK == 1 ]]; then pass N1 "default-bridge and lb-net containers without the lb cert cannot call Sign/FetchKeys; lb-net cannot reach signers"
else fail N1 "an unauthorised caller reached Sign/FetchKeys"; fi

section "N2: no component port accepts a TCP connection from the host"
echo "published ports of tk8s containers:"; docker ps --filter label=com.docker.compose.project=tk8s --format '  {{.Names}}: ports=[{{.Ports}}]'
echo "\$ sudo ss -tlnp (VM host):"; sudo ss -tlnp | sed 's/^/  /'
N2_OK=1; N2_N=0
for c in $(docker ps --filter label=com.docker.compose.project=tk8s --format '{{.Names}}'); do
  ports="$(docker exec "$c" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk 'NR>1 && $4=="0A" {split($2,a,":"); print a[2]}' | while read -r h; do echo $((16#$h)); done | sort -un | tr '\n' ' ')"
  ips="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$c")"
  echo "  $c listens on [${ports:-none}] at [$ips]"
  for ip in $ips; do for port in $ports; do
    N2_N=$((N2_N + 1))
    if bin/e2e/probe connect "$ip:$port" -timeout 2s >/dev/null 2>&1; then echo "    ACCEPTED from host: $ip:$port"; N2_OK=0; fi
  done; done
done
echo "  (unlisted high ports are Docker's embedded DNS resolver for 127.0.0.11 inside each container; 'ports=[80/tcp]' on nginx is image EXPOSE metadata, not a published port)"
SOCK_MODE="$(sudo stat -c '%U:%G %a' "$SOCK")"
DIR_MODE="$(sudo stat -c '%U:%G %a' "$(dirname "$SOCK")")"
echo "  the only entry point is the Unix socket $SOCK: socket $SOCK_MODE (nginx forces 0666), directory $DIR_MODE"
if NR_OUT="$(bin/e2e/probe fetchkeys "unix://$SOCK" 2>&1)"; then echo "  UNEXPECTED: non-root user $(id -un) called FetchKeys on the socket"; N2_OK=0
else echo "  non-root user $(id -un) -> socket: refused ($(tail -1 <<<"$NR_OUT" | cut -c1-120))"; fi
[[ "$DIR_MODE" == "root:root 700" ]] || { echo "  socket directory is not root:root 700"; N2_OK=0; }
if [[ "$TOPOLOGY" == multihost ]]; then
  echo "  multihost: this host IS the coordinator host, so the signer firewalls admit its address (coordinator traffic is NAT'd to it);"
  echo "  the signer's mTLS is then the control. TLS to each signer's /healthz from this host:"
  for i in 1 2 3 4 5; do
    a="${SIGNER_ADDRS[$((i-1))]}"
    if bin/e2e/probe https "$a" -ca secrets/tls/ca.crt -servername "signer-$i" -timeout 3s >/dev/null 2>&1; then echo "    UNEXPECTED: $a accepted a client with no cert"; N2_OK=0; else echo "    $a no client cert: refused"; fi
    if bin/e2e/probe https "$a" -ca secrets/tls/ca.crt -servername "signer-$i" -cert secrets/tls/lb/tls.crt -key secrets/tls/lb/tls.key -timeout 3s >/dev/null 2>&1; then echo "    UNEXPECTED: $a accepted the lb cert"; N2_OK=0; else echo "    $a lb cert: refused"; fi
    if bin/e2e/probe https "$a" -ca secrets/tls/ca.crt -servername "signer-$i" -cert secrets/tls/coordinator/tls.crt -key secrets/tls/coordinator/tls.key -timeout 3s >/dev/null 2>&1; then echo "    $a coordinator cert: accepted (control)"; else echo "    CONTROL FAILED: $a refused the coordinator cert"; N2_OK=0; fi
  done
fi
if [[ $N2_OK == 1 && $N2_N -gt 0 ]]; then pass N2 "0 of $N2_N (container ip, listening port) pairs accept a TCP connection from the host; nothing published; socket dir root:root 0700, non-root refused"
else fail N2 "host reached a component port or the socket is not root-only (tried $N2_N)"; fi

section "N3: nginx cannot open a TCP connection to any signer"
N3_OK=1
for i in 1 2 3 4 5; do
  tgts=("${SIGNER_ADDRS[$((i-1))]}")
  [[ "$TOPOLOGY" == single ]] && tgts+=("signer-$i:8443")
  for tgt in "${tgts[@]}"; do
    if out="$(probe_on container:tk8s-coordinator-lb-1 connect "$tgt" -timeout 2s 2>&1)"; then echo "  REACHABLE from nginx netns: $tgt"; N3_OK=0; else echo "  nginx netns -> $tgt: $(cut -c1-110 <<<"$out")"; fi
  done
done
echo "  nginx networks: $(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' tk8s-coordinator-lb-1)"
if [[ $N3_OK == 1 ]]; then pass N3 "nginx (its network namespace) reaches no signer by IP or name"; else fail N3 "nginx reached a signer"; fi

if [[ "$TOPOLOGY" == multihost ]]; then
  section "N4: coordinator egress reaches only the signer ports"
  N4_OK=1
  C1=container:tk8s-grpc-proxy-1-1
  for i in 1 2 3 4 5; do
    if probe_on "$C1" connect "${SIGNER_ADDRS[$((i-1))]}" -timeout 3s >/dev/null 2>&1; then echo "  coordinator -> signer-$i ${SIGNER_ADDRS[$((i-1))]}: allowed (control)"; else echo "  CONTROL FAILED: coordinator cannot reach signer-$i"; N4_OK=0; fi
  done
  S1HOST="${SIGNER_ADDRS[0]%%:*}"
  for tgt in 1.1.1.1:443 8.8.8.8:53 "$S1HOST:22" "$S1HOST:8445" 192.168.252.1:22; do
    if out="$(probe_on "$C1" connect "$tgt" -timeout 3s 2>&1)"; then echo "  UNEXPECTED: coordinator reached $tgt"; N4_OK=0; else echo "  coordinator -> $tgt: blocked ($(cut -c1-90 <<<"$out"))"; fi
  done
  echo "  FROST-EGRESS chain:"; sudo iptables -S FROST-EGRESS | sed 's/^/    /'
  if [[ $N4_OK == 1 ]]; then pass N4 "coordinators reach exactly the 5 signer ports; internet, SSH and other ports blocked"; else fail N4 "coordinator egress not restricted as expected"; fi
fi

section "(d) strategy used by every coordinator"
READY_LINES="$(coord_logs | grep '"msg":"coordinator ready"' || true)"
jq -rc '{strategy, deadline, signers, kid}' <<<"$READY_LINES" | sort | uniq -c
N_READY="$(grep -c . <<<"$READY_LINES" || true)"
N_STRICT="$(jq -r 'select(.strategy=="strict" and .deadline=="2s" and .kid=="'"$KID"'") | .strategy' <<<"$READY_LINES" | grep -c strict || true)"
if [[ "$N_READY" -ge 3 && "$N_READY" == "$N_STRICT" ]]; then
  pass REQ-d "all $N_READY coordinator starts (incl. restarts) ran strategy=strict, deadline=2s, kid=$KID"
else fail REQ-d "$N_STRICT of $N_READY coordinator starts were strict"; fi

section "Signer policy decisions (all signers, from audit logs)"
signer_ctl audit
cat audit/signer-*/audit.log | jq -r '.decision' | sort | uniq -c
cat audit/signer-*/audit.log | jq -r 'select(.decision=="deny") | .reason' | sed 's/[0-9]\{6,\}/N/g' | sort | uniq -c | head -20

section "Summary"
echo "git commit: $SHA"
echo "kubernetes: $(K version -o json | jq -r .serverVersion.gitVersion), node image $(docker inspect -f '{{.Image}}' "$CP")"
printf '%s\n' "${RESULT_LINES[@]}"
[[ $KEEP == 1 ]] && echo "--keep: cluster and secrets/ left in place; run 'make e2e-down' (T11 fails until then)"
if [[ $FAILED -ne 0 ]]; then echo "E2E: FAIL"; exit 1; fi
echo "E2E: PASS"
