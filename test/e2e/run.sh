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
CLUSTER=tk8s
KCTX="kind-$CLUSTER"
K() { kubectl --context "$KCTX" "$@"; }
COMPOSE=(docker compose -p tk8s -f deploy/docker-compose.yml)
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
coord_logs() { "${COMPOSE[@]}" logs --no-color grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 2>/dev/null; }

teardown() {
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
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
rm -rf secrets run audit bin/e2e
mkdir -p run bin/e2e
for i in 1 2 3 4 5; do mkdir -p "audit/signer-$i"; done
scripts/gen-certs.sh --out secrets
go build -o bin/e2e/dealer ./cmd/dealer
go build -o bin/e2e/fetchkeys ./test/e2e/fetchkeys
bin/e2e/dealer --out secrets/keys
KID="$(jq -r .kid secrets/keys/public-meta.json)"
echo "kid: $KID"
"${COMPOSE[@]}" build -q
"${COMPOSE[@]}" up -d
for _ in $(seq 1 60); do [[ -S "$SOCK" ]] && bin/e2e/fetchkeys "unix://$SOCK" >/dev/null 2>&1 && break; sleep 1; done
bin/e2e/fetchkeys "unix://$SOCK" || die "signer stack did not come up"
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
BAD_LOG="$(coord_logs | grep 'not-allowlisted' | grep 'is not allowed' | head -1 || true)"
echo "coordinator log: $BAD_LOG"
if [[ $AOK == 1 && $BOK == 0 && -n "$BAD_LOG" ]]; then
  pass REQ-b "allowlisted audience issued; non-allowlisted refused, coordinator log names the signer policy rule"
else fail REQ-b "allowed=$AOK refused=$(( 1 - BOK )) log=${BAD_LOG:-none}"; fi

section "E4: Deployment with 20 replicas; controllers keep working"
KCM_RESTARTS0="$(K get pod -n kube-system -l component=kube-controller-manager -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
SCHED_RESTARTS0="$(K get pod -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
K create deployment e4-web --image=registry.k8s.io/pause:3.10 --replicas=20
K rollout status deployment/e4-web --timeout=300s
READY="$(K get deployment e4-web -o jsonpath='{.status.readyReplicas}')"
KCM_RESTARTS1="$(K get pod -n kube-system -l component=kube-controller-manager -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
SCHED_RESTARTS1="$(K get pod -n kube-system -l component=kube-scheduler -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')"
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
docker stop tk8s-signer-4-1 tk8s-signer-5-1 >/dev/null
T6A="$(K create token default --duration=10m 2>&1)" && E6A=1 || E6A=0
echo "2 signers down: issue ok=$E6A kid=$( [[ $E6A == 1 ]] && jwt_header "$T6A" | jq -r .kid)"
docker stop tk8s-signer-3-1 >/dev/null
S=$(now_ms)
E6B_OUT="$(K create token default --duration=10m 2>&1)" && E6B=1 || E6B=0
E6B_MS=$(( $(now_ms) - S ))
echo "3 signers down: issue ok=$E6B after ${E6B_MS}ms; kubectl said: $E6B_OUT"
sleep 1
echo "coordinator log: $(coord_logs | grep 'threshold not met' | tail -1)"
OLD_REVIEW="$(tokenreview "$TOKEN1" | jq -r .status.authenticated)"
PROJ_REVIEW="$(tokenreview "$PTOKEN" | jq -r .status.authenticated)"
echo "previously issued tokens with 3 signers down: E1 token authenticated=$OLD_REVIEW, projected token authenticated=$PROJ_REVIEW"
if [[ $E6A == 1 && $E6B == 0 && "$OLD_REVIEW" == true && "$PROJ_REVIEW" == true ]]; then
  pass E6 "2 down: issued; 3 down: refused with threshold error (${E6B_MS}ms); old tokens still authenticate"
else fail E6 "2down=$E6A 3down=$E6B old=$OLD_REVIEW proj=$PROJ_REVIEW"; fi

section "E7: signer restart -> issuance recovers"
S=$(now_ms)
docker start tk8s-signer-3-1 tk8s-signer-4-1 tk8s-signer-5-1 >/dev/null
TRIES=0
until K create token default --duration=10m >/dev/null 2>&1; do TRIES=$((TRIES + 1)); (( TRIES > 600 )) && break; sleep 0.1; done
E7_MS=$(( $(now_ms) - S ))
READY_TS="$(docker logs tk8s-signer-3-1 2>&1 | grep '"signer ready"' | tail -1 | jq -r .time)"
echo "docker start -> first successful token: ${E7_MS}ms ($TRIES failed attempts; includes kubectl process start per attempt)"
echo "signer-3 last 'signer ready' log: $READY_TS"
if (( TRIES <= 600 )); then pass E7 "issuance recovered ${E7_MS}ms after docker start"; else fail E7 "did not recover within 60s"; fi

section "E8: coordinator replicas and nginx failover"
REF="$(bin/e2e/fetchkeys "unix://$SOCK")"
echo "via socket:   $REF"
SAME=1
for ip in 172.30.0.11 172.30.0.12 172.30.0.13; do
  R="$(bin/e2e/fetchkeys "$ip:9090")"; echo "replica $ip: $R"; [[ "$R" == "$REF" ]] || SAME=0
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
for ip in 172.30.0.11 172.30.0.12 172.30.0.13; do
  [[ "$(bin/e2e/fetchkeys "$ip:9090")" == "$REF" ]] || SAME=0
done
if [[ $SAME == 1 && $E8A == 1 && $FAILS == 0 ]]; then
  pass E8 "3 replicas serve identical FetchKeys; issuance survives 2 replicas down and a rolling restart (0/$N failed)"
else fail E8 "identical=$SAME twoDown=$E8A rollingFails=$FAILS/$N"; fi

section "(d) strategy used by every coordinator"
coord_logs | grep '"coordinator ready"' | jq -rc '{strategy, deadline, signers, kid}' | sort | uniq -c

section "Signer policy decisions (all signers, from audit logs)"
cat audit/signer-*/audit.log | jq -r '.decision' | sort | uniq -c
cat audit/signer-*/audit.log | jq -r 'select(.decision=="deny") | .reason' | sed 's/[0-9]\{6,\}/N/g' | sort | uniq -c | head -20

section "Summary"
echo "git commit: $SHA"
echo "kubernetes: $(K version -o json | jq -r .serverVersion.gitVersion), node image $(docker inspect -f '{{.Image}}' "$CP")"
printf '%s\n' "${RESULT_LINES[@]}"
if [[ $KEEP == 0 ]]; then teardown; echo "cluster and stack removed"; fi
if [[ $FAILED -ne 0 ]]; then echo "E2E: FAIL"; exit 1; fi
echo "E2E: PASS"
