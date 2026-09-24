#!/bin/bash
# =============================================================
# Baseline K8s RS256 Signing — Benchmark Suite
# Run this on the BASELINE minikube cluster
# =============================================================

echo "================================================"
echo "Baseline K8s RS256 Signing — Benchmark Suite"
echo "================================================"
echo "Date: $(date)"
echo "Environment: Minikube, Docker driver, macOS"
echo "Cluster: Baseline RS256 single-key signing"
echo ""

RESULTS="benchmark/results/baseline_benchmark_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p benchmark/results
exec > >(tee $RESULTS) 2>&1

# Verify baseline is active
echo "[ 0 ] Verifying RS256 baseline is active"
echo "─────────────────────────────────────"
HEADER=$(kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null)
echo "  JWT Header: $HEADER"
if echo "$HEADER" | grep -q "RS256"; then
  echo "  ✅ RS256 baseline confirmed"
else
  echo "  ❌ RS256 NOT active — wrong cluster?"
  exit 1
fi

echo ""
echo "[ 1 ] Single Token Latency — Cold Start (5 runs)"
echo "─────────────────────────────────────"
for i in $(seq 1 5); do
  START=$(date +%s%N)
  kubectl create token default > /dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  echo "  Run $i: ${MS}ms"
  sleep 2
done

echo ""
echo "[ 2 ] Single Token Latency — Warm Path (20 runs)"
echo "─────────────────────────────────────"
TIMES=()
for i in $(seq 1 20); do
  START=$(date +%s%N)
  kubectl create token default > /dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  TIMES+=($MS)
  echo "  Run $i: ${MS}ms"
done

SORTED=($(printf '%s\n' "${TIMES[@]}" | sort -n))
COUNT=${#SORTED[@]}
P50=${SORTED[$((COUNT * 50 / 100))]}
P95=${SORTED[$((COUNT * 95 / 100))]}
P99=${SORTED[$((COUNT * 99 / 100))]}
MIN=${SORTED[0]}
MAX=${SORTED[$((COUNT - 1))]}
SUM=0
for t in "${TIMES[@]}"; do SUM=$((SUM + t)); done
AVG=$((SUM / COUNT))
echo "  ─────────────────"
echo "  Min: ${MIN}ms | Avg: ${AVG}ms | P50: ${P50}ms | P95: ${P95}ms | P99: ${P99}ms | Max: ${MAX}ms"

echo ""
echo "[ 3 ] 100 Token Sequential Throughput"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 100); do
  kubectl create token default > /dev/null
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
AVG_MS=$(( TOTAL_MS / 100 ))
TPUT=$(( 100 * 1000 / TOTAL_MS ))
echo "  Total: ${TOTAL_MS}ms | Avg: ${AVG_MS}ms/token | Throughput: ${TPUT} tok/s"

echo ""
echo "[ 4 ] 500 Token Sequential Throughput"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 500); do
  kubectl create token default > /dev/null
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
AVG_MS=$(( TOTAL_MS / 500 ))
TPUT=$(( 500 * 1000 / TOTAL_MS ))
echo "  Total: ${TOTAL_MS}ms | Avg: ${AVG_MS}ms/token | Throughput: ${TPUT} tok/s"

echo ""
echo "[ 5 ] 1000 Token Sequential Throughput"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 1000); do
  kubectl create token default > /dev/null
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
AVG_MS=$(( TOTAL_MS / 1000 ))
TPUT=$(( 1000 * 1000 / TOTAL_MS ))
echo "  Total: ${TOTAL_MS}ms | Avg: ${AVG_MS}ms/token | Throughput: ${TPUT} tok/s"

echo ""
echo "[ 6 ] Concurrent Requests — 10 parallel"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 10); do
  kubectl create token default > /dev/null &
done
wait
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  10 concurrent: ${TOTAL_MS}ms total | $(( 10 * 1000 / TOTAL_MS )) tok/s"

echo ""
echo "[ 7 ] Concurrent Requests — 20 parallel"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 20); do
  kubectl create token default > /dev/null &
done
wait
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  20 concurrent: ${TOTAL_MS}ms total | $(( 20 * 1000 / TOTAL_MS )) tok/s"

echo ""
echo "[ 8 ] Concurrent Requests — 50 parallel"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 50); do
  kubectl create token default > /dev/null &
done
wait
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  50 concurrent: ${TOTAL_MS}ms total | $(( 50 * 1000 / TOTAL_MS )) tok/s"

echo ""
echo "[ 9 ] Memory Usage — Idle"
echo "─────────────────────────────────────"
echo "  kube-apiserver:"
docker exec baseline bash -c "ps aux | grep kube-apiserver | grep -v grep | awk '{print \"    RSS: \" \$6/1024 \" MB\"}'" 2>/dev/null || echo "    N/A"

echo ""
echo "[ 10 ] Memory Usage — Under Load"
echo "─────────────────────────────────────"
for i in $(seq 1 50); do kubectl create token default > /dev/null & done
sleep 2
echo "  kube-apiserver under load:"
docker exec baseline bash -c "ps aux | grep kube-apiserver | grep -v grep | awk '{print \"    RSS: \" \$6/1024 \" MB\"}'" 2>/dev/null || echo "    N/A"
wait

echo ""
echo "[ 11 ] 100 Pod Scaling"
echo "─────────────────────────────────────"
kubectl delete deployment scale-test --ignore-not-found > /dev/null
START=$(date +%s%N)
kubectl create deployment scale-test --image=nginx --replicas=100 > /dev/null
kubectl rollout status deployment/scale-test --timeout=300s
END=$(date +%s%N)
MS=$(( (END - START) / 1000000 ))
echo "  100 pods ready: ${MS}ms"
kubectl delete deployment scale-test --ignore-not-found > /dev/null

echo ""
echo "================================================"
echo "Baseline Benchmark Complete"
echo "Results saved to: $RESULTS"
echo "================================================"
