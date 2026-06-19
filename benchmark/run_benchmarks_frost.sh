#!/bin/bash
# =============================================================
# FROST K8s Threshold Signing — Comprehensive Benchmark Suite
# Run this on the FROST minikube cluster
# =============================================================

echo "================================================"
echo "FROST K8s Threshold Signing — Benchmark Suite"
echo "================================================"
echo "Date: $(date)"
echo "Environment: Minikube, Docker driver, macOS"
echo "Cluster: FROST 3-of-5 threshold signing"
echo ""

RESULTS="benchmark/results/frost_benchmark_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p benchmark/results
exec > >(tee $RESULTS) 2>&1

# Verify FROST is active
echo "[ 0 ] Verifying FROST signing is active"
echo "─────────────────────────────────────"
HEADER=$(kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null)
echo "  JWT Header: $HEADER"
if echo "$HEADER" | grep -q "frost-k8s-v1"; then
  echo "  ✅ FROST signing confirmed (kid=frost-k8s-v1)"
else
  echo "  ❌ FROST signing NOT active — wrong cluster?"
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

# Calculate p50/p95/p99
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
echo "  coordinator-lb (nginx):"
docker stats deploy-coordinator-lb-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  grpc-proxy-1:"
docker stats deploy-grpc-proxy-1-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  grpc-proxy-2:"
docker stats deploy-grpc-proxy-2-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  grpc-proxy-3:"
docker stats deploy-grpc-proxy-3-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-1:"
docker stats deploy-signer-1-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-2:"
docker stats deploy-signer-2-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-3:"
docker stats deploy-signer-3-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-4:"
docker stats deploy-signer-4-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-5:"
docker stats deploy-signer-5-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"

echo ""
echo "[ 10 ] Memory Usage — Under Load (50 concurrent)"
echo "─────────────────────────────────────"
for i in $(seq 1 50); do kubectl create token default > /dev/null & done
sleep 2
echo "  grpc-proxy-1 (under load):"
docker stats deploy-grpc-proxy-1-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-1 (under load):"
docker stats deploy-signer-1-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
wait

echo ""
echo "[ 11 ] Signer Failure Tolerance — 2 of 5 killed"
echo "─────────────────────────────────────"
echo "  Killing signer-4 and signer-5..."
docker stop deploy-signer-4-1 deploy-signer-5-1 > /dev/null
sleep 2
TIMES=()
for i in $(seq 1 5); do
  START=$(date +%s%N)
  kubectl create token default > /dev/null
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  TIMES+=($MS)
  echo "  Run $i: ${MS}ms"
done
SUM=0
for t in "${TIMES[@]}"; do SUM=$((SUM + t)); done
AVG=$((SUM / ${#TIMES[@]}))
echo "  Avg with 3/5 signers: ${AVG}ms"
docker start deploy-signer-4-1 deploy-signer-5-1 > /dev/null
sleep 3

echo ""
echo "[ 12 ] Threshold Enforcement — 3 of 5 killed"
echo "─────────────────────────────────────"
echo "  Killing signer-1, signer-2, signer-3..."
docker stop deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1 > /dev/null
sleep 2
START=$(date +%s%N)
OUTPUT=$(kubectl create token default 2>&1)
END=$(date +%s%N)
MS=$(( (END - START) / 1000000 ))
echo "  Result: $OUTPUT"
echo "  Error returned in: ${MS}ms"
docker start deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1 > /dev/null
sleep 5

echo ""
echo "[ 13 ] Signer Recovery Time"
echo "─────────────────────────────────────"
docker stop deploy-signer-1-1 > /dev/null
sleep 2
docker start deploy-signer-1-1 > /dev/null
START=$(date +%s%N)
until kubectl create token default > /dev/null 2>&1; do
  sleep 0.1
done
END=$(date +%s%N)
MS=$(( (END - START) / 1000000 ))
echo "  Signer recovery time: ${MS}ms"

echo ""
echo "[ 14 ] Coordinator HA Failover Time"
echo "─────────────────────────────────────"
echo "  Killing grpc-proxy-1..."
docker stop deploy-grpc-proxy-1-1 > /dev/null
sleep 1
START=$(date +%s%N)
kubectl create token default > /dev/null
END=$(date +%s%N)
MS=$(( (END - START) / 1000000 ))
echo "  Token after proxy-1 killed: ${MS}ms ✅"
docker start deploy-grpc-proxy-1-1 > /dev/null
sleep 2

echo ""
echo "[ 15 ] 100 Pod Scaling"
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
echo "FROST Benchmark Complete"
echo "Results saved to: $RESULTS"
echo "================================================"
