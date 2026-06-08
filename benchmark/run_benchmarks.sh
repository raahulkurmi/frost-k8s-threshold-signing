#!/bin/bash

echo "================================================"
echo "FROST K8s Threshold Signing — Benchmark Suite"
echo "================================================"
echo "Date: $(date)"
echo "Environment: Minikube, Docker driver, macOS"
echo ""

RESULTS="benchmark/results/benchmark_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p benchmark/results
exec > >(tee $RESULTS) 2>&1

echo "[ 1 ] Single Token Latency (10 runs)"
echo "─────────────────────────────────────"
for i in $(seq 1 10); do
  TIME=$( { time kubectl create token default > /dev/null; } 2>&1 | grep real | awk '{print $2}')
  echo "  Run $i: $TIME"
done

echo ""
echo "[ 2 ] 100 Token Throughput"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 100); do
  kubectl create token default > /dev/null
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
AVG_MS=$(( TOTAL_MS / 100 ))
echo "  Total: ${TOTAL_MS}ms"
echo "  Average per token: ${AVG_MS}ms"
echo "  Throughput: $(( 100 * 1000 / TOTAL_MS )) tokens/sec"

echo ""
echo "[ 3 ] 500 Token Throughput"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 500); do
  kubectl create token default > /dev/null
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
AVG_MS=$(( TOTAL_MS / 500 ))
echo "  Total: ${TOTAL_MS}ms"
echo "  Average per token: ${AVG_MS}ms"
echo "  Throughput: $(( 500 * 1000 / TOTAL_MS )) tokens/sec"

echo ""
echo "[ 4 ] Concurrent Token Requests (10 parallel)"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 10); do
  kubectl create token default > /dev/null &
done
wait
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  10 concurrent tokens: ${TOTAL_MS}ms"

echo ""
echo "[ 5 ] Concurrent Token Requests (50 parallel)"
echo "─────────────────────────────────────"
START=$(date +%s%N)
for i in $(seq 1 50); do
  kubectl create token default > /dev/null &
done
wait
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  50 concurrent tokens: ${TOTAL_MS}ms"

echo ""
echo "[ 6 ] Memory Usage"
echo "─────────────────────────────────────"
echo "  grpc-proxy (idle):"
docker stats deploy-grpc-proxy-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"
echo "  signer-1 (idle):"
docker stats deploy-signer-1-1 --no-stream --format "    CPU: {{.CPUPerc}} | Memory: {{.MemUsage}}"

echo ""
echo "[ 7 ] Signer Failure Tolerance"
echo "─────────────────────────────────────"
echo "  Killing signer-4 and signer-5..."
docker stop deploy-signer-4-1 deploy-signer-5-1 > /dev/null
sleep 2
START=$(date +%s%N)
kubectl create token default > /dev/null
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  Token with 3/5 signers: ${TOTAL_MS}ms"
docker start deploy-signer-4-1 deploy-signer-5-1 > /dev/null
sleep 3

echo ""
echo "[ 8 ] Signer Recovery Time"
echo "─────────────────────────────────────"
docker stop deploy-signer-1-1 > /dev/null
sleep 1
docker start deploy-signer-1-1 > /dev/null
START=$(date +%s%N)
until kubectl create token default > /dev/null 2>&1; do
  sleep 0.1
done
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  Signer recovery time: ${TOTAL_MS}ms"

echo ""
echo "[ 9 ] 100 Pod Scaling"
echo "─────────────────────────────────────"
kubectl delete deployment scale-test 2>/dev/null
START=$(date +%s%N)
kubectl create deployment scale-test --image=nginx --replicas=100 > /dev/null
echo "  Waiting for pods..."
kubectl rollout status deployment/scale-test --timeout=300s
END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))
echo "  100 pods ready: ${TOTAL_MS}ms"
kubectl delete deployment scale-test > /dev/null

echo ""
echo "================================================"
echo "Benchmark Complete — Results saved to $RESULTS"
echo "================================================"
