#!/bin/bash
set -e

BASE="$(cd "$(dirname "$0")" && pwd)"

echo "=== minikube Docker 환경으로 전환 ==="
eval $(minikube docker-env)

echo "=== 이미지 빌드 ==="
docker build -t pdp:latest "$BASE/pdp"
docker build -t pep:latest "$BASE/pep"
docker build -t pip:latest "$BASE/pip"
docker build -t upstream:latest "$BASE/upstream"

echo "=== 네임스페이스 생성 ==="
kubectl apply -f "$BASE/k8s/namespace.yaml"

echo "=== Secret 생성 ==="
kubectl create secret generic zerotrust-secrets \
  --namespace=zerotrust \
  --from-literal=jwt-secret=dev-secret \
  --from-literal=abuseipdb-api-key="" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "=== 서비스 배포 ==="
kubectl apply -f "$BASE/k8s/redis.yaml"
kubectl apply -f "$BASE/k8s/pdp/deployment.yaml"
kubectl apply -f "$BASE/k8s/pip/deployment.yaml"
kubectl apply -f "$BASE/k8s/pep/deployment.yaml"
kubectl apply -f "$BASE/k8s/upstream/deployment.yaml"

echo "=== NetworkPolicy 적용 ==="
kubectl apply -f "$BASE/k8s/networkpolicy/policy.yaml"

echo "=== Pod 상태 확인 (Ready 대기) ==="
kubectl rollout status deployment/pdp -n zerotrust
kubectl rollout status deployment/pep -n zerotrust
kubectl rollout status deployment/pip -n zerotrust
kubectl rollout status deployment/upstream -n zerotrust

echo ""
echo "=== 배포 완료 ==="
kubectl get pods -n zerotrust
