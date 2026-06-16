# Kubernetes 기반 Mini Zero Trust Policy Gateway

NIST SP 800-207 기반 Zero Trust 아키텍처를 Kubernetes 위에 직접 구현한 프로젝트.  
OPA, Istio, Envoy 같은 기성 솔루션 없이 PEP / PDP / PIP 핵심 흐름을 처음부터 구현하여,  
Zero Trust가 실제로 어떻게 동작하는지 이해하는 데 초점을 맞췄다.

> 향후 PEP를 Envoy sidecar(Istio)로 교체하는 방식으로 확장 예정.

---

## 아키텍처

```
Client
  │  HTTP + Bearer JWT
  ▼
[PEP Gateway]  ←── 유일한 외부 진입점 (NodePort)
  │  Python · FastAPI · :8000
  ├── authorize() ──────────► [PDP Engine]
  │                            Go · net/http · :8001
  │                            └── policies.yaml 기반 정책 판단
  │                                in-memory cache (sync.RWMutex)
  │
  └── get_risk_score() ──────► [PIP Context]
                                Python · FastAPI · :8002
                                ├── AbuseIPDB   (IP 악성도 +40)
                                ├── ip-api.com  (해외 IP  +20)
                                └── Redis       (요청 빈도 +30)
                                    :6379

  ALLOW ──► [Upstream Service]  Python · FastAPI · :8080
  DENY  ──► 403 Forbidden
```

모든 컴포넌트는 `zerotrust` 네임스페이스에 배포되며,  
Calico NetworkPolicy로 PEP 이외의 Pod에서 upstream / pdp / pip 직접 접근을 차단한다.

---

## 보안 기능

| 기능 | 구현 내용 |
|------|-----------|
| **JWT 검증** | HS256 서명 + `exp` 만료 검증 (python-jose) |
| **토큰 폐기** | `POST /revoke` → JTI를 Redis 블랙리스트에 등록, 즉시 차단 |
| **정책 기반 접근 제어** | policies.yaml 우선순위 순 매칭, 매칭 없으면 default deny |
| **동적 위험도 평가** | riskScore ≥ 70 → block-high-risk 정책으로 DENY |
| **네트워크 격리** | Calico NetworkPolicy — PEP 이외 직접 접근 시 패킷 DROP |
| **Audit Log** | 모든 요청을 구조화 JSON으로 기록 |

---

## 정책 (policies.yaml)

| 우선순위 | 이름 | 조건 | 결과 |
|----------|------|------|------|
| 1 | admin-only-delete | subject=`role:admin`, action=DELETE | ALLOW |
| 2 | block-high-risk | riskScore ≥ 70 | DENY |
| 3 | user-read-allowed | subject=`role:user`, action=GET·POST | ALLOW |
| 999 | default-deny | 나머지 전부 | DENY |

---

## riskScore 계산 (PIP)

| 조건 | 가중치 |
|------|--------|
| AbuseIPDB 신뢰도 점수 ≥ 50 | +40 |
| 해외 IP (국가 코드 non-KR) | +20 |
| 10분 내 요청 10회 초과 | +30 |
| **합계 ≥ 70** → block-high-risk DENY | max 100 |

---

## 빠른 시작

### 사전 요구사항

```bash
# minikube (Calico CNI 필수)
minikube start --driver=docker --cni=calico --memory=4096
```

### 배포

```bash
chmod +x deploy.sh
./deploy.sh
```

### PEP 접근

```bash
kubectl port-forward svc/pep 8000:8000 -n zerotrust
```

---

## 테스트

### JWT 토큰 발급

```python
from jose import jwt
import uuid, time

secret = "dev-secret"

admin_token = jwt.encode(
    {"sub": "admin", "role": "role:admin",
     "jti": str(uuid.uuid4()), "exp": int(time.time()) + 3600},
    secret, algorithm="HS256"
)

user_token = jwt.encode(
    {"sub": "user1", "role": "role:user",
     "jti": str(uuid.uuid4()), "exp": int(time.time()) + 3600},
    secret, algorithm="HS256"
)
```

### E2E 요청 테스트

```bash
# 1. 토큰 없음 → 401
curl http://localhost:8000/api/users

# 2. user GET → 200 ALLOW (user-read-allowed)
curl -H "Authorization: Bearer $USER" http://localhost:8000/api/users

# 3. user DELETE → 403 DENY (default-deny)
curl -X DELETE -H "Authorization: Bearer $USER" http://localhost:8000/api/users

# 4. admin DELETE → 200 ALLOW (admin-only-delete)
curl -X DELETE -H "Authorization: Bearer $ADMIN" http://localhost:8000/api/users

# 5. 만료된 토큰 → 401
curl -H "Authorization: Bearer $EXPIRED" http://localhost:8000/api/users

# 6. 토큰 폐기
curl -X POST -H "Authorization: Bearer $USER" http://localhost:8000/revoke

# 7. 폐기된 토큰 재사용 → 401
curl -H "Authorization: Bearer $USER" http://localhost:8000/api/users
```

### NetworkPolicy 차단 검증

```bash
# PEP를 거치지 않고 upstream 직접 접근 → timeout (DROP)
kubectl run netpol-test --image=curlimages/curl:latest -n zerotrust \
  --restart=Never --rm -i -- curl -m 5 http://upstream:8080/health

# 결과: curl: (28) Connection timed out after 5002 milliseconds
```

---

## Audit Log 예시

```json
{
  "subject": "role:user",
  "resource": "/api/users",
  "action": "DELETE",
  "decision": "DENY",
  "matchedPolicy": "default-deny",
  "riskScore": 0.0,
  "clientIp": "10.244.120.64",
  "latencyMs": 273,
  "jti": "6546a478-c71a-401d-8962-5e8fd1d1cde5"
}
```

---

## 프로젝트 구조

```
.
├── deploy.sh                      # 전체 빌드 + 배포 스크립트
├── architecture.html              # 아키텍처 다이어그램 (브라우저에서 열기)
├── pdp/                           # PDP — Go
│   ├── main.go
│   ├── evaluate.go                # 정책 평가 엔진
│   ├── policy.go                  # 정책 로드 + 매칭
│   ├── cache.go                   # in-memory 캐시
│   ├── policies.yaml
│   └── Dockerfile
├── pep/                           # PEP — Python/FastAPI
│   ├── main.py                    # 게이트웨이 + /revoke
│   ├── requirements.txt
│   └── Dockerfile
├── pip/                           # PIP — Python/FastAPI
│   ├── main.py                    # riskScore 계산
│   ├── requirements.txt
│   └── Dockerfile
├── upstream/                      # 보호 대상 백엔드
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
└── k8s/
    ├── namespace.yaml
    ├── redis.yaml
    ├── pdp/deployment.yaml
    ├── pep/deployment.yaml
    ├── pip/deployment.yaml
    ├── upstream/deployment.yaml
    └── networkpolicy/policy.yaml
```

---

## 한계 및 향후 계획

| 항목 | 현재 | 개선 방향 |
|------|------|-----------|
| 서명 알고리즘 | HS256 (대칭키) | RS256 (비대칭) |
| 정책 엔진 | policies.yaml 수동 편집 | OPA (Rego) 연동 |
| Pod 간 통신 | 평문 HTTP | **Istio mTLS** (Envoy sidecar) |
| ID 공급자 | JWT 자체 발급 | Keycloak / OIDC 연동 |
| Upstream | 목 데이터 하드코딩 | PostgreSQL 연동 |

---

## 참고

- [NIST SP 800-207 Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207)
- [OASIS XACML — PEP/PDP/PIP 모델](https://www.oasis-open.org/committees/xacml/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
