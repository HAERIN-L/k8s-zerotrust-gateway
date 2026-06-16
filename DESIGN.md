# 구현 설계 문서

## 디렉토리 구조

```
.
├── README.md
├── DESIGN.md
├── pdp/                        # Go — 정책 평가 엔진
│   ├── main.go
│   ├── policy.go               # 정책 파일 로드 및 파싱
│   ├── evaluate.go             # 정책 매칭 로직
│   ├── cache.go                # in-memory 캐시
│   ├── policies.yaml           # 정책 정의
│   └── Dockerfile
├── pep/                        # Python FastAPI — 역방향 프록시
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── pip/                        # Python FastAPI — 컨텍스트 제공
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── upstream/                   # Python FastAPI — 보호 대상 서비스 (테스트용)
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── k8s/                        # Kubernetes 매니페스트
│   ├── pdp/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── pep/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── pip/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── upstream/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── networkpolicy/
│   │   └── policy.yaml
│   └── ingress/
│       └── ingress.yaml
└── tests/
    ├── test_pdp.py
    ├── test_pep.py
    └── load/
        └── k6-script.js
```

---

## 기술 스택

| 컴포넌트 | 언어 | 프레임워크 | 포트 |
|---|---|---|---|
| PDP | Go 1.22 | net/http, gopkg.in/yaml.v3 | 8001 |
| PEP | Python 3.11 | FastAPI, httpx | 8000 |
| PIP | Python 3.11 | FastAPI, httpx, redis-py | 8002 |
| upstream | Python 3.11 | FastAPI | 8080 |

---

## API 명세

### PDP — `POST /authorize`

**요청**
```json
{
  "subject": "role:user",
  "resource": "/api/transfer",
  "action": "POST",
  "riskScore": 85
}
```

**응답 (ALLOW)**
```json
{
  "decision": "ALLOW",
  "matchedPolicy": "block-high-risk",
  "reason": "riskScore < 70 condition met"
}
```

**응답 (DENY)**
```json
{
  "decision": "DENY",
  "matchedPolicy": "default-deny",
  "reason": "No matching ALLOW policy"
}
```

---

### PIP — `GET /context`

**요청**
```
GET /context?subject=role:user&ip=1.2.3.4
```

**응답**
```json
{
  "riskScore": 85,
  "geoLocation": "US",
  "requestCount": 15,
  "lastLoginTime": "2026-06-15T03:12:00Z"
}
```

---

### PEP — 모든 경로 프록시

```
ANY /*  →  JWT 검증 → PDP 판단 → ALLOW: upstream 전달 / DENY: 403
```

---

## 데이터 모델

### 정책 파일 (pdp/policies.yaml)

```yaml
policies:
  - name: "admin-only-delete"
    subject: "role:admin"
    resource: "/api/users"
    action: "DELETE"
    effect: ALLOW
    priority: 1

  - name: "block-high-risk"
    subject: "role:user"
    resource: "/api/transfer"
    action: "POST"
    condition: "riskScore < 70"
    effect: ALLOW
    priority: 2

  - name: "default-deny"
    effect: DENY
    priority: 999
```

### Audit Log 구조

```json
{
  "timestamp": "2026-06-15T03:12:00Z",
  "subject": "role:user",
  "resource": "/api/transfer",
  "action": "POST",
  "decision": "DENY",
  "matchedPolicy": "default-deny",
  "riskScore": 85,
  "latencyMs": 12
}
```

---

## 요청 흐름

```
Client
  │
  │  Authorization: Bearer <JWT>
  ▼
PEP (8000)
  │  1. JWT 파싱 → subject, resource, action 추출
  │  2. PIP에서 riskScore 조회
  │  3. PDP에 authorize 요청
  ▼
PDP (8001)
  │  정책 매칭 → ALLOW / DENY 반환
  ▼
PEP
  │  ALLOW → upstream 프록시
  │  DENY  → 403 반환
  ▼
upstream (8080)  또는  Client에게 403
```

---

## 구현 순서

### 1단계 — PDP (Go)
- [ ] `policies.yaml` 작성
- [ ] `policy.go` — 정책 구조체 + YAML 로드
- [ ] `evaluate.go` — 정책 매칭 로직 (priority순, condition 평가, default deny)
- [ ] `cache.go` — in-memory 캐시 (subject+resource+action 키)
- [ ] `main.go` — HTTP 서버, `/authorize` 엔드포인트
- [ ] curl로 ALLOW/DENY 응답 확인

### 2단계 — upstream (Python)
- [ ] `/api/users`, `/api/transfer` 엔드포인트 가진 더미 서비스
- [ ] PEP 테스트할 때 필요

### 3단계 — PEP (Python)
- [ ] JWT 파싱 (python-jose)
- [ ] PDP `/authorize` 호출
- [ ] ALLOW → httpx로 upstream 프록시
- [ ] DENY → 403 반환
- [ ] Audit log 출력

### 4단계 — PIP (Python)
- [ ] AbuseIPDB API 연동
- [ ] ip-api.com 연동
- [ ] Redis 연동 (요청 빈도)
- [ ] riskScore 계산 후 반환

### 5단계 — K8s 배포
- [ ] 각 서비스 Dockerfile 작성
- [ ] Deployment + Service 매니페스트 작성
- [ ] NetworkPolicy 적용
- [ ] Ingress 설정

### 6단계 — 검증
- [ ] tcpdump로 NetworkPolicy 동작 확인
- [ ] pytest로 PDP/PEP 단위 테스트
- [ ] k6 부하 테스트

---

## 로컬 개발 환경

```bash
# Go 설치 확인
go version  # 1.22 이상

# Python 환경
python3 -m venv venv
source venv/bin/activate

# Redis (Docker로 실행)
docker run -d -p 6379:6379 redis:alpine

# 로컬 실행 순서
# 1. PDP
cd pdp && go run .

# 2. upstream
cd upstream && uvicorn main:app --port 8080

# 3. PIP
cd pip && uvicorn main:app --port 8002

# 4. PEP
cd pep && uvicorn main:app --port 8000
```
