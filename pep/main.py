import json
import logging
import os
import time

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jose import jwt, JWTError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="PEP Gateway")

PDP_URL = os.getenv("PDP_URL", "http://localhost:8001")
PIP_URL = os.getenv("PIP_URL", "http://localhost:8002")
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://localhost:8080")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

REVOKED_SET = "revoked_tokens"


def get_redis():
    return aioredis.from_url(REDIS_URL, decode_responses=True)


def parse_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"verify_exp": True},
    )


async def is_revoked(jti: str) -> bool:
    try:
        async with get_redis() as r:
            return bool(await r.sismember(REVOKED_SET, jti))
    except Exception:
        logger.warning("Redis 연결 실패 — revocation 체크 스킵")
        return False


async def get_risk_score(subject: str, ip: str) -> float:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{PIP_URL}/context", params={"subject": subject, "ip": ip})
            return resp.json().get("riskScore", 0)
    except Exception:
        logger.warning("PIP 호출 실패 — riskScore 0 사용")
        return 0


async def authorize(subject: str, resource: str, action: str, risk_score: float) -> dict:
    async with httpx.AsyncClient(timeout=3.0) as client:
        resp = await client.post(
            f"{PDP_URL}/authorize",
            json={"subject": subject, "resource": resource, "action": action, "riskScore": risk_score},
        )
        return resp.json()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/revoke")
async def revoke(request: Request):
    """토큰을 즉시 폐기 (JTI를 Redis 블랙리스트에 추가)"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "missing token"})

    token = auth_header.removeprefix("Bearer ")
    try:
        claims = parse_jwt(token)
    except JWTError as e:
        return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})

    jti = claims.get("jti")
    if not jti:
        return JSONResponse(status_code=400, content={"detail": "token has no jti claim"})

    exp = claims.get("exp")
    ttl = max(int(exp) - int(time.time()), 1) if exp else 3600

    try:
        async with get_redis() as r:
            await r.sadd(REVOKED_SET, jti)
            await r.expire(REVOKED_SET, ttl)
    except Exception as e:
        logger.error(f"Redis revocation 저장 실패: {e}")
        return JSONResponse(status_code=503, content={"detail": "revocation store unavailable"})

    logger.info(f"[REVOKE] jti={jti} ttl={ttl}s")
    return {"detail": "token revoked", "jti": jti}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway(path: str, request: Request):
    start = time.time()

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "missing token"})

    token = auth_header.removeprefix("Bearer ")
    try:
        claims = parse_jwt(token)
    except JWTError as e:
        return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})

    # JTI revocation 체크
    jti = claims.get("jti")
    if jti and await is_revoked(jti):
        logger.warning(f"[REVOKED] jti={jti}")
        return JSONResponse(status_code=401, content={"detail": "token has been revoked"})

    subject = claims.get("role", "role:unknown")
    resource = f"/{path}"
    action = request.method
    client_ip = get_client_ip(request)

    risk_score = await get_risk_score(subject, client_ip)

    try:
        decision_resp = await authorize(subject, resource, action, risk_score)
    except Exception as e:
        logger.error(f"PDP 호출 실패: {e}")
        return JSONResponse(status_code=503, content={"detail": "policy engine unavailable"})

    decision = decision_resp.get("decision", "DENY")
    matched_policy = decision_resp.get("matchedPolicy", "unknown")
    latency_ms = round((time.time() - start) * 1000)

    audit = {
        "subject": subject,
        "resource": resource,
        "action": action,
        "decision": decision,
        "matchedPolicy": matched_policy,
        "riskScore": risk_score,
        "clientIp": client_ip,
        "latencyMs": latency_ms,
        "jti": jti,
    }
    logger.info(f"[AUDIT] {json.dumps(audit)}")

    if decision == "DENY":
        return JSONResponse(status_code=403, content={"detail": "forbidden", "reason": decision_resp.get("reason")})

    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}

    async with httpx.AsyncClient(timeout=10.0) as client:
        upstream_resp = await client.request(
            method=action,
            url=f"{UPSTREAM_URL}/{path}",
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )

    from fastapi import Response
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers),
    )
