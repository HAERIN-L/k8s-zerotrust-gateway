import logging
import os
import time

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="PIP — Policy Information Point")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REQUEST_WINDOW_SEC = 600   # 10분
REQUEST_THRESHOLD = 10     # 10분 내 10회 초과 시 가중치


def get_redis():
    return aioredis.from_url(REDIS_URL, decode_responses=True)


async def fetch_abuse_score(ip: str) -> float:
    if not ABUSEIPDB_API_KEY:
        return 0
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            data = resp.json().get("data", {})
            return float(data.get("abuseConfidenceScore", 0))
    except Exception as e:
        logger.warning(f"AbuseIPDB 호출 실패: {e}")
        return 0


async def fetch_geo(ip: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=countryCode")
            return resp.json().get("countryCode", "XX")
    except Exception as e:
        logger.warning(f"ip-api.com 호출 실패: {e}")
        return "XX"


async def fetch_request_count(subject: str) -> int:
    try:
        r = get_redis()
        key = f"req_count:{subject}"
        now = int(time.time())
        window_start = now - REQUEST_WINDOW_SEC

        async with r:
            await r.zremrangebyscore(key, "-inf", window_start)
            await r.zadd(key, {str(now): now})
            await r.expire(key, REQUEST_WINDOW_SEC)
            count = await r.zcard(key)
            return count
    except Exception as e:
        logger.warning(f"Redis 호출 실패: {e}")
        return 0


def calc_risk_score(abuse_score: float, country: str, request_count: int) -> float:
    score = 0.0

    # AbuseIPDB 점수 50 이상이면 +40
    if abuse_score >= 50:
        score += 40

    # 해외 IP면 +20
    if country not in ("KR", "XX"):
        score += 20

    # 10분 내 요청 10회 초과면 +30
    if request_count > REQUEST_THRESHOLD:
        score += 30

    return min(score, 100)


@app.get("/context")
async def get_context(subject: str, ip: str):
    abuse_score, country, request_count = (
        await fetch_abuse_score(ip),
        await fetch_geo(ip),
        await fetch_request_count(subject),
    )

    risk_score = calc_risk_score(abuse_score, country, request_count)

    logger.info(
        f"subject={subject} ip={ip} country={country} "
        f"abuseScore={abuse_score} requestCount={request_count} riskScore={risk_score}"
    )

    return {
        "riskScore": risk_score,
        "geoLocation": country,
        "abuseScore": abuse_score,
        "requestCount": request_count,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
