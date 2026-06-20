"""
Redis-backed job queue.
Jobs are stored as hashes; a list acts as the FIFO queue.
"""
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

import redis.asyncio as aioredis

from api.models import JobStatus, AnalysisResult
from utils.logger import get_logger

logger = get_logger(__name__)

QUEUE_KEY = "sandbox:queue"
JOB_PREFIX = "sandbox:job:"
RECENT_KEY = "sandbox:recent"


class JobQueue:
    def __init__(self):
        self._url = os.getenv("REDIS_URL", "redis://localhost:6379")
        self._redis: Optional[aioredis.Redis] = None

    async def connect(self):
        self._redis = await aioredis.from_url(self._url, decode_responses=True)
        logger.info(f"Redis connected: {self._url}")

    async def disconnect(self):
        if self._redis:
            await self._redis.aclose()

    # ── Producer ──────────────────────────────────────────────────────────────

    async def push(self, job_id: str, payload: Dict[str, Any]):
        data = {
            "job_id": job_id,
            "status": JobStatus.QUEUED,
            "submitted_at": datetime.utcnow().isoformat(),
            **payload,
        }
        await self._redis.set(f"{JOB_PREFIX}{job_id}", json.dumps(data))
        await self._redis.lpush(QUEUE_KEY, job_id)
        await self._redis.lpush(RECENT_KEY, job_id)
        await self._redis.ltrim(RECENT_KEY, 0, 99)  # keep last 100

    # ── Consumer ──────────────────────────────────────────────────────────────

    async def pop(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """Blocking pop — returns job payload or None on timeout."""
        result = await self._redis.brpop(QUEUE_KEY, timeout=timeout)
        if result is None:
            return None
        _, job_id = result
        raw = await self._redis.get(f"{JOB_PREFIX}{job_id}")
        if raw is None:
            return None
        return json.loads(raw)

    # ── State management ──────────────────────────────────────────────────────

    async def update(self, job_id: str, updates: Dict[str, Any]):
        raw = await self._redis.get(f"{JOB_PREFIX}{job_id}")
        data = json.loads(raw) if raw else {}
        data.update(updates)
        await self._redis.set(f"{JOB_PREFIX}{job_id}", json.dumps(data), ex=3600)

    async def get_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        raw = await self._redis.get(f"{JOB_PREFIX}{job_id}")
        return json.loads(raw) if raw else None

    async def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        job_ids = await self._redis.lrange(RECENT_KEY, 0, limit - 1)
        results = []
        for jid in job_ids:
            raw = await self._redis.get(f"{JOB_PREFIX}{jid}")
            if raw:
                results.append(json.loads(raw))
        return results
