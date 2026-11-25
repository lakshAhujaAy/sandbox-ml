"""
Redis-backed job queue.
Jobs are stored as hashes; a list acts as the FIFO queue.
"""
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

import redis.asyncio as aioredis

from api.models import JobStatus
from job_queue_service.constants import (
    QUEUE_KEY, JOB_PREFIX, RECENT_KEY, ML_QUEUE_KEY, ML_RESULT_PREFIX, WORKER_STATUS_KEY
)
from utils.logger import get_logger

logger = get_logger(__name__)


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

    # ── ML worker dispatch ───────────────────────────────────────────────────────
    # Separate from the main job queue above: this is the contract between the
    # orchestrator (producer) and the standalone ml-worker process (consumer).
    # ML runs in its own container/process so the API doesn't need torch/
    # torchvision installed and ML capacity can scale independently of API
    # instances. See ml/worker.py for the consumer side.

    async def push_ml_job(self, job_id: str, target: str, sandbox_result: Dict[str, Any]):
        payload = {"job_id": job_id, "target": target, "sandbox": sandbox_result}
        await self._redis.lpush(ML_QUEUE_KEY, json.dumps(payload))

    async def get_ml_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Returns the ML result if ready, or None if the worker hasn't finished yet.
        Consumes (deletes) the result on read so Redis doesn't accumulate stale entries."""
        key = f"{ML_RESULT_PREFIX}{job_id}"
        raw = await self._redis.get(key)
        if raw is None:
            return None
        await self._redis.delete(key)
        return json.loads(raw)

    async def get_worker_status(self) -> Optional[Dict[str, Any]]:
        """Latest heartbeat from the ML worker, or None if it is down (key expires after 15s)."""
        raw = await self._redis.get(WORKER_STATUS_KEY)
        return json.loads(raw) if raw else None
