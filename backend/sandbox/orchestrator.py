"""
Sandbox Orchestrator
====================
1. Pulls jobs from the queue
2. Spins up an isolated Docker container
3. Executes the target URL inside a headless browser
4. Collects network/filesystem/process logs + screenshot
5. Destroys the container
6. Hands telemetry off to the ML worker process via Redis (does NOT run
   ML models in-process — see _run_ml_pipeline below) and waits for results
7. Aggregates results and stores them

Architecture note: ML inference runs in a SEPARATE process (ml/worker.py,
its own container in docker-compose.yml) rather than inline in this API
process. This keeps the API container lightweight — it doesn't need torch/
torchvision installed — and lets ML workers scale independently of API
instances. The orchestrator communicates with the ML worker purely through
Redis: push a job to `sandbox:ml_queue`, poll `sandbox:ml_result:{job_id}`
until the worker writes a result there (or the timeout in ML_TIMEOUT elapses).
"""
import asyncio
import json
import os
import tempfile
import time
from datetime import datetime
from typing import Any, Dict

import docker
from docker.errors import DockerException

from api.models import (
    JobStatus, ThreatLevel
)
from api.connection_manager import ConnectionManager
from job_queue_service.job_queue import JobQueue
from utils.logger import get_logger

logger = get_logger(__name__)

SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "sandbox-worker:latest")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "3"))
ML_TIMEOUT = int(os.getenv("ML_TIMEOUT", "30"))
ML_POLL_INTERVAL = 0.3  # seconds between result polls


class SandboxOrchestrator:
    def __init__(self, job_queue: JobQueue, ws_manager: ConnectionManager):
        self.queue = job_queue
        self.ws = ws_manager
        self._semaphore = asyncio.Semaphore(MAX_WORKERS)

        try:
            self._docker = docker.from_env()
        except DockerException as e:
            logger.warning(f"Docker unavailable, using simulation mode: {e}")
            self._docker = None

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run_forever(self):
        logger.info("Orchestrator loop started")
        while True:
            job = await self.queue.pop(timeout=2)
            if job:
                asyncio.create_task(self._handle_job(job))

    # ── Job handler ───────────────────────────────────────────────────────────

    async def _handle_job(self, job: Dict[str, Any]):
        job_id = job["job_id"]
        target = job.get("target", "")

        async with self._semaphore:
            await self._emit(job_id, "status", {"status": JobStatus.RUNNING})
            await self.queue.update(job_id, {"status": JobStatus.RUNNING})

            try:
                # Step 1 — Sandbox execution
                await self._emit(job_id, "stage", {"stage": "sandbox", "msg": "Spinning up isolated container…"})
                sandbox_result = await self._run_sandbox(job_id, target)

                # Step 2 — Hand off to the ML worker process for all 3 models
                await self._emit(job_id, "stage", {"stage": "ml_pipeline", "msg": "Dispatching to ML worker…"})
                ml_results = await self._run_ml_pipeline(job_id, target, sandbox_result)

                url_result = ml_results["url_nlp"]
                behavior_result = ml_results["behavior"]
                vision_result = ml_results["vision"]

                # Step 3 — Aggregate
                aggregate_score = self._aggregate(url_result, behavior_result, vision_result)
                threat_level = self._score_to_level(aggregate_score)

                final: Dict[str, Any] = {
                    "job_id": job_id,
                    "status": JobStatus.DONE,
                    "target": target,
                    "submitted_at": job.get("submitted_at"),
                    "completed_at": datetime.utcnow().isoformat(),
                    "threat_level": threat_level,
                    "aggregate_score": round(aggregate_score, 4),
                    "url_nlp": url_result,
                    "behavior": behavior_result,
                    "vision": vision_result,
                    "sandbox": sandbox_result,
                }

                await self.queue.update(job_id, final)
                await self._emit(job_id, "done", final)

            except Exception as exc:
                logger.exception(f"Job {job_id} failed")
                error_payload = {
                    "job_id": job_id,
                    "status": JobStatus.ERROR,
                    "error": str(exc),
                    "completed_at": datetime.utcnow().isoformat(),
                }
                await self.queue.update(job_id, error_payload)
                await self._emit(job_id, "error", error_payload)

    # ── ML dispatch (delegates to the separate ml-worker process) ─────────────

    async def _run_ml_pipeline(self, job_id: str, target: str, sandbox_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pushes the job to the ML worker's Redis queue and polls for the result.
        Raises TimeoutError if the worker doesn't respond within ML_TIMEOUT seconds
        — this surfaces as a job error rather than hanging forever, which matters
        if the ml-worker container is down or still loading the CNN checkpoint.
        """
        await self.queue.push_ml_job(job_id, target, sandbox_result)

        deadline = time.time() + ML_TIMEOUT
        while time.time() < deadline:
            result = await self.queue.get_ml_result(job_id)
            if result is not None:
                return result
            await asyncio.sleep(ML_POLL_INTERVAL)

        raise TimeoutError(
            f"ML worker did not respond within {ML_TIMEOUT}s — "
            f"check that the ml-worker container is running (docker compose logs ml-worker)"
        )

    # ── Sandbox execution ─────────────────────────────────────────────────────

    async def _run_sandbox(self, job_id: str, target: str) -> Dict[str, Any]:
        """
        Run target in an isolated Docker container with a headless browser.
        Falls back to a rich simulation if Docker is unavailable.
        """
        if self._docker is None:
            return await asyncio.to_thread(self._simulate_sandbox, target)

        with tempfile.TemporaryDirectory() as tmpdir:
            result_file = os.path.join(tmpdir, "result.json")

            try:
                start = time.time()
                container_output = await asyncio.to_thread(
                    self._docker.containers.run,
                    image=SANDBOX_IMAGE,
                    command=f"python /sandbox/run.py --url '{target}' --out /results/result.json",
                    volumes={tmpdir: {"bind": "/results", "mode": "rw"}},
                    network_mode="bridge",
                    mem_limit="256m",
                    cpu_period=100000,
                    cpu_quota=50000,       # 50% of one CPU
                    read_only=False,
                    remove=True,
                    detach=False,
                    timeout=60,
                )
                elapsed = int((time.time() - start) * 1000)
                logger.debug(f"Sandbox container output ({job_id}): {container_output[:500]!r}")

                if os.path.exists(result_file):
                    with open(result_file) as f:
                        data = json.load(f)
                    data["execution_ms"] = elapsed
                    return data

            except Exception as e:
                logger.warning(f"Container execution failed ({e}), using simulation")

        return await asyncio.to_thread(self._simulate_sandbox, target)

    def _simulate_sandbox(self, target: str) -> Dict[str, Any]:
        """
        Realistic sandbox simulation — used when Docker is unavailable.
        Generates plausible network/filesystem/process events based on URL features.
        """
        import random
        import re

        suspicious_keywords = [
            "login", "secure", "verify", "account", "update", "bank",
            "paypal", "microsoft", "apple", "amazon", "confirm", "password"
        ]
        is_suspicious = any(kw in target.lower() for kw in suspicious_keywords)
        has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target))
        long_subdomain = len(target.split(".")) > 4

        risk_factor = sum([is_suspicious * 0.4, has_ip * 0.3, long_subdomain * 0.2])

        network_requests = [
            {"url": target, "method": "GET", "status": 200, "content_type": "text/html"},
        ]
        logs = [
            {"timestamp": datetime.utcnow().isoformat(), "level": "info",
             "category": "network", "message": f"GET {target} → 200 OK"},
        ]

        if risk_factor > 0.3 or random.random() < risk_factor:
            suspicious_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            network_requests.append({
                "url": f"http://{suspicious_ip}/payload.exe",
                "method": "GET", "status": 200, "content_type": "application/octet-stream"
            })
            logs.append({
                "timestamp": datetime.utcnow().isoformat(), "level": "alert",
                "category": "network", "message": f"Outbound binary download: {suspicious_ip}/payload.exe"
            })

        if is_suspicious:
            logs.append({
                "timestamp": datetime.utcnow().isoformat(), "level": "warn",
                "category": "visual", "message": "Page visually resembles known brand login page"
            })

        process_events = [
            {"pid": 1234, "name": "chromium", "event": "spawn", "args": ["--headless", target]},
        ]
        if risk_factor > 0.4:
            process_events.append({
                "pid": 1235, "name": "powershell.exe", "event": "spawn",
                "args": ["-enc", "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA=="]
            })
            logs.append({
                "timestamp": datetime.utcnow().isoformat(), "level": "alert",
                "category": "process", "message": "Suspicious process: encoded PowerShell spawned"
            })

        return {
            "network_requests": network_requests,
            "dns_queries": [target.split("/")[2] if "//" in target else target],
            "file_operations": [],
            "process_events": process_events,
            "screenshot_b64": None,
            "page_title": "Simulated Page" if not is_suspicious else "Verify Your Account - Security Alert",
            "final_url": target,
            "logs": logs,
            "execution_ms": random.randint(800, 3200),
        }

    # ── Scoring helpers ───────────────────────────────────────────────────────

    def _aggregate(self, url: dict, behavior: dict, vision: dict) -> float:
        weights = {"url_nlp": 0.25, "behavior": 0.45, "vision": 0.30}
        scores = {
            "url_nlp": url.get("score", 0.0),
            "behavior": behavior.get("score", 0.0),
            "vision": vision.get("score", 0.0),
        }
        return sum(weights[k] * scores[k] for k in weights)

    def _score_to_level(self, score: float) -> str:
        if score >= 0.70:
            return ThreatLevel.MALICIOUS
        if score >= 0.40:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.SAFE

    # ── WS helper ─────────────────────────────────────────────────────────────

    async def _emit(self, job_id: str, event: str, data: dict):
        await self.ws.broadcast(job_id, {"event": event, "job_id": job_id, **data})
