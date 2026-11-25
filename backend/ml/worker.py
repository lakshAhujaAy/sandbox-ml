"""
ml/worker.py — standalone ML worker process
=============================================
Pulls {job_id, target, sandbox} payloads pushed by sandbox/orchestrator.py
(via JobQueue.push_ml_job), runs all 3 ML models, writes results back to
Redis under sandbox:ml_result:{job_id} for the orchestrator to pick up.

This runs as its own container (Dockerfile.ml, requirements-ml.txt — which
includes torch/torchvision) so the main API container stays lightweight and
doesn't need the CNN's dependencies installed. See docker-compose.yml's
`ml-worker` service and sandbox/orchestrator.py's `_run_ml_pipeline` for the
producer side of this contract.

INFERENCE LOGGING: live predictions are batched into periodic MLflow runs
(every INFERENCE_LOG_BATCH_SIZE predictions, default 50) rather than one
MLflow run per request — logging a full MLflow run per inference would be
the wrong granularity (MLflow runs carry meaningful overhead and are
designed for experiment-level tracking, not per-request telemetry) and
would make the MLflow UI unusable at any real request volume. Each batch
run logs aggregate score distributions and model_source breakdowns (how
often each model's trained-model-vs-fallback path actually fired in
production), which is the genuinely useful signal for detecting drift or
silent fallback failures over time.
"""
import asyncio
import json
import os
import signal
import statistics
from collections import Counter
from pathlib import Path

import mlflow
import redis.asyncio as aioredis

from ml.url_nlp.analyzer import URLAnalyzer
from ml.behavior.analyzer import BehaviorAnalyzer
from ml.vision.analyzer import VisionAnalyzer
from job_queue_service.constants import ML_QUEUE_KEY, ML_RESULT_PREFIX, WORKER_STATUS_KEY
from utils.logger import get_logger

logger = get_logger("ml.worker")

INFERENCE_LOG_BATCH_SIZE = int(os.getenv("INFERENCE_LOG_BATCH_SIZE", "50"))
# Same convention as ml/url_nlp/training/train.py and ml/behavior/training/train.py:
# one shared mlflow.db at backend/mlflow.db, resolved as an absolute path anchored
# to this file's own location so it's correct regardless of the process's cwd.
_BACKEND_DIR = Path(__file__).parent.parent  # backend/
MLFLOW_URI = os.getenv("MLFLOW_TRACKING_URI", f"sqlite:///{_BACKEND_DIR / 'mlflow.db'}")


class MLWorker:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.vision_analyzer = VisionAnalyzer()
        self._running = True
        self._inference_batch = []  # accumulates results until batch size is hit

        try:
            mlflow.set_tracking_uri(MLFLOW_URI)
            mlflow.set_experiment("production_inference")
            self._mlflow_available = True
        except Exception as e:
            logger.warning(f"MLflow unavailable, inference logging disabled: {e}")
            self._mlflow_available = False

    def _log_inference_batch(self):
        """Logs aggregate stats for a batch of live predictions as a single
        MLflow run — score distributions and model_source breakdowns, which
        surface silent fallback failures (e.g. a model file going missing in
        production would show up as model_source flipping to
        rule_based_fallback for 100% of a batch) without per-request overhead."""
        if not self._mlflow_available or not self._inference_batch:
            return

        try:
            with mlflow.start_run(run_name=f"inference_batch_{len(self._inference_batch)}"):
                mlflow.log_param("batch_size", len(self._inference_batch))

                for model_name in ("url_nlp", "behavior", "vision"):
                    scores = [b[model_name]["score"] for b in self._inference_batch if model_name in b]
                    sources = Counter(b[model_name].get("model_source", "unknown") for b in self._inference_batch if model_name in b)
                    threat_levels = Counter(b[model_name].get("threat_level", "unknown") for b in self._inference_batch if model_name in b)

                    if scores:
                        mlflow.log_metric(f"{model_name}_mean_score", statistics.mean(scores))
                        mlflow.log_metric(f"{model_name}_median_score", statistics.median(scores))
                    for source, count in sources.items():
                        mlflow.log_metric(f"{model_name}_source_{source}_count", count)
                    for level, count in threat_levels.items():
                        mlflow.log_metric(f"{model_name}_threat_{level}_count", count)

                aggregate_scores = [b.get("aggregate_score", 0) for b in self._inference_batch]
                if aggregate_scores:
                    mlflow.log_metric("aggregate_mean_score", statistics.mean(aggregate_scores))

            logger.info(f"Logged inference batch of {len(self._inference_batch)} predictions to MLflow")
        except Exception as e:
            logger.warning(f"Failed to log inference batch to MLflow: {e}")
        finally:
            self._inference_batch = []

    async def run(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        r = await aioredis.from_url(redis_url, decode_responses=True)
        logger.info(f"ML Worker connected to Redis: {redis_url}")

        while self._running:
            try:
                # Heartbeat doubles as a model-load report, so a silent fallback to
                # rule-based scoring (missing dependency, bad checkpoint) shows up in /health.
                await r.set(WORKER_STATUS_KEY, json.dumps({
                    "url_nlp": self.url_analyzer._model is not None,
                    "behavior": self.behavior_analyzer._model is not None,
                    "vision": self.vision_analyzer._cnn is not None,
                }), ex=15)
                item = await r.brpop(ML_QUEUE_KEY, timeout=3)
                if item is None:
                    continue

                _, raw = item
                payload = json.loads(raw)
                job_id = payload.get("job_id")
                target = payload.get("target", "")
                sandbox = payload.get("sandbox", {})

                logger.info(f"Processing ML job: {job_id}")

                url_result = self.url_analyzer.analyze(target)
                behavior_result = self.behavior_analyzer.analyze(sandbox)
                vision_result = self.vision_analyzer.analyze(sandbox)

                result = {
                    "job_id": job_id,
                    "url_nlp": url_result,
                    "behavior": behavior_result,
                    "vision": vision_result,
                }

                await r.set(
                    f"{ML_RESULT_PREFIX}{job_id}",
                    json.dumps(result),
                    ex=3600
                )
                logger.info(f"ML job complete: {job_id}")

                # Accumulate for batched MLflow logging — see _log_inference_batch docstring
                self._inference_batch.append(result)
                if len(self._inference_batch) >= INFERENCE_LOG_BATCH_SIZE:
                    self._log_inference_batch()

            except Exception as e:
                logger.exception(f"ML worker error: {e}")
                await asyncio.sleep(1)

        # Flush any remaining partial batch before shutting down — otherwise
        # up to INFERENCE_LOG_BATCH_SIZE-1 predictions silently vanish from
        # tracking every time the worker restarts/redeploys.
        if self._inference_batch:
            logger.info(f"Flushing final partial batch of {len(self._inference_batch)} predictions before shutdown")
            self._log_inference_batch()

        await r.aclose()
        logger.info("ML Worker stopped")

    def stop(self):
        self._running = False


async def main():
    worker = MLWorker()

    def shutdown(sig, frame):
        logger.info(f"Signal {sig} received, shutting down…")
        worker.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
