"""
job_queue_service/constants.py
================================
Redis key names shared between sandbox/orchestrator.py (producer) and
ml/worker.py (consumer). Deliberately has ZERO imports beyond the standard
library — both the lightweight API container and the heavier ML-worker
container (which doesn't need fastapi/pydantic at all, just torch/sklearn)
need these names, so this module must not pull in anything that would force
either container to install dependencies it doesn't otherwise need.
"""

# Main job queue (API <-> orchestrator)
QUEUE_KEY = "sandbox:queue"
JOB_PREFIX = "sandbox:job:"
RECENT_KEY = "sandbox:recent"

# ML dispatch queue (orchestrator <-> ml-worker)
ML_QUEUE_KEY = "sandbox:ml_queue"
ML_RESULT_PREFIX = "sandbox:ml_result:"
WORKER_STATUS_KEY = "sandbox:ml_worker_status"  # JSON written by ml/worker.py, 15s TTL
