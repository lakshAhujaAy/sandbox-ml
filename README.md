# MalSandbox ML

> Dynamic malware analysis sandbox with a three-model ML pipeline — URL NLP · Behavior classifier · Vision CNN

[![CI](https://github.com/your-username/sandbox-ml/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/sandbox-ml/actions)
[![Python](https://img.shields.io/badge/python-3.11-blue?logo=python)](https://www.python.org)
[![React](https://img.shields.io/badge/react-18-61dafb?logo=react)](https://react.dev)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Submit a URL → it runs inside a disposable Docker container → three independent ML models analyse the telemetry → you get a verdict in seconds.

---

## How it works

```
Submit URL
    │
    ▼
┌─────────────────┐     ┌──────────────────────────────────────┐
│  Redis Queue    │────▶│   Isolated Docker Container          │
│  (FIFO + WS)    │     │   Playwright headless Chromium        │
└─────────────────┘     │   • Intercepts every network request  │
         ▲              │   • Captures process events           │
         │              │   • Detects password fields           │
         │              │   • Takes a screenshot                │
         │              │   Destroyed after execution ✓         │
         │              └──────────────┬───────────────────────┘
         │                             │ telemetry JSON, via Redis
         │              ┌──────────────▼───────────────────────┐
         │              │   ml-worker (separate container)      │
         │              │   No connection to the API process —  │
         │              │   the orchestrator pushes a job here  │
         │              │   and polls sandbox:ml_result:{id}    │
         │              │                                       │
         │              │  ① URL NLP        score × 0.25       │
         │              │  ② Behavior       score × 0.45       │
         │              │  ③ Vision CNN     score × 0.30       │
         │              │     (trained ResNet18)                │
         │              │                                       │
         │              │  Weighted aggregate → SAFE /          │
         └──────────────│  SUSPICIOUS / MALICIOUS              │
    WebSocket stream    └───────────────────────────────────────┘
```

ML inference runs in its own container (`ml-worker` in `docker-compose.yml`),
not inline in the API process. This keeps the API container lightweight — it
never imports torch/torchvision — and means ML capacity can scale independently
of API instances. The handoff is pure Redis: the orchestrator pushes
`{job_id, target, sandbox}` onto `sandbox:ml_queue`; `ml-worker` consumes it,
runs all three models, and writes the result to `sandbox:ml_result:{job_id}`,
which the orchestrator polls for (timing out and surfacing a job error after
`ML_TIMEOUT` seconds if the worker is down).

### The three models

All three now have a trained-model primary path with rule-based fallback —
see [`reports/EVALUATION_REPORT.md`](backend/reports/EVALUATION_REPORT.md)
for real performance numbers, and each model's own `TRAINING_NOTES.md` for
the full honest story (including 4 real bugs found and fixed during
development — not hypothetical, documented with the empirical proof for
each).

| # | Model | Input | Trained on | What it detects |
|---|-------|-------|-----------|-----------------|
| 1 | **URL NLP** | Raw URL string | **Real** 88,647-row dataset ([GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)) — 93.0% test accuracy, 82.5% recall on held-out real PhishTank URLs | Random Forest over 98 lexical features: entropy, DGA domains, brand spoofing, IP-in-URL, typosquatting, redirect params |
| 2 | **Behavior** | Sandbox telemetry | Synthetic telemetry (bootstrap — no public dataset exists), grounded in named MITRE ATT&CK techniques | Random Forest over 11 behavioral features: binary downloads, C2 port connections, encoded PowerShell, process injection, sensitive file writes |
| 3 | **Vision CNN** | Screenshot + page title | Synthetic login-page screenshots (bootstrap — real dataset blocked by sandbox network/browser limits, see Vision's TRAINING_NOTES.md) | Trained ResNet18 classifies the screenshot's brand resemblance; combined with a domain-ownership check to flag impersonation |

**Honesty note, stated plainly:** only URL NLP has real-world-validated
numbers. Behavior and Vision's reported 100% test accuracy reflects how
cleanly separable their *synthetic* training data is, not real-world
detection capability — both models' `TRAINING_NOTES.md` say this explicitly
and document a real false-positive/limitation found during validation. All
three models fall back to interpretable rule-based heuristics if the
trained model or its dependencies aren't available.

---

## Quick start

**Requirements:** Docker + Docker Compose

```bash
git clone https://github.com/your-username/sandbox-ml
cd sandbox-ml
cp .env.example .env
bash scripts/start.sh
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

### Run it from a permanent URL (no localhost)

The root `Dockerfile` packages the whole system, including all three trained
models, into one container. See [DEPLOY.md](DEPLOY.md) for hosting options,
settings and security notes.

```bash
docker build -t malsandbox . && docker run -p 7860:7860 -e BASIC_AUTH_PASSWORD=pick-one malsandbox
python scripts/smoke_test.py http://localhost:7860 --password pick-one
```

### Local dev (no Docker)

```bash
# Terminal 1 — Redis
docker run -p 6379:6379 redis:7-alpine

# Terminal 2 — Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-ml.txt  # includes torch/torchvision for the vision CNN — a few hundred MB, can take a few minutes
uvicorn api.main:app --reload --port 8000

# Terminal 3 — Frontend
cd frontend && npm install && npm start
```

---

## API

### Submit a URL

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "https://paypal-verify.xyz/login", "target_type": "url"}'
```

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "target": "https://paypal-verify.xyz/login",
  "submitted_at": "2025-01-15T10:30:00.000Z"
}
```

### Poll for results

```bash
curl http://localhost:8000/jobs/550e8400-e29b-41d4-a716-446655440000
```

The `vision` result includes a `model_source` field — `"cnn"` when the trained
ResNet18 ran on a real screenshot, or `"rule_based_fallback"` when no screenshot
was available (the CNN can't run without pixels to look at):

```json
{
  "vision": {
    "model": "vision",
    "model_source": "cnn",
    "score": 0.87,
    "threat_level": "malicious",
    "reasoning": ["Vision model identified page as visually matching 'paypal' (confidence 99.1%) but the domain does not belong to paypal — likely impersonation"]
  }
}
```

### Stream live events (WebSocket)

```js
const ws = new WebSocket("ws://localhost:8000/ws/<job_id>");
ws.onmessage = e => console.log(JSON.parse(e.data));
// events: status | stage | done | error
```

---

## Project structure

```
sandbox-ml/
├── .github/workflows/ci.yml     # GitHub Actions — lint, test, Docker build
├── backend/
│   ├── api/
│   │   ├── main.py              # FastAPI app — REST + WebSocket endpoints
│   │   ├── models.py            # Pydantic schemas
│   │   └── connection_manager.py
│   ├── sandbox/
│   │   ├── orchestrator.py      # Job runner — Docker lifecycle + ML dispatch (via Redis, not inline)
│   │   └── run.py               # Playwright script (executes inside container)
│   ├── ml/
│   │   ├── url_nlp/
│   │   │   ├── analyzer.py            # Model 1 — loads the trained Random Forest, falls back to rules
│   │   │   ├── feature_extractor.py   # Reproduces the dataset's 98-feature schema from a raw URL string
│   │   │   ├── TRAINING_NOTES.md      # Honest writeup — incl. 2 real bugs found+fixed, with proof
│   │   │   ├── dataset/phishing_dataset_full.csv  # Real 88,647-row dataset (GregaVrbancic/Phishing-Dataset)
│   │   │   ├── training/train.py      # Trains RF/XGBoost, logs to MLflow
│   │   │   └── models/                # Trained checkpoints + training_report_*.json
│   │   ├── behavior/
│   │   │   ├── analyzer.py            # Model 2 — loads the trained Random Forest, falls back to rules
│   │   │   ├── TRAINING_NOTES.md      # Honest writeup — incl. 2 data-leakage bugs found+fixed
│   │   │   ├── dataset/synthetic_telemetry_generator.py  # MITRE ATT&CK-grounded synthetic telemetry
│   │   │   ├── training/train.py      # Trains RF/XGBoost, logs to MLflow
│   │   │   └── models/                # Trained checkpoints + training_report_*.json
│   │   ├── vision/
│   │   │   ├── analyzer.py            # Model 3 — loads the trained CNN, falls back to rules
│   │   │   ├── TRAINING_NOTES.md      # Honest writeup: what was trained, on what data, and why
│   │   │   ├── models/phishing_resnet18.pt  # Trained checkpoint (committed, 43MB)
│   │   │   ├── training/train.py      # Dataset-agnostic training script
│   │   │   ├── training/predict.py    # Standalone inference/verification script
│   │   │   ├── dataset/synthetic_generator.py  # Bootstraps a Phish-IRIS-structured dataset
│   │   │   └── dataset/package/       # Real PhishTank URL collection kit, pending offline run
│   │   └── worker.py            # ML worker process — REQUIRED, runs as its own container; batches live predictions into MLflow every 50 jobs
│   ├── job_queue_service/job_queue.py  # Redis FIFO queue (named to avoid colliding with stdlib `queue`)
│   ├── reports/EVALUATION_REPORT.md    # Consolidated real performance numbers across all 3 models
│   ├── mlflow.db                # SQLite-backed MLflow tracking — every training run + batched live inference
│   ├── scripts/check_eval_report_freshness.py  # Verifies EVALUATION_REPORT.md hasn't drifted from actual training artifacts
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_ml_models.py        # 23 tests across all 3 models
│   │   └── test_feature_extractor.py # 12 tests directly targeting the URL NLP bugs found during development
│   ├── requirements.txt
│   ├── requirements-ml.txt      # includes mlflow, scikit-learn, xgboost, torch/torchvision
│   └── pytest.ini
├── frontend/
│   └── src/App.jsx              # React dashboard — live WS, radar chart, telemetry tabs
├── docker/
│   └── sandbox/Dockerfile       # Playwright + Chromium sandbox image
├── scripts/start.sh             # One-command bootstrap
├── docker-compose.yml
├── .env.example
├── CONTRIBUTING.md
└── CHANGELOG.md
```

---

## Running tests

```bash
cd backend
pytest tests/ -v
```

The test suite covers:
- URL NLP: trained Random Forest predictions, the feature extractor's exact 98-column schema, 2 regression tests for real bugs found during development (scheme-stripping, -1 sentinel handling — see `ml/url_nlp/TRAINING_NOTES.md`), rule-based fallback
- Behavior: trained Random Forest predictions, rule-based fallback's specific signal weighting, safe/malicious telemetry, binary download detection, encoded PowerShell
- Vision: trained CNN predictions, brand/domain mismatch, urgency language, rule-based fallback when no screenshot is present
- Feature extractor: 12 dedicated tests directly targeting the two URL NLP bugs in isolation
- Aggregate: end-to-end high/low risk scenarios

(35 tests, all passing — `tests/test_ml_models.py` + `tests/test_feature_extractor.py`)

---

## Extending

All three models follow the same pattern: a trained classifier as the
primary scoring path, with the original hand-weighted rule-based heuristics
kept as an automatic fallback if the model file or its dependencies
(scikit-learn, joblib, pandas, or torch for Vision) aren't available. See
[`reports/EVALUATION_REPORT.md`](backend/reports/EVALUATION_REPORT.md) for
consolidated real performance numbers across all three, and each model's
own `TRAINING_NOTES.md` for the full narrative — including every bug found
during development, documented with the actual empirical proof rather than
just a fix with no explanation.

### URL NLP — retrain on the real dataset, or your own

Trained on 88,647 **real** labeled URLs
([GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)),
restricted to 98 features computable from a URL string alone (13
lookup-dependent columns requiring live DNS/WHOIS/Google checks were
excluded — `URLAnalyzer` never has network access at inference time). Two
real, serious bugs were found and fixed while wiring this in — both caused
`github.com` to score 90%+ phishing despite 93% test accuracy, both found
by directly comparing extracted features against real training rows. Full
story in [`backend/ml/url_nlp/TRAINING_NOTES.md`](backend/ml/url_nlp/TRAINING_NOTES.md).

```bash
cd backend/ml/url_nlp/training
python train.py --data ../dataset/phishing_dataset_full.csv --model random_forest
# or: --model xgboost (faster inference, slightly lower accuracy)
```

### Behavior — retrain on synthetic telemetry, or real sandbox traces

No public dataset of raw sandbox telemetry exists, so this was bootstrapped
from synthetic data grounded in named MITRE ATT&CK techniques (drive-by
download, PowerShell droppers, C2 beaconing, persistence, credential
harvesting). Two real data-leakage bugs were found and fixed (a host-count
proxy, and a circular pre-labeled-log-line issue) — full story in
[`backend/ml/behavior/TRAINING_NOTES.md`](backend/ml/behavior/TRAINING_NOTES.md),
including a real false positive found during validation (a benign IP-pixel
request scoring 78.7% malicious, since the synthetic data never covered
that case).

```bash
cd backend/ml/behavior/training
python train.py --data ../dataset/synthetic_telemetry.json --model random_forest
```

To retrain on real data: replace `synthetic_telemetry.json` with real
sandbox execution traces (e.g. from CAPE/Cuckoo running real malware
samples from MalwareBazaar) in the same `{network_requests, process_events,
file_operations, logs, label}` schema — the training script imports
`BehaviorAnalyzer._extract_features()` directly rather than reimplementing
feature extraction, so training and inference can never silently diverge.

### Vision CNN — what's already trained, and how to retrain it for real

The vision model is a **ResNet18, trained from scratch**, on a **synthetic
dataset** generated to match the structure of the real Phish-IRIS benchmark
(6 brand classes + "other"/legitimate). This was a deliberate choice — the real
Phish-IRIS dataset requires submitting a manual request form, which wasn't
completed for this version. Training from scratch (no ImageNet pretrained
weights) was also a constraint, not a preference: the training environment
used couldn't reach `download.pytorch.org`.

**What this validates:** the full pipeline — data loading, augmentation,
fine-tuning loop, per-class precision/recall/F1, checkpointing, and inference —
runs correctly end-to-end. The 100% validation accuracy reported in
`ml/vision/models/training_report.json` reflects the synthetic data's low
visual complexity (fixed brand color palettes, template-generated layouts),
**not** real-world phishing detection accuracy.

Full details, the per-epoch training log, and an honest discussion of the
gap to real data are in [`backend/ml/vision/TRAINING_NOTES.md`](backend/ml/vision/TRAINING_NOTES.md) —
read that before discussing this project in an interview.

A real collection attempt was made and packaged for offline use: 340 real,
PhishTank-verified 2020 phishing URLs with human-verified brand labels, plus
a Playwright collection script — see
[`backend/ml/vision/dataset/package/README.md`](backend/ml/vision/dataset/package/README.md).
This couldn't be run in the development sandbox (no browser binary
installable, no arbitrary external network access) and is pending
collection on a machine with normal internet access.

**To retrain on real data:**

```bash
cd backend/ml/vision/training

# Point at any directory structured like:
#   <root>/train/<brand>/*.png   <root>/train/other/*.png
#   <root>/test/<brand>/*.png    <root>/test/other/*.png
# (Phish-IRIS already ships in this exact layout — no preprocessing needed)
python train.py --data-root /path/to/phish-iris --epochs 15

# Verify the new checkpoint
python predict.py --image /path/to/test/image.png
```

No code changes are required to swap datasets — only `--data-root`. If the
training machine can reach `download.pytorch.org`, pretrained ImageNet weights
will be used automatically (the script detects and falls back gracefully if not).

### Experiment tracking — MLflow

All training runs (across all three models) log to a single shared
`backend/mlflow.db` (SQLite backend). Live production inference is also
logged, batched every 50 predictions (not per-request — see
`ml/worker.py`'s docstring for why per-request MLflow runs would be the
wrong granularity) into a `production_inference` experiment, tracking score
distributions and how often each model's trained-vs-fallback path actually
fired — useful for catching a model file silently going missing in
production.

```bash
cd backend
mlflow ui --backend-store-uri sqlite:///mlflow.db
# open http://localhost:5000
```

This is **not yet implemented** — it's the next step, not a finished feature.

### Add a new ML model

1. Create `backend/ml/<name>/analyzer.py` with `analyze(input) -> dict`
2. Register it in `sandbox/orchestrator.py → _handle_job`
3. Add its weight to `_aggregate()`
4. Wire it into the React dashboard
5. Add tests in `backend/tests/test_ml_models.py`

### Scale horizontally

Increase `MAX_WORKERS` in `.env`. Redis distributes jobs automatically across multiple API replicas.

### Integrate CAPE Sandbox

Replace `orchestrator._run_sandbox()` with a call to the CAPE REST API. The ML pipeline remains unchanged — it consumes the same telemetry schema.

---

## Security notes

- The Docker socket is mounted into the API container — use a dedicated sandbox host or rootless Docker in production
- Sandbox containers run with `mem_limit: 256m` and 50% CPU quota to prevent resource exhaustion
- All containers use `remove=True` — no persistence between runs
- Never expose the sandbox API to the public internet without a WAF and rate limiting

---

## License

MIT — see [LICENSE](LICENSE)
