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
│  (FIFO + WS)   │     │   Playwright headless Chromium        │
└─────────────────┘     │   • Intercepts every network request  │
         ▲              │   • Captures process events           │
         │              │   • Detects password fields           │
         │              │   • Takes a screenshot                │
         │              │   Destroyed after execution ✓         │
         │              └──────────────┬───────────────────────┘
         │                             │ telemetry JSON
         │              ┌──────────────▼───────────────────────┐
         │              │         ML Pipeline                   │
         │              │                                       │
         │              │  ① URL NLP        score × 0.25       │
         │              │  ② Behavior       score × 0.45       │
         │              │  ③ Vision CNN     score × 0.30       │
         │              │                                       │
         │              │  Weighted aggregate → SAFE /          │
         └──────────────│  SUSPICIOUS / MALICIOUS              │
    WebSocket stream    └───────────────────────────────────────┘
```

### The three models

| # | Model | Input | What it detects |
|---|-------|-------|-----------------|
| 1 | **URL NLP** | Raw URL string | Shannon entropy, DGA domains, brand spoofing, IP-in-URL, typosquatting, redirect params |
| 2 | **Behavior** | Sandbox telemetry | Binary downloads, C2 port connections, encoded PowerShell, process injection, sensitive file writes |
| 3 | **Vision CNN** | Screenshot + page title | Trained ResNet18 classifies the screenshot's brand resemblance; combined with a domain-ownership check to flag impersonation. Falls back to rule-based color/keyword heuristics when no screenshot is available |

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
│   │   ├── orchestrator.py      # Job runner — Docker lifecycle + ML dispatch
│   │   └── run.py               # Playwright script (executes inside container)
│   ├── ml/
│   │   ├── url_nlp/analyzer.py  # Model 1
│   │   ├── behavior/analyzer.py # Model 2
│   │   ├── vision/
│   │   │   ├── analyzer.py            # Model 3 — loads the trained CNN, falls back to rules
│   │   │   ├── TRAINING_NOTES.md      # Honest writeup: what was trained, on what data, and why
│   │   │   ├── models/phishing_resnet18.pt  # Trained checkpoint (committed, 43MB)
│   │   │   ├── training/train.py      # Dataset-agnostic training script
│   │   │   ├── training/predict.py    # Standalone inference/verification script
│   │   │   └── dataset/synthetic_generator.py  # Bootstraps a Phish-IRIS-structured dataset
│   │   └── worker.py            # Standalone ML worker process
│   ├── job_queue_service/job_queue.py  # Redis FIFO queue (named to avoid colliding with stdlib `queue`)
│   ├── tests/
│   │   ├── conftest.py
│   │   └── test_ml_models.py    # unit tests across all 3 models (see "Running tests" below)
│   ├── requirements.txt
│   ├── requirements-ml.txt
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
- URL NLP: safe URLs score low, IPs/brand mismatches/DGA domains score high, schema validation, score clamping
- Behavior: safe/malicious sandboxes, binary download detection, encoded PowerShell, empty input
- Vision: brand mismatch, urgency language, confidence reduction without screenshot, rule-based fallback when no screenshot is present (the CNN can't run without pixels)
- Aggregate: end-to-end high/low risk scenarios

(21 tests, all passing — see `tests/test_ml_models.py`)

---

## Extending

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

### URL NLP and Behavior models — currently rule-based, not yet trained

Unlike Vision, the URL NLP and Behavior analyzers are **hand-weighted rule
classifiers**, not trained models — there is no dataset, training script, or
serialized model backing them yet. They were deliberately built this way:
fully interpretable scoring (every score ships with a plain-English reason),
and no labelled dataset was sourced for either.

Both expose a `_extract_features()` method that already produces a clean,
fixed-length numeric feature vector — this is the integration point for a
real classifier:

```python
from ml.url_nlp.analyzer import URLAnalyzer

analyzer = URLAnalyzer()
features = analyzer._extract_features("http://paypal-verify.xyz/login")
# → dict of ~20 numeric/boolean features: entropy, digit_ratio, brand_mismatch, etc.
```

To convert either to a trained model: collect labelled samples (PhishTank/
OpenPhish for malicious URLs, Tranco/Majestic top-1M for benign; sandboxed
malware execution logs from CAPE/VirusTotal for behavior), extract feature
vectors with the existing `_extract_features()`, and train a
`RandomForestClassifier` or `XGBClassifier` — both models have small (~20
feature) tabular inputs that suit tree ensembles better than deep learning.
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
