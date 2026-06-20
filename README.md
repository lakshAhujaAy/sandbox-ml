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
| 3 | **Vision CNN** | Screenshot + page title | Brand impersonation, phishing color palettes, urgency language, credential-harvesting layouts |

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
pip install -r requirements.txt -r requirements-ml.txt
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
│   │   ├── vision/analyzer.py   # Model 3
│   │   └── worker.py            # Standalone ML worker process
│   ├── job_queue_service/job_queue.py  # Redis FIFO queue (named to avoid colliding with stdlib `queue`)
│   ├── tests/
│   │   ├── conftest.py
│   │   └── test_ml_models.py    # 20 unit tests across all 3 models
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
- Vision: brand mismatch, urgency language, confidence reduction without screenshot
- Aggregate: end-to-end high/low risk scenarios

---

## Extending

### Train a real Random Forest on your own data

```python
# 1. Collect labelled samples
samples = [{"url": "...", "label": 1}, ...]  # 1 = malicious

# 2. Extract feature vectors using the existing pipeline
from ml.url_nlp.analyzer import URLAnalyzer
analyzer = URLAnalyzer()
X = [list(analyzer._extract_features(s["url"]).values()) for s in samples]
y = [s["label"] for s in samples]

# 3. Train and serialize
from sklearn.ensemble import RandomForestClassifier
import joblib
clf = RandomForestClassifier(n_estimators=200)
clf.fit(X, y)
joblib.dump(clf, "backend/models/url_nlp.joblib")

# 4. Load in analyzer.py and replace _score() with clf.predict_proba()
```

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
