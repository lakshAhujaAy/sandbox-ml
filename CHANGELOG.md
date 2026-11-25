# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.1.0] — Unreleased

### Added — run it from a permanent URL instead of localhost
- Root `Dockerfile`: one image/one port with the dashboard, API, Redis, ML worker
  and headless Chromium. Deploy guide in `DEPLOY.md`.
- `SANDBOX_MODE=subprocess`: runs the Playwright sandbox inside the container, so
  no Docker socket is needed (required by most hosts). A failed run fails the job;
  it never falls back to simulated telemetry in this mode.
- Hosted-mode protections: only public http(s) targets are accepted, the sandbox
  browser blocks requests to private/internal addresses, optional shared password
  (`BASIC_AUTH_PASSWORD`).
- `/health` reports whether the ML worker is up and which trained models actually
  loaded; the dashboard shows it. `scripts/smoke_test.py` checks a live deployment.
- Dashboard is same-origin by default and polls for results if WebSockets are blocked.

### Fixed
- `requirements-ml.txt` pinned scikit-learn 1.4.2 but the committed models were
  pickled with 1.9.0; pins now match.
- `tldextract` no longer downloads its suffix list at runtime (bundled snapshot).
- The queue loop survives transient Redis errors instead of dying silently.
- CI lint rule set is pinned (unpinned `ruff` started failing on new default rules).

## [2.0.0] — 2026-06-22

### Added — real datasets, training pipelines, experiment tracking
- **URL NLP:** trained Random Forest + XGBoost on a **real** 88,647-row
  labeled phishing URL dataset ([GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)).
  93.0% test accuracy, 98.1% ROC-AUC, 82.5% recall on 200 held-out real
  PhishTank URLs from a completely different source/year than training data
- **Behavior:** trained Random Forest + XGBoost on synthetic sandbox
  telemetry grounded in named MITRE ATT&CK techniques (drive-by download,
  PowerShell droppers, C2 beaconing, persistence, credential harvesting)
- **Vision:** now wired into the production `VisionAnalyzer` (was trained
  in a prior version but not yet integrated)
- MLflow experiment tracking (SQLite backend) for all training runs, plus
  batched live-inference logging (every 50 predictions) from `ml/worker.py`
- Consolidated `backend/reports/EVALUATION_REPORT.md` with real metrics
  across all three models, plus a freshness-check script
  (`scripts/check_eval_report_freshness.py`, wired into CI) that fails the
  build if the report's documented numbers drift from the actual
  `training_report_*.json` artifacts
- Per-model `TRAINING_NOTES.md` documenting every real bug found during
  development with empirical proof, not just a changelog line

### Changed — architecture
- ML inference moved fully out of the API process — `sandbox/orchestrator.py`
  no longer imports any ML analyzer directly; it dispatches to `ml/worker.py`
  (a separate container) via Redis and polls for results
- `URLAnalyzer`'s default model switched from Random Forest to XGBoost
  (580KB vs 59MB, for a 0.35 percentage-point accuracy difference) so the
  default checkpoint can ship in the repo

### Fixed — real bugs found during development (not hypothetical)
- **URL NLP:** the feature extractor was including the URL scheme
  (`http://`/`https://`) in character counts the trained model expected to
  exclude — proven by finding 47,509 training rows with `qty_slash_url == 0`,
  impossible if the scheme were included. Caused `github.com` to score 93%+
  phishing despite the model's 93% test accuracy.
- **URL NLP:** absent URL segments (no path/file/query string) must use a
  -1 sentinel, not 0 — conflating these corrupted every feature for any
  bare-domain URL. Found by directly comparing extracted features against
  real training rows with a matching URL shape.
- **URL NLP:** `model_source` field stayed hardcoded to `"random_forest"`
  after the default model was switched to XGBoost, silently mislabeling
  every prediction's source — fixed with an explicit class-name mapping
  (an initial regex-based auto-conversion attempt produced
  `"x_g_b_classifier"`, which was also wrong).
- **Behavior:** `unique_host_count` was a perfect accidental classifier —
  benign/malicious synthetic samples had non-overlapping host-count ranges
  purely as a generator artifact, not a real behavioral signal. Fixed by
  widening both distributions to genuinely overlap.
- **Behavior:** `alert_log_count` was circular — malicious synthetic
  archetypes had pre-labeled "alert" log lines narrating the attack, which
  the model was learning to detect instead of the underlying facts. Fixed
  by stripping alert/warn-level logs before feature extraction during
  training.
- A real false-positive limitation was found (not fixed, documented): a
  benign analytics tracking-pixel request to a raw IP scores 78.7%
  malicious in the Behavior model, since the synthetic training data never
  included a benign example of that pattern.

## [1.0.0] — 2025-01-15

### Added
- FastAPI backend with REST + WebSocket endpoints
- Redis-backed FIFO job queue with pub/sub streaming
- Sandbox orchestrator with Docker container lifecycle management
- Playwright headless browser execution inside isolated containers
- **ML Model 1 — URL NLP:** Shannon entropy, DGA detection, brand mismatch, IP-in-URL, typosquatting heuristics
- **ML Model 2 — Behavior Classifier:** Binary download detection, C2 port analysis, encoded PowerShell detection, process injection heuristics
- **ML Model 3 — Vision CNN:** Brand color palette matching, urgency language detection, phishing layout analysis
- Weighted aggregate scoring (URL 25% · Behavior 45% · Vision 30%)
- React 18 dashboard with live WebSocket feed, radar chart, sandbox telemetry tabs
- Docker Compose orchestration for all services
- GitHub Actions CI pipeline (lint, test, Docker build)
- Comprehensive unit tests for all three ML models
