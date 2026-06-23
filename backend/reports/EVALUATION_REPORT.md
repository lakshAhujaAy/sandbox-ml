# Model Evaluation Report

**Last updated:** generated from the actual training artifacts in
`ml/*/models/training_report_*.json` — every number below is pulled directly
from those files or from validation scripts re-run at report time, not
hand-typed from memory. Run `python scripts/check_eval_report_freshness.py`
(from `backend/`) after retraining any model to verify this report's
numbers haven't silently drifted out of date — it diffs the documented
percentages against the current `training_report_*.json` files and fails
loudly if they disagree.

This report covers all three models honestly — including where synthetic
data was used, what bugs were found and fixed, and where real-world
performance is expected to differ from the numbers below. Read the
model-specific `TRAINING_NOTES.md` files for full narrative detail; this
document is the numbers-first summary.

---

## Summary table

| Model | Dataset | Real or synthetic | Test accuracy | ROC-AUC | Cross-dataset validation |
|---|---|---|---|---|---|
| **URL NLP** | [GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset), 88,647 rows | **Real** | 93.0% | 98.1% | 82.5% recall on 200 held-out real PhishTank URLs; 0/20 false positives on mainstream sites |
| **Behavior** | Synthetic sandbox telemetry, 800 samples | Synthetic (bootstrap) | 100% | 100% | Found a real false positive on a benign IP-literal pattern not covered by the synthetic generator (see below) |
| **Vision** | Synthetic login-page screenshots, 560 images | Synthetic (bootstrap) | 100% | — | Not independently cross-validated against real screenshots (blocked — see `ml/vision/TRAINING_NOTES.md`) |

**The headline takeaway:** only URL NLP has real-world-validated numbers.
Behavior and Vision's 100% scores are properties of how clean their
synthetic data is, not real-world claims — both `TRAINING_NOTES.md` files
say this explicitly, and this report repeats it here so it can't be missed
by skimming just the summary table.

---

## URL NLP — full detail

**Real dataset, real validation.** This is the only model in the project
with genuine, defensible accuracy numbers.

### Training metrics (held-out test set, 17,730 samples from the same dataset)

| Metric | Random Forest | XGBoost |
|---|---|---|
| Accuracy | 93.04% | 92.69% |
| Precision | 87.02% | — |
| Recall | 93.87% | — |
| F1 | 90.32% | — |
| ROC-AUC | 98.14% | 98.03% |
| Avg inference time | 0.060ms/sample | 0.010ms/sample (6x faster) |

Random Forest was chosen as the production default for slightly higher
recall; XGBoost is the better choice if inference latency at scale matters
more than the ~1.5 point accuracy gap.

### Cross-dataset validation (the numbers that actually matter)

Test-set accuracy measures performance on data from the *same* source as
training. The real question is generalization to genuinely novel data:

- **200 real PhishTank-verified phishing URLs (2020 export, completely
  different source than training data):** 82.5% recall, mean score 0.762
- **20 real mainstream legitimate URLs** (GitHub, Google, Wikipedia, NYT,
  PayPal, Chase, etc.): **0/20 false positives**
- **Important caveat found during validation:** testing against a noisier,
  decade-old "benign" URL list (torrent sites, heavily percent-encoded
  URLs) showed only ~24% scored correctly as safe — not a model failure,
  but a reminder that apparent accuracy depends heavily on test-set quality

### Bugs found and fixed (see `ml/url_nlp/TRAINING_NOTES.md` for full detail)

1. **Scheme-inclusion mismatch** — the trained model's features must exclude
   `http://`/`https://` from character counts; the extractor initially
   included it, causing `github.com` to score 92.8% phishing
2. **-1 sentinel vs. 0 confusion** — absent URL segments (no path/file/
   params) must use -1, not 0, in 13 of the 98 feature columns; conflating
   these corrupted predictions for any URL without a path

Both were found by directly comparing extracted feature values against
real training-data rows, not guessed — see the training notes for the
exact empirical proof for each.

---

## Behavior — full detail

**Synthetic dataset, real bugs found in the synthetic data itself.**

### Training metrics (held-out synthetic test set, 160 samples)

| Metric | Random Forest | XGBoost |
|---|---|---|
| Accuracy | 100% | 100% |
| Precision / Recall / F1 | 100% / 100% / 100% | 100% / 100% / 100% |
| Per-archetype accuracy | 100% on all 7 archetypes | 100% on all 7 archetypes |

### Why these numbers don't mean what they'd mean on real data

Two real data-leakage bugs were found and fixed during development (full
empirical proof in `ml/behavior/TRAINING_NOTES.md`):

1. **`unique_host_count` was a perfect accidental proxy** — benign sessions
   sampled many distinct hosts, malicious archetypes contacted very few,
   purely as a generator artifact. Fixed by widening both distributions to
   genuinely overlap.
2. **`alert_log_count` was circular** — malicious archetypes had
   pre-labeled "alert" log lines narrating the attack, which is the
   answer disguised as a feature. Fixed by stripping alert/warn-level logs
   before feature extraction during training.

After both fixes, feature importance is spread across 5 genuinely
behavioral signals (`ip_connection_count` 21.6%, `unique_host_count`
20.5%, `network_request_count` 18.2%, `binary_download_count` 14.7%,
`suspicious_process_count` 10.5%) with no single dominant proxy — but **the
model still hits 100%**, because each of the 7 synthetic archetypes is
designed around a clean, distinct technique with no archetype straddling
the benign/malicious boundary. This is expected, not a sign of real-world
readiness.

### A real false positive, found by deliberately testing outside the archetypes

A benign analytics tracking-pixel request to a raw IP address (a common,
legitimate pattern) scored **78.7% malicious** — because the synthetic
generator never included a benign example of an IP-literal connection.
This is a genuine coverage gap in the synthetic data, documented rather
than quietly patched.

---

## Vision — full detail

**Synthetic dataset, trained from scratch (no pretrained weights reachable).**
See `ml/vision/TRAINING_NOTES.md` for the full story — summarized here:

- ResNet18, trained from scratch (training environment couldn't reach
  `download.pytorch.org` for ImageNet weights)
- 560 synthetic login-page screenshots, 7 classes (6 brands + legitimate)
- 100% validation accuracy — explicitly attributed in the training notes to
  the synthetic data's clean, fixed color palettes per brand and limited
  layout variation, not real-world phishing detection capability
- Verified to generalize to a freshly-generated (different random seed)
  synthetic sample correctly classifying as the right brand — confirms the
  training pipeline works end-to-end, does NOT confirm real-world accuracy
- A real attempt was made to source real screenshots: 340 real,
  PhishTank-verified 2020 phishing URLs with human-verified brand labels
  were identified and packaged (`backend/ml/vision/dataset/package/` — see
  that folder's README) for collection on a machine with real browser/
  network access, since the agent's sandbox could install neither a
  browser binary nor reach arbitrary external sites. Real-data retraining
  is pending that collection step.

---

## What "real datasets, training pipelines, evaluation metrics, experiment
tracking, model performance reports" actually means for this project

Being explicit about scope, since this phrase covers a lot of ground:

| Requirement | URL NLP | Behavior | Vision |
|---|---|---|---|
| Real dataset | ✅ 88,647 real rows | ❌ synthetic (no public dataset exists) | ❌ synthetic (real one blocked by sandbox network/browser limits) |
| Training pipeline | ✅ `training/train.py` | ✅ `training/train.py` | ✅ `training/train.py` |
| Evaluation metrics | ✅ real cross-dataset validation | ⚠️ synthetic-only, documented limitation | ⚠️ synthetic-only, documented limitation |
| Experiment tracking | ✅ MLflow, 5 runs | ✅ MLflow, 6 runs | ⚠️ not yet wired into MLflow (trained before MLflow was added to the project) |
| Performance report | ✅ this file + TRAINING_NOTES.md | ✅ this file + TRAINING_NOTES.md | ✅ this file + TRAINING_NOTES.md |

---

## Reproducing these numbers

```bash
cd backend

# URL NLP — writes to ml/url_nlp/models/ and logs to backend/mlflow.db
cd ml/url_nlp/training && python train.py --data ../dataset/phishing_dataset_full.csv --model random_forest
cd ../../../..

# Behavior — writes to ml/behavior/models/ and logs to the same backend/mlflow.db
cd ml/behavior/training && python train.py --data ../dataset/synthetic_telemetry.json --model random_forest
cd ../../../..

# Verify this report's numbers still match after retraining
python scripts/check_eval_report_freshness.py

# Browse every training run interactively (params, metrics, artifacts)
mlflow ui --backend-store-uri sqlite:///mlflow.db
```

Then open `http://localhost:5000`.
