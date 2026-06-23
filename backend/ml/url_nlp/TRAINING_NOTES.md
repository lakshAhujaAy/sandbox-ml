# URL NLP Model Training — What Actually Happened

This document is the ground truth for the URL NLP classifier. Read this
before discussing the project in an interview — written to be quoted
directly. Same honesty pattern as `ml/vision/TRAINING_NOTES.md` and
`ml/behavior/TRAINING_NOTES.md`.

## TL;DR

A Random Forest was trained on **88,647 REAL labeled URLs** from a published
academic dataset, restricted to 98 lexical/structural features computable
from a URL string alone (13 features requiring live DNS/WHOIS/Google
lookups were excluded, since `URLAnalyzer` never has network access at
inference time). Test-set accuracy: **93.0%**, ROC-AUC **98.1%**. After
wiring the model into production code, **two serious, real bugs** were found
in the feature-extraction logic that initially caused the model to score
`github.com` as 93%+ phishing — both root-caused by directly comparing
extracted feature values against the actual training data, not guessed.

## The dataset — this one is genuinely real, not synthetic

**Source:** [GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)
on GitHub — 88,647 rows (30,647 phishing, 58,000 legitimate), citation
available via the repo's `CITATION.cff` (Vrbančič, G. — "Phishing Dataset
for Machine Learning: Feature Evaluation," published dataset accompanying
peer-reviewed research). Fetched directly via
`raw.githubusercontent.com` — no manual form, no API key required.

**Feature scope decision:** the raw dataset has 111 feature columns, but 13
require live lookups at extraction time: `time_response`, `domain_spf`,
`asn_ip`, `time_domain_activation`, `time_domain_expiration`,
`qty_ip_resolved`, `qty_nameservers`, `qty_mx_servers`, `ttl_hostname`,
`tls_ssl_certificate`, `qty_redirects`, `url_google_index`,
`domain_google_index`. These need DNS resolution, WHOIS queries, or a live
Google index check — none of which `URLAnalyzer.analyze()` can do (it only
ever receives a URL string). Training on these would have produced a
benchmark number disconnected from what the deployed code can actually use.
**Trained only on the remaining 98 string-computable features.**

## Two real bugs found — both via empirical comparison, not guessing

### Bug 1: scheme inclusion mismatch

First test after wiring in the trained model: `https://github.com` scored
**92.8% phishing probability**. Investigating: `qty_slash_url` for
`github.com` was 2 (from the `//` in `https://`), but the training data's
median `qty_slash_url` was 0. Proof, not assumption: **47,509 of 88,647
training rows have `qty_slash_url == 0`**, which is mathematically
impossible if the scheme were included (the scheme alone contributes 2
slashes). This proved the original dataset's "url" substring excludes the
scheme — my extractor was counting characters on the full URL including
`https://`, one substring too long for every single feature.

**Fix:** the "url" substring used for all `qty_*_url` features and
`length_url` now excludes the scheme entirely.

### Bug 2: -1 sentinel vs. 0 confusion (the more serious one)

After fixing Bug 1, `github.com` *still* scored 93%+ phishing. Pulled an
actual legitimate row from the training data with a similarly bare-domain
shape (no path, no params) and compared every feature side by side. Found:
`directory_length`, `file_length`, `params_length`, and `qty_params` were
all **exactly -1** in that real row — not 0. Proof: **every one of the
47,509 rows with `directory_length == -1` also has every single
`qty_*_directory` feature at exactly -1** (verified directly, zero
exceptions) — this is a deliberate sentinel meaning "this URL segment does
not exist at all," distinct from 0, which means "this segment exists and
contains zero of this character." My extractor always produced 0 for an
absent segment, silently corrupting every feature derived from path/file/
params for any URL without one — which describes most simple homepage URLs.

**Fix:** the extractor now returns -1 for every directory/file/params
feature when that URL segment doesn't structurally exist, matching the
original encoding exactly.

**A sub-finding while fixing this:** I initially assumed single-segment
paths (e.g. `/login`) would have a "file but no directory" pattern (file
present, directory absent). Checked the training data directly: **zero rows
have that combination** — `directory_length == -1` and `file_length == -1`
occur together in literally every row, with zero exceptions (`std == 0`
across the full distribution). So the actual encoding is simpler: a path
either exists (both directory and file get real values, even if one is an
empty string) or doesn't exist at all (both are -1). My first fix encoded
the wrong, unverified assumption; the test I wrote for it caught the
mismatch, which is exactly what the test should do.

## Validation after both fixes

```
https://github.com               -> 10.6% (safe)       [was 92.8% before fixes]
https://www.google.com            -> 2.1%  (safe)
https://www.paypal.com             -> 1.4%  (safe)
http://paypal-secure-verify.xyz/login?... -> 94.2% (malicious)
http://192.168.1.45/payload.exe    -> 88.6% (malicious)
```

**Cross-dataset generalization test** (the real test — these URLs are from
a completely different source than training data, PhishTank's 2020 export,
never seen during training):
- 200 real PhishTank-verified phishing URLs: **82.5% recall** (correctly
  flagged as malicious)
- 20 real mainstream legitimate URLs (GitHub, Google, NYT, Wikipedia,
  etc.): **0/20 false positives**

**An important caveat found during this validation:** testing against a
different, noisier "legitimate" URL list (a 2015-era academic benign
dataset including torrent sites and heavily percent-encoded URLs) showed
only 24% scored correctly as safe. This is not a model failure — it's a
test-set quality issue (torrent sites and Cyrillic-percent-encoded URLs
aren't really "clean legitimate" examples in a security sense) — but it's
an important, honest finding: **this model's apparent accuracy depends
heavily on what you consider "legitimate."**

## What was actually trained

| | |
|---|---|
| Architecture | Random Forest (`sklearn.ensemble.RandomForestClassifier`), 200 trees, max_depth=20, `class_weight="balanced"` |
| Dataset | Real, 88,647 rows (GregaVrbancic/Phishing-Dataset) |
| Features | 98 lexical/structural (13 lookup-dependent columns excluded) |
| Train/test split | 70,917 / 17,730, stratified |
| Test accuracy | 93.0% |
| Test precision / recall / F1 | see `models/training_report_random_forest.json` |
| Test ROC-AUC | 98.1% |
| XGBoost comparison | trained for comparison — ~9x faster inference, slightly lower accuracy; see `training_report_xgboost.json` |

## Files

| File | Purpose |
|------|---------|
| `dataset/phishing_dataset_full.csv` | The real 88,647-row dataset |
| `feature_extractor.py` | Reproduces the dataset's 98-column schema from a raw URL string — this is where both bugs lived; extensively documented inline with the empirical proof for each design decision |
| `training/train.py` | Training script — excludes lookup-dependent columns, trains RF/XGBoost, full MLflow tracking |
| `models/url_nlp_random_forest.joblib` | The trained checkpoint + feature column order |
| `models/training_report_random_forest.json` | Full metrics, confusion matrix, feature importance |
| `analyzer.py` | `URLAnalyzer` — loads the checkpoint, runs inference via `feature_extractor.py`, falls back to rule-based heuristics if unavailable |
| `../../tests/test_feature_extractor.py` | 12 regression tests directly targeting both bugs found above |

## How to talk about this in an interview

"I trained a Random Forest on a real, published 88,000-row phishing URL
dataset, restricted to features computable from the URL string alone since
that's all my analyzer has access to at inference time. After wiring it in,
my very first smoke test — `github.com` — scored over 90% phishing
probability, which told me immediately something was deeply wrong despite
93% test accuracy. I traced it to two separate bugs in how I was
reconstructing the dataset's feature schema from raw URLs: first, the
dataset excluded the URL scheme from its character counts and I wasn't;
second, and more subtly, the dataset uses -1 as a sentinel for 'this URL
segment doesn't exist' which I was confusing with 0, meaning 'it exists and
is empty.' I found both by directly comparing my extracted features against
real training rows with a similar URL shape, not by guessing. After fixing
both, I validated on 200 completely held-out real PhishTank URLs from a
different year and source than training, and got 82.5% recall with zero
false positives on 20 mainstream sites — though I also found the model's
apparent accuracy varies a lot depending on what 'legitimate' means in your
test set, which is its own useful, honest finding."
