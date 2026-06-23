# Behavior Model Training — What Actually Happened

This document is the ground truth for the Behavior classifier. Read this
before discussing the project in an interview — it's written to be quoted
directly. Same honesty pattern as `ml/vision/TRAINING_NOTES.md`.

## TL;DR

A Random Forest was trained on **800 synthetic sandbox telemetry samples**
(400 benign, 400 malicious), achieving 100% test accuracy. The synthetic
data went through **two rounds of real debugging** after the first training
run revealed the model had found unintentional shortcuts ("leaks") rather
than learning genuine behavioral patterns — both were found empirically by
inspecting feature distributions, not assumed, and both are documented below
along with a real false-positive case discovered during validation.

## Why synthetic data

No public dataset of raw sandbox telemetry (network requests + process
events + file operations, in this schema) paired with malicious/benign
labels exists. Datasets like EMBER and SOREL-20M provide static PE file
features, not dynamic execution traces. Generating real traces would require
an actual isolated malware sandbox and real malware samples — out of scope
for this project, same constraint that led to Vision's synthetic bootstrap.

**What's real about this data:** every malicious archetype is grounded in a
named, documented MITRE ATT&CK technique (drive-by download / T1189,
PowerShell dropper / T1059.001, C2 beaconing / T1071 + T1571, filesystem
persistence / T1547, credential harvesting / T1056.003) — these aren't
arbitrary made-up rules, they're real attack patterns.

**What's not real:** no actual malware ran. No real network traffic, no
real process trees. The generator constructs plausible-looking telemetry
that exercises these techniques structurally.

## Two real bugs found during development (not hypothetical — these happened)

### Bug 1: `unique_host_count` was a perfect, accidental proxy

First training run hit 100% accuracy with XGBoost assigning **100% of
feature importance to a single feature**, `unique_host_count`, with every
other feature at exactly 0.0. Investigating why: benign sessions sampled
3-15 *distinct* domains from a fixed list without replacement, while every
malicious archetype only ever contacted 1-2 specific malicious URLs. This
was a generator design artifact, not a real fact about malware — real C2
infrastructure frequently domain-fronts through many legitimate-looking
CDN hosts before the actual callback, and real benign traffic can be sparse
(a single static page with no CDN dependencies).

**Fix:** added a 1-4 host CDN-fronting prefix to ~50% of C2 beaconing
samples, and widened benign host sampling to 1-15 with replacement (allowing
low/repeated counts). After the fix, benign and malicious `unique_host_count`
ranges genuinely overlap (`{1,2,3,4,5}` shared between both classes).

### Bug 2: `alert_log_count` was circular

After fixing bug 1, Random Forest's importance shifted to `alert_log_count`
at 35-44% — still suspiciously dominant. Inspection showed every malicious
archetype's generator wrote a pre-labeled `"level": "alert"` log line (e.g.
*"Binary download detected"*, *"Connection to known C2 port"*) narrating what
happened, while benign archetypes never used that log level. This is
circular: those log lines were written by a human (me) who already knew the
ground-truth label, not derived independently from raw facts. A real
classifier should learn from raw network/process/file data, not consume a
pre-computed verdict disguised as a log line.

**Fix:** the training script now strips `alert`/`warn`-level log entries
before feature extraction by default (`strip_alert_logs=True` in
`train.py`'s `load_data()`), forcing the model to learn from
`binary_download_count`, `ip_connection_count`, etc. — the underlying facts
— rather than a log message that already contains the answer. Also fixed an
inconsistency this surfaced: `password_form_detected`'s log message had been
written at `"warn"` level in one archetype and `"info"` in another, which
would have made the alert-stripping fix accidentally *invert* that signal;
both are now consistently `"info"` (detecting a password field is a neutral
fact, not inherently alert-worthy — the credential harvester's actual
malicious signal is the suspicious IP connection alongside it, logged
separately at `"alert"` level).

## What was actually trained (after both fixes)

| | |
|---|---|
| Architecture | Random Forest (`sklearn.ensemble.RandomForestClassifier`), 150 trees, max_depth=12 |
| Dataset | Synthetic, 800 samples (400 benign / 400 malicious), 7 archetypes |
| Features | 11 numeric features — the exact same ones `BehaviorAnalyzer._extract_features()` computes at inference time (imported directly, not reimplemented, to guarantee training/inference parity) |
| Train/test split | 640 / 160, stratified |
| Final test accuracy | 100% (160/160) |
| Per-archetype accuracy | 100% on all 7 archetypes |
| Feature importance (top 3) | `ip_connection_count` (21.6%), `unique_host_count` (20.5%), `network_request_count` (18.2%) — `alert_log_count` correctly dropped to 0.0% importance after the fix, confirming the leak is gone |

Full metrics in `ml/behavior/models/training_report_random_forest.json`.
XGBoost was also trained for comparison — see
`training_report_xgboost.json`.

## Why 100% accuracy is still not fully trustworthy (even after fixing both leaks)

Each of the 7 archetypes triggers a distinct, designed combination of
signals (drive-by → binary download; PowerShell dropper → encoded args;
persistence → sensitive file write). With 7 cleanly-separated archetypes and
no archetype straddling the benign/malicious boundary, **100% on this
specific synthetic test set is expected**, not impressive — it reflects how
the data was constructed, not genuine real-world ambiguity. Real sandbox
telemetry is far noisier: benign software does sometimes write to
sensitive paths (installers), sometimes spawns `cmd.exe` legitimately
(batch scripts), and malicious actors increasingly avoid the most obvious
signals (no more cleartext `-EncodedCommand`, for instance) specifically to
evade pattern-based detection.

## A real false positive, found during validation

While stress-testing the trained model on a case not matching any clean
archetype — a single benign analytics tracking-pixel request to a raw IP
address (a real, common, legitimate pattern), with everything else clean —
the model scored it **78.7% malicious**. This happens because
`ip_connection_count` was *only ever* nonzero in malicious training samples;
the synthetic data never included a benign example of an IP-literal request.
This is a genuine coverage gap, not a hidden bug — documented here rather
than fixed by quietly patching the test case, since the honest lesson is
that synthetic data's negative examples are only as good as the generator
author's imagination, and this generator's author (me) didn't think to
include benign IP-literal traffic until it broke.

## What changes for a more defensible version

1. **Source real sandbox traces.** Run actual malware samples (e.g. from
   MalwareBazaar, with appropriate isolation) through a real sandbox (Cuckoo,
   CAPE) and pair with real benign software execution traces. This is the
   only way to get genuine signal noise and edge cases like the IP-pixel
   false positive above.
2. **Add benign coverage for every "suspicious" pattern.** Specifically:
   benign IP-literal connections (analytics, some CDNs), benign use of
   `cmd.exe`/`powershell.exe` (legitimate installers, IT scripts), benign
   writes to startup folders (legitimate auto-update software).
3. **Move from archetype-level generation to compositional generation** —
   instead of 7 fixed scenarios, randomly combine individual signals with
   independently-randomized presence/absence, so the model has to learn
   real decision boundaries rather than memorize 7 cluster centroids.
4. **Re-run the same leak-detection process** (check feature distributions
   for suspiciously clean separation, check feature importance for single
   dominant features) on whatever real data is eventually sourced — this
   is a repeatable diagnostic, not a one-time fix.

## Files

| File | Purpose |
|------|---------|
| `dataset/synthetic_telemetry_generator.py` | Generates the synthetic telemetry, with full docstrings citing the MITRE ATT&CK technique each malicious archetype represents |
| `dataset/synthetic_telemetry.json` | The generated 800-sample dataset |
| `training/train.py` | Training script — imports `BehaviorAnalyzer._extract_features()` directly (not reimplemented) to guarantee train/inference parity; strips alert-level logs by default per Bug 2 above |
| `models/behavior_random_forest.joblib` | The trained checkpoint |
| `models/training_report_random_forest.json` | Full metrics, confusion matrix, feature importance, per-archetype breakdown |
| `models/training_report_xgboost.json` | XGBoost comparison run |
| `analyzer.py` | `BehaviorAnalyzer` — loads the checkpoint, runs inference, falls back to the original rule-based heuristics if the model/dependencies are unavailable |

## How to talk about this in an interview

"I trained a Random Forest on synthetic sandbox telemetry, since no public
dataset of raw sandbox execution traces exists. The first training run hit
100% accuracy with all the importance loaded onto a single feature — that
was my signal something was wrong, not a success. I traced it to a generator
design flaw where my benign and malicious samples had completely
non-overlapping host counts, purely by accident of how I wrote the data
generator. I fixed that, retrained, and found a second, subtler issue: I'd
written pre-labeled 'alert' log messages into the malicious telemetry that
basically gave the model the answer directly — which is circular, since a
real classifier shouldn't be handed a verdict disguised as a log line. After
stripping those, the model still hits 100% on this specific synthetic test
set, but I don't trust that number as a real-world claim — I validated that
by deliberately testing an edge case outside any of my archetypes, a benign
analytics pixel hitting a raw IP, and it scored 78.7% malicious. That's a
real, honest limitation: the synthetic data's negative examples only cover
what I thought to include."
