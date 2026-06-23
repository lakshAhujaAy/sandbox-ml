"""
scripts/check_eval_report_freshness.py
=========================================
Checks whether reports/EVALUATION_REPORT.md's numbers match what's
currently in the actual training_report_*.json files. Does NOT
auto-regenerate the report's prose (that requires human judgment about what
changed and why — see every TRAINING_NOTES.md for why that matters), but
will print a clear diff if the underlying metrics have drifted from what's
documented, signaling EVALUATION_REPORT.md needs a manual update.

Usage:
    cd backend && python scripts/check_eval_report_freshness.py
"""
import json
import re
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
REPORT_PATH = BACKEND_DIR / "reports" / "EVALUATION_REPORT.md"

CHECKS = [
    {
        "name": "URL NLP Random Forest accuracy",
        "json_path": BACKEND_DIR / "ml/url_nlp/models/training_report_random_forest.json",
        "json_key": ("metrics", "accuracy"),
        "report_pattern": r"\| Accuracy \| ([\d.]+)% \| [\d.]+% \|",
    },
    {
        "name": "URL NLP Random Forest ROC-AUC",
        "json_path": BACKEND_DIR / "ml/url_nlp/models/training_report_random_forest.json",
        "json_key": ("metrics", "roc_auc"),
        "report_pattern": r"\| ROC-AUC \| ([\d.]+)% \| [\d.]+% \|",
    },
    {
        "name": "Behavior Random Forest accuracy",
        "json_path": BACKEND_DIR / "ml/behavior/models/training_report_random_forest.json",
        "json_key": ("metrics", "accuracy"),
        "report_pattern": r"\| Accuracy \| (\d+)% \| \d+% \|\n\| Precision",
    },
]


def get_nested(d: dict, keys: tuple):
    for k in keys:
        d = d[k]
    return d


def main():
    if not REPORT_PATH.exists():
        print(f"ERROR: {REPORT_PATH} not found.")
        sys.exit(1)

    report_text = REPORT_PATH.read_text()
    drift_found = False

    for check in CHECKS:
        if not check["json_path"].exists():
            print(f"⚠️  SKIP: {check['name']} — {check['json_path']} not found "
                  f"(model may not be trained yet)")
            continue

        with open(check["json_path"]) as f:
            data = json.load(f)
        actual_value = get_nested(data, check["json_key"])
        actual_pct = round(actual_value * 100, 1) if actual_value <= 1.0 else actual_value

        match = re.search(check["report_pattern"], report_text)
        if not match:
            print(f"⚠️  Could not find '{check['name']}' pattern in EVALUATION_REPORT.md "
                  f"— report structure may have changed, update the regex in this script")
            continue

        documented_pct = float(match.group(1))

        if abs(actual_pct - documented_pct) > 0.5:  # tolerance for rounding
            drift_found = True
            print(f"❌ DRIFT: {check['name']}")
            print(f"   Documented in report: {documented_pct}%")
            print(f"   Actual (from {check['json_path'].name}): {actual_pct}%")
            print("   -> Re-run training and manually update EVALUATION_REPORT.md")
        else:
            print(f"✅ OK: {check['name']} ({actual_pct}%, matches report)")

    print()
    if drift_found:
        print("Some numbers have drifted. Update reports/EVALUATION_REPORT.md before "
              "presenting it as current.")
        sys.exit(1)
    else:
        print("All checked numbers match the current training artifacts.")


if __name__ == "__main__":
    main()
