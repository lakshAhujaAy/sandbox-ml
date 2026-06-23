"""
ml/behavior/training/train.py
================================
Trains a real classifier (RandomForest, XGBoost) on SYNTHETIC sandbox
telemetry — see ml/behavior/dataset/synthetic_telemetry_generator.py for
full honesty notes on why synthetic data was used here (no public dataset
of raw sandbox telemetry traces exists) and what's real vs simulated about
it (the behavioral archetypes are grounded in named, documented MITRE
ATT&CK techniques; the actual network/process data is synthetic).

Uses the EXACT same 13 features BehaviorAnalyzer._extract_features() already
computes from raw telemetry — this script imports that method directly
rather than reimplementing feature extraction, so there's zero risk of the
training-time and inference-time feature computation silently diverging
(the exact bug class that broke URL NLP's deployment earlier in this
project — see ml/url_nlp/feature_extractor.py's docstring for that story).

Usage:
    python train.py --data ../dataset/synthetic_telemetry.json --model random_forest
"""
import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import mlflow
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))  # backend/
from ml.behavior.analyzer import BehaviorAnalyzer


def load_data(json_path: str, strip_alert_logs: bool = True):
    """
    Loads synthetic telemetry samples and runs them through
    BehaviorAnalyzer._extract_features() — the SAME method used at
    inference time — to produce the training feature vectors. This
    guarantees training-time and inference-time features can never diverge,
    by construction, rather than by careful-but-fallible manual mirroring.

    IMPORTANT — strip_alert_logs (default True): the synthetic generator
    writes pre-labeled "alert"/"warn" level log entries for malicious
    archetypes (e.g. "Binary download detected", "Connection to known C2
    port") as a way of narrating what happened. Found during development:
    leaving these in makes alert_log_count a near-perfect classifier on its
    own (benign=0 always, malicious>=1 always) — but that's circular, since
    those log entries were written BY a human (me) who already knew which
    archetype was malicious, not derived independently. A real classifier
    should learn from raw network/process/file facts, not consume a
    pre-computed verdict disguised as a log line. Stripping these logs (but
    keeping plain "info" level ones, which carry no verdict) forces the
    model to actually learn from binary_download_count, ip_connection_count,
    etc. — the facts a real sandbox would report neutrally.
    """
    with open(json_path) as f:
        samples = json.load(f)

    analyzer = BehaviorAnalyzer()
    rows = []
    for s in samples:
        sample = s
        if strip_alert_logs:
            sample = dict(s)
            sample["logs"] = [entry for entry in s.get("logs", []) if entry.get("level") not in ("alert", "warn")]

        features = analyzer._extract_features(sample)
        # Drop list-valued features (binary_download_urls, suspicious_process_names)
        # — these are for human-readable reasoning, not numeric model input.
        # Convert booleans to int for sklearn.
        numeric_features = {
            k: (int(v) if isinstance(v, bool) else v)
            for k, v in features.items()
            if not isinstance(v, list)
        }
        numeric_features["label"] = 1 if s["label"] == "malicious" else 0
        numeric_features["archetype"] = s["archetype"]
        rows.append(numeric_features)

    df = pd.DataFrame(rows)
    feature_columns = [c for c in df.columns if c not in ("label", "archetype")]
    return df, feature_columns


def train_random_forest(X_train, y_train, **kwargs):
    params = {
        "n_estimators": kwargs.get("n_estimators", 150),
        "max_depth": kwargs.get("max_depth", 12),
        "min_samples_split": kwargs.get("min_samples_split", 4),
        "class_weight": "balanced",
        "random_state": 42,
        "n_jobs": -1,
    }
    model = RandomForestClassifier(**params)
    model.fit(X_train, y_train)
    return model, params


def train_xgboost(X_train, y_train, **kwargs):
    import xgboost as xgb
    params = {
        "n_estimators": kwargs.get("n_estimators", 150),
        "max_depth": kwargs.get("max_depth", 5),
        "learning_rate": kwargs.get("learning_rate", 0.1),
        "scale_pos_weight": (y_train == 0).sum() / max((y_train == 1).sum(), 1),
        "random_state": 42,
        "eval_metric": "logloss",
    }
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train)
    return model, params


def evaluate(model, X_test, y_test, feature_columns, df_test):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_proba),
    }

    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, output_dict=True)

    feature_importance = {}
    if hasattr(model, "feature_importances_"):
        feature_importance = dict(
            sorted(zip(feature_columns, model.feature_importances_.tolist()), key=lambda x: -x[1])
        )

    # Per-archetype breakdown — which malicious techniques does the model
    # actually catch vs miss? More informative than a single aggregate number.
    per_archetype = {}
    for archetype in df_test["archetype"].unique():
        mask = df_test["archetype"] == archetype
        if mask.sum() == 0:
            continue
        arch_preds = model.predict(X_test[mask])
        arch_true = y_test[mask]
        per_archetype[archetype] = {
            "n_samples": int(mask.sum()),
            "accuracy": float(accuracy_score(arch_true, arch_preds)) if len(set(arch_true)) > 0 else None,
        }

    return metrics, cm, report, feature_importance, per_archetype


def main(args):
    mlflow.set_tracking_uri(args.mlflow_uri)
    mlflow.set_experiment("behavior_telemetry_classifier")

    print(f"Loading and feature-extracting from {args.data}...")
    df, feature_columns = load_data(args.data)
    print(f"  {len(feature_columns)} features, {len(df)} samples "
          f"({(df['label']==1).sum()} malicious, {(df['label']==0).sum()} benign)")

    X = df[feature_columns]
    y = df["label"]

    X_train, X_test, y_train, y_test, df_train, df_test = train_test_split(
        X, y, df, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)}  Test: {len(X_test)}")

    with mlflow.start_run(run_name=f"{args.model}_synthetic_telemetry"):
        mlflow.log_param("model_type", args.model)
        mlflow.log_param("n_features", len(feature_columns))
        mlflow.log_param("n_train_samples", len(X_train))
        mlflow.log_param("n_test_samples", len(X_test))
        mlflow.log_param("dataset_source", "synthetic_telemetry_generator (bootstrap, not real malware)")

        print(f"\nTraining {args.model}...")
        start = time.time()
        if args.model == "random_forest":
            model, params = train_random_forest(X_train, y_train, n_estimators=args.n_estimators)
        elif args.model == "xgboost":
            model, params = train_xgboost(X_train, y_train, n_estimators=args.n_estimators)
        else:
            raise ValueError(f"Unknown model type: {args.model}")
        train_time = time.time() - start

        for k, v in params.items():
            mlflow.log_param(k, v)
        mlflow.log_metric("train_time_seconds", train_time)

        print(f"Trained in {train_time:.2f}s. Evaluating...")
        metrics, cm, report, feature_importance, per_archetype = evaluate(
            model, X_test, y_test, feature_columns, df_test
        )

        for k, v in metrics.items():
            mlflow.log_metric(k, v)

        print("\n=== Test Set Results ===")
        for k, v in metrics.items():
            print(f"  {k}: {v:.4f}")

        print("\nConfusion matrix [benign, malicious]:")
        print(f"  {cm}")

        print("\nFeature importance:")
        for feat, imp in feature_importance.items():
            print(f"  {feat}: {imp:.4f}")

        print("\nPer-archetype accuracy (test set):")
        for arch, stats in per_archetype.items():
            acc_str = f"{stats['accuracy']:.2f}" if stats['accuracy'] is not None else "N/A"
            print(f"  {arch:25} n={stats['n_samples']:3}  accuracy={acc_str}")

        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        model_path = out_dir / f"behavior_{args.model}.joblib"
        joblib.dump({"model": model, "feature_columns": feature_columns}, model_path)
        mlflow.log_artifact(str(model_path))

        report_data = {
            "model_type": args.model,
            "dataset_source": "synthetic (bootstrap) — see synthetic_telemetry_generator.py docstring",
            "n_features": len(feature_columns),
            "feature_columns": feature_columns,
            "n_train_samples": int(len(X_train)),
            "n_test_samples": int(len(X_test)),
            "params": params,
            "metrics": metrics,
            "confusion_matrix": cm,
            "classification_report": report,
            "feature_importance": feature_importance,
            "per_archetype_accuracy": per_archetype,
            "train_time_seconds": train_time,
        }
        report_path = out_dir / f"training_report_{args.model}.json"
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)
        mlflow.log_artifact(str(report_path))

        print(f"\nModel saved -> {model_path}")
        print(f"Report saved -> {report_path}")
        print(f"MLflow run: {mlflow.active_run().info.run_id}")

    return report_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../dataset/synthetic_telemetry.json")
    parser.add_argument("--model", choices=["random_forest", "xgboost"], default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=150)
    parser.add_argument("--output-dir", default="../models")
    parser.add_argument("--mlflow-uri", default=None,
                         help="MLflow tracking URI. Defaults to backend/mlflow.db (one shared "
                              "file for the whole project), resolved as an ABSOLUTE path anchored "
                              "to this script's own location, not the working directory.")
    args = parser.parse_args()

    if args.mlflow_uri is None:
        backend_dir = Path(__file__).parent.parent.parent.parent  # backend/
        args.mlflow_uri = f"sqlite:///{backend_dir / 'mlflow.db'}"

    main(args)
