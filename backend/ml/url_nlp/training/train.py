"""
ml/url_nlp/training/train.py
================================
Trains a real classifier (RandomForest, XGBoost) on a REAL labeled phishing
URL dataset, restricted to lexical/structural features computable from the
URL string alone — i.e. features URLAnalyzer can actually produce at
inference time without any network lookup.

DATASET: GregaVrbancic/Phishing-Dataset (88,647 rows, 30,647 phishing /
58,000 legitimate), MIT-style open dataset, hosted on GitHub:
https://github.com/GregaVrbancic/Phishing-Dataset
Citation: Vrbančič, G. (2020). Phishing Dataset for Machine Learning:
Feature Evaluation. Available via the same repo's CITATION.cff.

IMPORTANT FEATURE SCOPE: the raw dataset has 111 features, but 13 require
live lookups (DNS resolution, WHOIS domain age, Google index status, SSL
certificate inspection, HTTP response timing). Those CANNOT be computed by
URLAnalyzer at inference time — it only ever sees a URL string, no network
access. This script trains ONLY on the remaining 98 lexical/structural
features, so the trained model is actually deployable in the existing
analyzer, not just a benchmark exercise disconnected from the real codebase.

Usage:
    python train.py --data ../dataset/phishing_dataset_full.csv --model random_forest
    python train.py --data ../dataset/phishing_dataset_full.csv --model xgboost
"""
import argparse
import json
import time
from pathlib import Path

import joblib
import mlflow
import mlflow.sklearn
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split


# Features requiring live network lookups at inference time — excluded because
# URLAnalyzer only ever receives a URL string, never live DNS/WHOIS/Google data.
LOOKUP_DEPENDENT_COLUMNS = [
    "time_response", "domain_spf", "asn_ip", "time_domain_activation",
    "time_domain_expiration", "qty_ip_resolved", "qty_nameservers",
    "qty_mx_servers", "ttl_hostname", "tls_ssl_certificate", "qty_redirects",
    "url_google_index", "domain_google_index",
]
LABEL_COLUMN = "phishing"


def load_data(csv_path: str):
    df = pd.read_csv(csv_path)
    feature_columns = [c for c in df.columns if c not in LOOKUP_DEPENDENT_COLUMNS and c != LABEL_COLUMN]

    X = df[feature_columns]
    y = df[LABEL_COLUMN]

    return X, y, feature_columns


def train_random_forest(X_train, y_train, **kwargs):
    params = {
        "n_estimators": kwargs.get("n_estimators", 200),
        "max_depth": kwargs.get("max_depth", 20),
        "min_samples_split": kwargs.get("min_samples_split", 5),
        "class_weight": "balanced",  # dataset is 65/35, not catastrophic but worth correcting
        "random_state": 42,
        "n_jobs": -1,
    }
    model = RandomForestClassifier(**params)
    model.fit(X_train, y_train)
    return model, params


def train_xgboost(X_train, y_train, **kwargs):
    import xgboost as xgb
    params = {
        "n_estimators": kwargs.get("n_estimators", 200),
        "max_depth": kwargs.get("max_depth", 6),
        "learning_rate": kwargs.get("learning_rate", 0.1),
        "scale_pos_weight": (y_train == 0).sum() / (y_train == 1).sum(),  # class imbalance correction
        "random_state": 42,
        "eval_metric": "logloss",
    }
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train)
    return model, params


def evaluate(model, X_test, y_test, feature_columns):
    start = time.time()
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    inference_time_ms = (time.time() - start) / len(X_test) * 1000

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_proba),
        "avg_inference_ms_per_sample": inference_time_ms,
    }

    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, output_dict=True)

    # Feature importance — which lexical features actually matter most
    feature_importance = {}
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        feature_importance = dict(
            sorted(zip(feature_columns, importances.tolist()), key=lambda x: -x[1])
        )

    return metrics, cm, report, feature_importance


def main(args):
    mlflow.set_tracking_uri(args.mlflow_uri)
    mlflow.set_experiment("url_nlp_phishing_classifier")

    print(f"Loading dataset from {args.data}...")
    X, y, feature_columns = load_data(args.data)
    print(f"  {len(feature_columns)} lexical features, {len(X)} samples "
          f"({(y==1).sum()} phishing, {(y==0).sum()} legitimate)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)}  Test: {len(X_test)}")

    with mlflow.start_run(run_name=f"{args.model}_lexical_only"):
        mlflow.log_param("model_type", args.model)
        mlflow.log_param("n_features", len(feature_columns))
        mlflow.log_param("n_train_samples", len(X_train))
        mlflow.log_param("n_test_samples", len(X_test))
        mlflow.log_param("dataset_source", "GregaVrbancic/Phishing-Dataset")
        mlflow.log_param("feature_scope", "lexical_only_no_network_lookups")

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

        print(f"Trained in {train_time:.1f}s. Evaluating...")
        metrics, cm, report, feature_importance = evaluate(model, X_test, y_test, feature_columns)

        for k, v in metrics.items():
            mlflow.log_metric(k, v)

        print("\n=== Test Set Results ===")
        for k, v in metrics.items():
            print(f"  {k}: {v:.4f}")

        print("\nConfusion matrix (rows=actual, cols=predicted) [legitimate, phishing]:")
        print(f"  {cm}")

        print("\nTop 15 most important features:")
        for feat, imp in list(feature_importance.items())[:15]:
            print(f"  {feat}: {imp:.4f}")

        # Save model + full report
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        model_path = out_dir / f"url_nlp_{args.model}.joblib"
        joblib.dump({"model": model, "feature_columns": feature_columns}, model_path)
        mlflow.log_artifact(str(model_path))

        report_data = {
            "model_type": args.model,
            "dataset_source": "GregaVrbancic/Phishing-Dataset (github.com/GregaVrbancic/Phishing-Dataset)",
            "n_features": len(feature_columns),
            "feature_columns": feature_columns,
            "excluded_lookup_columns": LOOKUP_DEPENDENT_COLUMNS,
            "n_train_samples": int(len(X_train)),
            "n_test_samples": int(len(X_test)),
            "params": params,
            "metrics": metrics,
            "confusion_matrix": cm,
            "classification_report": report,
            "feature_importance": feature_importance,
            "train_time_seconds": train_time,
        }
        report_path = out_dir / f"training_report_{args.model}.json"
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)
        mlflow.log_artifact(str(report_path))

        print(f"\nModel saved → {model_path}")
        print(f"Report saved → {report_path}")
        print(f"MLflow run: {mlflow.active_run().info.run_id}")

    return report_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../dataset/phishing_dataset_full.csv")
    parser.add_argument("--model", choices=["random_forest", "xgboost"], default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--output-dir", default="../models")
    parser.add_argument("--mlflow-uri", default=None,
                         help="MLflow tracking URI. Defaults to backend/mlflow.db (one shared "
                              "file for the whole project), resolved as an ABSOLUTE path anchored "
                              "to this script's own location — NOT relative to the working "
                              "directory the script happens to be invoked from, which silently "
                              "produced two different mlflow.db files in different locations "
                              "during development (one from backend/, one from "
                              "backend/ml/url_nlp/training/) before this fix.")
    args = parser.parse_args()

    if args.mlflow_uri is None:
        backend_dir = Path(__file__).parent.parent.parent.parent  # backend/
        args.mlflow_uri = f"sqlite:///{backend_dir / 'mlflow.db'}"

    main(args)
