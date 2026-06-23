"""
ML Model 2 — Behavior / Anomaly Classifier
===========================================
Primary path: a Random Forest trained on SYNTHETIC sandbox telemetry (see
ml/behavior/dataset/synthetic_telemetry_generator.py for full honesty notes
— no public dataset of raw sandbox telemetry traces exists, so this was
bootstrapped from behavioral archetypes grounded in named MITRE ATT&CK
techniques, not real malware execution). Achieves 100% test accuracy on
this synthetic data, which reflects how cleanly separable the synthetic
archetypes are, not real-world performance — see
ml/behavior/models/training_report_random_forest.json and
ml/behavior/TRAINING_NOTES.md for the full honest writeup, including a
documented false-positive edge case (a single benign IP-literal request
scores 78.7% malicious, because the synthetic data never included a benign
example of that pattern).

Fallback path: the original hand-crafted rule-based heuristics below — used
when the trained model or its dependencies (scikit-learn, joblib, pandas)
aren't available, so the analyzer never hard-fails just because a model
file is missing.
"""
import os
import re
from pathlib import Path
from typing import Dict, Any, List


# ── Known-bad indicators ──────────────────────────────────────────────────────
BINARY_MIME_TYPES = {
    "application/octet-stream", "application/x-msdownload",
    "application/x-executable", "application/x-dosexec",
    "application/x-elf", "application/vnd.ms-cab-compressed",
}

MALWARE_EXTENSIONS = re.compile(
    r'\.(exe|dll|bat|cmd|ps1|vbs|jar|msi|scr|hta|wsf|pif|reg)(\?|$)',
    re.IGNORECASE
)

C2_PORTS = {4444, 8080, 1337, 6666, 9001, 8443, 31337, 2222}

SUSPICIOUS_PROCESSES = {
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin",
}

ENCODED_ARG_PATTERN = re.compile(r'-enc(odedcommand)?[\s]+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)

DEFAULT_MODEL_PATH = Path(__file__).parent / "models" / "behavior_random_forest.joblib"


class BehaviorAnalyzer:
    """
    Feature vector extraction + classifier (trained model primary, rule-based
    fallback) over sandbox telemetry.
    """

    def __init__(self, model_path: str = None):
        self._model = None
        self._feature_columns: List[str] = []
        self._load_model(model_path or str(DEFAULT_MODEL_PATH))

    def _load_model(self, model_path: str):
        """Attempt to load the trained Random Forest. Silently no-ops if
        scikit-learn/joblib aren't installed or the checkpoint is missing —
        the analyzer degrades to rule-based scoring in that case."""
        if not os.path.exists(model_path):
            return
        try:
            import joblib
            bundle = joblib.load(model_path)
            self._model = bundle["model"]
            self._feature_columns = bundle["feature_columns"]
        except Exception:
            self._model = None
            self._feature_columns = []

    def _model_predict(self, features: Dict[str, Any]):
        """Runs the trained Random Forest on already-extracted features.
        Returns the malicious-class probability, or None if unavailable."""
        if self._model is None:
            return None
        try:
            import pandas as pd
            numeric = {
                k: (int(v) if isinstance(v, bool) else v)
                for k, v in features.items()
                if not isinstance(v, list)
            }
            ordered = {col: numeric.get(col, 0) for col in self._feature_columns}
            X = pd.DataFrame([ordered])[self._feature_columns]
            proba = self._model.predict_proba(X)[0]
            return float(proba[1])  # class 1 = malicious
        except Exception:
            return None

    def analyze(self, sandbox: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(sandbox)
        model_score = self._model_predict(features)

        if model_score is not None:
            score = model_score
            _, reasoning = self._classify(features)  # human-readable signals, even when score comes from the model
            reasoning = [r for r in reasoning if r != "No anomalous behavior patterns detected in sandbox telemetry"]
            reasoning.insert(0, f"Random Forest (trained on synthetic telemetry): {score*100:.1f}% malicious probability")
            if not reasoning[1:]:
                reasoning.append("No specific rule-based indicators triggered, but model flagged this pattern")
            model_source = "random_forest"
        else:
            score, reasoning = self._classify(features)
            model_source = "rule_based_fallback"

        threat_level = "safe"
        if score >= 0.70:
            threat_level = "malicious"
        elif score >= 0.40:
            threat_level = "suspicious"

        return {
            "model": "behavior",
            "model_source": model_source,
            "score": round(score, 4),
            "confidence": round(min(0.55 + len(reasoning) * 0.07, 0.97), 4),
            "threat_level": threat_level,
            "features": {k: v for k, v in features.items() if not k.startswith("_")},
            "reasoning": reasoning,
        }

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_features(self, s: Dict[str, Any]) -> Dict[str, Any]:
        net = s.get("network_requests", [])
        procs = s.get("process_events", [])
        files = s.get("file_operations", [])
        logs = s.get("logs", [])

        # Network features
        binary_downloads = [
            r for r in net
            if r.get("content_type", "") in BINARY_MIME_TYPES
            or MALWARE_EXTENSIONS.search(r.get("url", ""))
        ]

        unique_hosts = len({r.get("url", "").split("/")[2] for r in net if "//" in r.get("url", "")})
        suspicious_port_connections = [
            r for r in net
            if any(f":{p}" in r.get("url", "") for p in C2_PORTS)
        ]

        ip_connections = [
            r for r in net
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r.get("url", ""))
        ]

        # Process features
        suspicious_proc_names = [
            p for p in procs
            if any(sp in p.get("name", "").lower() for sp in SUSPICIOUS_PROCESSES)
        ]

        encoded_args = [
            p for p in procs
            if ENCODED_ARG_PATTERN.search(" ".join(p.get("args", [])))
        ]

        child_process_count = len([p for p in procs if p.get("event") == "spawn"])

        # File features
        sensitive_writes = [
            f for f in files
            if f.get("operation") in ("write", "create")
            and any(path in f.get("path", "").lower()
                    for path in ("system32", "startup", "appdata\\roaming",
                                 "/etc/", "/bin/", "crontab"))
        ]

        # Log-level alerts
        alert_logs = [entry for entry in logs if entry.get("level") == "alert"]
        password_form_detected = any(
            "password" in entry.get("message", "").lower() for entry in logs
        )

        return {
            "network_request_count": len(net),
            "unique_host_count": unique_hosts,
            "binary_download_count": len(binary_downloads),
            "binary_download_urls": [r["url"] for r in binary_downloads[:3]],
            "suspicious_port_count": len(suspicious_port_connections),
            "ip_connection_count": len(ip_connections),
            "suspicious_process_count": len(suspicious_proc_names),
            "suspicious_process_names": [p["name"] for p in suspicious_proc_names],
            "encoded_argument_count": len(encoded_args),
            "child_process_count": child_process_count,
            "sensitive_write_count": len(sensitive_writes),
            "alert_log_count": len(alert_logs),
            "password_form_detected": password_form_detected,
        }

    # ── Weighted rule classifier ──────────────────────────────────────────────

    def _classify(self, f: Dict[str, Any]):
        score = 0.0
        reasoning: List[str] = []

        def add(points: float, reason: str):
            nonlocal score
            score += points
            reasoning.append(reason)

        # Binary / file downloads
        if f["binary_download_count"] > 0:
            add(0.45, f"Binary file download detected ({f['binary_download_count']} files): "
                      + ", ".join(f["binary_download_urls"][:2]))

        # Direct IP connections
        if f["ip_connection_count"] > 0:
            add(0.25, f"Direct IP connection(s) bypassing DNS ({f['ip_connection_count']})")

        # Known C2 ports
        if f["suspicious_port_count"] > 0:
            add(0.30, f"Connection to known C2 port(s) ({f['suspicious_port_count']})")

        # Suspicious processes
        if f["suspicious_process_count"] > 0:
            names = ", ".join(set(f["suspicious_process_names"]))
            add(0.35, f"Suspicious process(es) spawned: {names}")

        # Encoded arguments (obfuscation)
        if f["encoded_argument_count"] > 0:
            add(0.40, "Obfuscated encoded command-line argument detected — common malware technique")

        # Sensitive file writes
        if f["sensitive_write_count"] > 0:
            add(0.35, f"Write to sensitive system path ({f['sensitive_write_count']} operations)")

        # Password form
        if f["password_form_detected"]:
            add(0.20, "Password input field detected — potential credential harvesting page")

        # Alert-level log density
        if f["alert_log_count"] >= 3:
            add(0.15, f"High alert-log density ({f['alert_log_count']} alerts from sandbox)")

        # Lateral movement heuristic
        if f["unique_host_count"] > 8:
            add(0.10, f"Contacted unusually high number of hosts ({f['unique_host_count']})")

        if not reasoning:
            reasoning.append("No anomalous behavior patterns detected in sandbox telemetry")

        return min(score, 1.0), reasoning
