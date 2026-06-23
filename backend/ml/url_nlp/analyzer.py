"""
ML Model 1 — URL Lexical / NLP Analyzer
========================================
Primary path: a Random Forest trained on 88,647 REAL labeled URLs from
GregaVrbancic/Phishing-Dataset (github.com/GregaVrbancic/Phishing-Dataset),
restricted to the 98 lexical/structural features computable from a URL
string alone (13 lookup-dependent columns requiring live DNS/WHOIS/Google
checks were excluded — see ml/url_nlp/training/train.py for why).
Test-set performance: 93.0% accuracy, 98.1% ROC-AUC — see
ml/url_nlp/models/training_report_random_forest.json for the full report.

Fallback path: hand-crafted rule-based heuristics (Shannon entropy, brand
mismatch, suspicious TLDs, phishing keywords) — used when the trained model
or its dependencies (scikit-learn, joblib) aren't available, so the analyzer
never hard-fails just because a model file is missing.
"""
import math
import os
import re
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs

import tldextract

from ml.url_nlp.feature_extractor import extract_features as extract_lexical_features


# ── Known brand domains (partial list for demo) ───────────────────────────────
BRAND_DOMAINS = {
    "paypal", "microsoft", "apple", "amazon", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".tech", ".pw",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".bid", ".stream",
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "password", "credential", "banking", "suspended",
    "unusual", "activity", "security", "alert", "urgent",
}

DGA_CONSONANT_CLUSTERS = re.compile(r'[bcdfghjklmnpqrstvwxyz]{5,}')

DEFAULT_MODEL_PATH = Path(__file__).parent / "models" / "url_nlp_xgboost.joblib"
# NOTE: XGBoost was chosen as the default over the Random Forest checkpoint
# (also available in this directory after training) specifically because
# of file size: the RF model is 59MB (200 trees, depth 20) vs XGBoost's
# 580KB, for a 0.35 percentage-point accuracy difference (92.69% vs 93.04%)
# that doesn't justify shipping a 100x larger file in the repo. See
# TRAINING_NOTES.md for both models' full metrics if you want to compare
# and choose the Random Forest instead — just point model_path at it.

# Explicit mapping from sklearn/xgboost class names to display strings —
# deliberately NOT derived via string manipulation on the class name (an
# earlier attempt using a regex to auto-convert CamelCase to snake_case
# produced "x_g_b_classifier" for XGBClassifier, which is wrong and
# unreadable). Add an entry here if a new model type is introduced.
MODEL_CLASS_DISPLAY_NAMES = {
    "RandomForestClassifier": "Random Forest",
    "XGBClassifier": "XGBoost",
}
MODEL_CLASS_SOURCE_IDS = {
    "RandomForestClassifier": "random_forest",
    "XGBClassifier": "xgboost",
}


class URLAnalyzer:
    """
    Analyzes a URL using lexical and structural features.
    Returns a score dict compatible with the orchestrator's MLScore format.
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

    def _model_predict(self, url: str):
        """Runs the trained Random Forest on a URL. Returns (score, top_features)
        or None if the model isn't loaded."""
        if self._model is None:
            return None
        try:
            import pandas as pd
            raw_features = extract_lexical_features(url)
            # Order columns EXACTLY as during training — dict insertion order
            # is not a safe assumption across refactors/versions.
            ordered = {col: raw_features.get(col, 0) for col in self._feature_columns}
            X = pd.DataFrame([ordered])[self._feature_columns]
            proba = self._model.predict_proba(X)[0]
            phishing_score = float(proba[1])  # class 1 = phishing
            return {"score": phishing_score, "raw_features": raw_features}
        except Exception:
            return None

    def analyze(self, url: str) -> Dict[str, Any]:
        model_result = self._model_predict(url)
        features = self._extract_features(url)  # rule-based features, used for reasoning either way

        if model_result is not None:
            score = model_result["score"]
            reasoning = self._reasoning_from_rules(features)  # human-readable signals, even when score comes from the model
            model_class_name = type(self._model).__name__
            display_name = MODEL_CLASS_DISPLAY_NAMES.get(model_class_name, model_class_name)
            reasoning.insert(0, f"{display_name} (trained on 88,647 real labeled URLs): {score*100:.1f}% phishing probability")
            confidence = max(score, 1 - score)  # how far from 0.5 the prediction is
            # Derived from the actual loaded model class, not hardcoded — this was
            # a real bug found while switching the default from Random Forest to
            # XGBoost: model_source stayed "random_forest" even after the loaded
            # model changed, silently mislabeling every prediction's source.
            model_source = MODEL_CLASS_SOURCE_IDS.get(model_class_name, model_class_name.lower())
        else:
            score, reasoning = self._score(features)
            confidence = self._confidence(features)
            model_source = "rule_based_fallback"

        threat_level = "safe"
        if score >= 0.70:
            threat_level = "malicious"
        elif score >= 0.40:
            threat_level = "suspicious"

        return {
            "model": "url_nlp",
            "model_source": model_source,
            "score": round(score, 4),
            "confidence": round(confidence, 4),
            "threat_level": threat_level,
            "features": features,
            "reasoning": reasoning,
        }

    def _reasoning_from_rules(self, features: Dict[str, Any]) -> List[str]:
        """Generates human-readable reasoning from rule-based features even when
        the trained model produced the actual score — keeps explanations
        interpretable rather than just handing back a bare probability."""
        _, reasoning = self._score(features)
        # Drop the generic "no significant indicators" fallback line if present —
        # it would be confusing alongside a high model score, or redundant alongside a low one.
        return [r for r in reasoning if r != "No significant threat indicators found"]

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_features(self, url: str) -> Dict[str, Any]:
        # Ensure scheme present for urlparse
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        ext = tldextract.extract(url)

        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        tld = f".{ext.suffix}" if ext.suffix else ""
        full_domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query_str = parsed.query

        return {
            # Length features
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            "subdomain_depth": len(subdomain.split(".")) if subdomain else 0,

            # Entropy — high entropy → likely DGA
            "domain_entropy": self._shannon_entropy(domain),
            "url_entropy": self._shannon_entropy(url),

            # Digit ratio
            "digit_ratio": sum(c.isdigit() for c in domain) / max(len(domain), 1),

            # Special chars in domain
            "hyphen_count": domain.count("-"),
            "at_sign": "@" in url,
            "double_slash_path": "//" in path,
            "ip_in_url": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', full_domain)),

            # TLD suspicion
            "suspicious_tld": tld in SUSPICIOUS_TLDS,
            "tld": tld,

            # Brand impersonation
            "brand_in_subdomain": any(b in subdomain for b in BRAND_DOMAINS),
            "brand_in_path": any(b in path for b in BRAND_DOMAINS),
            "brand_mismatch": self._brand_mismatch(domain, subdomain, path),

            # Phishing keywords
            "phishing_keyword_count": sum(kw in url.lower() for kw in PHISHING_KEYWORDS),

            # DGA heuristics
            "dga_consonant_cluster": bool(DGA_CONSONANT_CLUSTERS.search(domain)),
            "low_vowel_ratio": self._vowel_ratio(domain) < 0.25,

            # Query params
            "param_count": len(parse_qs(query_str)),
            "redirect_param": any(k in ["redirect", "url", "goto", "next", "redir"]
                                  for k in parse_qs(query_str).keys()),

            # HTTPS
            "is_https": parsed.scheme == "https",

            # Raw parts (not scored directly)
            "domain": domain,
            "subdomain": subdomain,
            "full_url": url,
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, f: Dict[str, Any]):
        score = 0.0
        reasoning: List[str] = []

        def add(points: float, reason: str):
            nonlocal score
            score += points
            if points > 0:
                reasoning.append(reason)

        # URL length
        if f["url_length"] > 75:
            add(0.05, f"Long URL ({f['url_length']} chars)")
        if f["url_length"] > 120:
            add(0.08, f"Very long URL ({f['url_length']} chars)")

        # IP address in host
        if f["ip_in_url"]:
            add(0.35, "IP address used instead of domain name")

        # Suspicious TLD
        if f["suspicious_tld"]:
            add(0.20, f"Suspicious TLD: {f['tld']}")

        # Brand impersonation
        if f["brand_mismatch"]:
            add(0.40, "Brand name in subdomain/path but domain doesn't match — likely spoofing")
        elif f["brand_in_subdomain"]:
            add(0.15, "Brand keyword in subdomain")

        # Phishing keywords
        kw_count = f["phishing_keyword_count"]
        if kw_count >= 3:
            add(0.30, f"High phishing keyword density ({kw_count} matches)")
        elif kw_count >= 1:
            add(0.12 * kw_count, f"Phishing keywords in URL ({kw_count})")

        # DGA / entropy
        if f["domain_entropy"] > 3.8:
            add(0.20, f"High domain entropy ({f['domain_entropy']:.2f}) — possible DGA")
        if f["dga_consonant_cluster"]:
            add(0.15, "Suspicious consonant cluster — possible DGA domain")
        if f["low_vowel_ratio"]:
            add(0.10, "Low vowel ratio — consonant-heavy domain")

        # Digit ratio
        if f["digit_ratio"] > 0.4:
            add(0.15, f"High digit ratio in domain ({f['digit_ratio']:.0%})")

        # @ sign
        if f["at_sign"]:
            add(0.30, "@ symbol in URL — hides real destination")

        # Double slash in path
        if f["double_slash_path"]:
            add(0.20, "Double slash in path — possible redirect abuse")

        # Redirect param
        if f["redirect_param"]:
            add(0.15, "Open redirect parameter detected in query string")

        # Deep subdomain
        if f["subdomain_depth"] > 3:
            add(0.15, f"Deep subdomain ({f['subdomain_depth']} levels)")

        # Hyphen count
        if f["hyphen_count"] >= 3:
            add(0.10, f"Multiple hyphens in domain ({f['hyphen_count']})")

        # HTTPS bonus (slightly reduces score, not fully exculpatory)
        if f["is_https"] and score > 0:
            score *= 0.90

        score = min(score, 1.0)
        if not reasoning:
            reasoning.append("No significant threat indicators found")

        return score, reasoning

    def _confidence(self, f: Dict[str, Any]) -> float:
        """Higher confidence when more features are present."""
        signals = sum([
            f["ip_in_url"],
            f["suspicious_tld"],
            f["brand_mismatch"],
            f["phishing_keyword_count"] > 0,
            f["domain_entropy"] > 3.5,
        ])
        return min(0.5 + signals * 0.10, 0.98)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    @staticmethod
    def _vowel_ratio(s: str) -> float:
        vowels = set("aeiou")
        alpha = [c for c in s.lower() if c.isalpha()]
        if not alpha:
            return 0.5
        return sum(c in vowels for c in alpha) / len(alpha)

    @staticmethod
    def _brand_mismatch(domain: str, subdomain: str, path: str) -> bool:
        """True if a brand keyword appears in subdomain/path but NOT as the actual domain."""
        combined = subdomain + " " + path
        for brand in BRAND_DOMAINS:
            if brand in combined and brand != domain:
                return True
        return False
