"""
tests/test_ml_models.py
Unit tests for URL NLP, Behavior, and Vision analyzers.
Run with: pytest tests/ -v
"""
import sys
import types
import pytest

# ── Patch tldextract for environments without network access ──────────────────
class _FakeTLDResult:
    """
    Simplified stand-in for tldextract.extract() — assumes a single-label TLD
    (e.g. .com, .xyz, .net) rather than consulting a real public suffix list.
    This is sufficient for test URLs in this file (none use multi-label
    suffixes like .co.uk), but will misidentify those if added later.
    """
    def __init__(self, url: str):
        host = url.split("//")[-1].split("/")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            self.suffix = parts[-1]                          # e.g. "xyz" from example.xyz
            self.domain = parts[-2]                           # e.g. "example" from example.xyz
            self.subdomain = ".".join(parts[:-2])              # e.g. "" or "www"
        else:
            self.suffix = ""
            self.domain = host
            self.subdomain = ""

_fake = types.ModuleType("tldextract")
_fake.extract = lambda url: _FakeTLDResult(url)
sys.modules.setdefault("tldextract", _fake)

from ml.url_nlp.analyzer import URLAnalyzer  # noqa: E402 — must follow the tldextract patch above
from ml.behavior.analyzer import BehaviorAnalyzer  # noqa: E402
from ml.vision.analyzer import VisionAnalyzer  # noqa: E402


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def url_analyzer():
    return URLAnalyzer()

@pytest.fixture(scope="module")
def behavior_analyzer():
    return BehaviorAnalyzer()

@pytest.fixture(scope="module")
def vision_analyzer():
    return VisionAnalyzer()

@pytest.fixture
def safe_sandbox():
    return {
        "network_requests": [
            {"url": "https://github.com/main.js", "method": "GET", "content_type": "application/javascript"},
        ],
        "process_events": [
            {"pid": 1, "name": "chromium", "event": "spawn", "args": ["--headless"]},
        ],
        "logs": [],
        "file_operations": [],
        "screenshot_b64": None,
        "page_title": "GitHub",
        "final_url": "https://github.com",
    }

@pytest.fixture
def malicious_sandbox():
    return {
        "network_requests": [
            {"url": "http://45.33.12.99/payload.exe", "method": "GET", "content_type": "application/octet-stream"},
        ],
        "process_events": [
            {"pid": 2, "name": "powershell", "event": "spawn",
             "args": ["-encodedcommand", "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA=="]},
        ],
        "logs": [{"level": "alert", "category": "network", "message": "Binary download"}],
        "file_operations": [],
        "screenshot_b64": None,
        "page_title": "Loading…",
        "final_url": "http://45.33.12.99",
    }


# ── URL NLP tests ─────────────────────────────────────────────────────────────

class TestURLAnalyzer:
    def test_safe_url_scores_low(self, url_analyzer):
        result = url_analyzer.analyze("https://github.com")
        assert result["score"] < 0.20
        assert result["threat_level"] == "safe"

    def test_ip_url_flagged(self, url_analyzer):
        result = url_analyzer.analyze("http://192.168.1.45/payload.exe")
        assert result["score"] >= 0.30
        assert any("IP address" in r for r in result["reasoning"])

    def test_brand_mismatch_flagged(self, url_analyzer):
        result = url_analyzer.analyze("http://paypal.secure-update.xyz/login")
        assert result["score"] >= 0.30

    def test_phishing_keywords_raise_score(self, url_analyzer):
        result = url_analyzer.analyze(
            "http://verify-account-password-confirm.net/login?redirect=paypal"
        )
        assert result["score"] >= 0.30

    def test_suspicious_tld_flagged(self, url_analyzer):
        result = url_analyzer.analyze("http://example.xyz/update")
        assert result["score"] >= 0.15

    def test_result_schema(self, url_analyzer):
        result = url_analyzer.analyze("https://example.com")
        assert "score" in result
        assert "threat_level" in result
        assert "confidence" in result
        assert "reasoning" in result
        assert isinstance(result["reasoning"], list)
        assert 0.0 <= result["score"] <= 1.0
        assert 0.0 <= result["confidence"] <= 1.0

    def test_score_clamped(self, url_analyzer):
        """Score must never exceed 1.0 regardless of input."""
        result = url_analyzer.analyze(
            "http://192.168.1.1/paypal-login-verify-confirm-password-update-security-alert.xyz"
        )
        assert result["score"] <= 1.0

    def test_bare_domain_not_falsely_flagged(self, url_analyzer):
        """
        Regression test for a real bug found during development: the trained
        model's feature extractor must use a -1 sentinel for directory/file/
        params features when those URL segments don't exist (a bare domain
        like 'github.com' has no path, file, or query string at all) — NOT 0,
        which is a different, valid value meaning "the segment exists and is
        empty of special characters". Confusing these two caused every
        bare-domain URL (no path) to score as 90%+ malicious despite the
        model being correctly trained, because ~47,500-81,000 of 88,647
        training rows used -1 for exactly this case and the model learned
        that distinction. See ml/url_nlp/feature_extractor.py's docstring
        on extract_features() for the full root-cause writeup.
        """
        for url in ["https://github.com", "https://www.google.com", "https://stackoverflow.com"]:
            result = url_analyzer.analyze(url)
            assert result["score"] < 0.30, (
                f"{url} scored {result['score']} — bare domain URLs should score low; "
                f"a high score here likely means the -1/0 sentinel bug has regressed"
            )

    def test_model_loads_when_available(self, url_analyzer):
        """If the trained model file exists, model_source should report it was used."""
        result = url_analyzer.analyze("https://example.com")
        assert result["model_source"] in ("random_forest", "xgboost", "rule_based_fallback")
        # Don't assert WHICH one — the model file may or may not be present in
        # every environment this test runs in (e.g. a fresh clone before
        # training has been run) — but the field must always be present and
        # valid, and the analyzer must never crash either way.


# ── Behavior tests ────────────────────────────────────────────────────────────

class TestBehaviorAnalyzer:
    def test_safe_sandbox_scores_low(self, behavior_analyzer, safe_sandbox):
        result = behavior_analyzer.analyze(safe_sandbox)
        assert result["score"] < 0.30
        assert result["threat_level"] == "safe"

    def test_binary_download_flagged(self, behavior_analyzer, malicious_sandbox):
        result = behavior_analyzer.analyze(malicious_sandbox)
        assert result["score"] >= 0.50
        assert any("Binary" in r or "binary" in r for r in result["reasoning"])

    def test_encoded_powershell_flagged(self, behavior_analyzer, malicious_sandbox):
        result = behavior_analyzer.analyze(malicious_sandbox)
        assert any("encoded" in r.lower() or "Obfuscated" in r for r in result["reasoning"])

    def test_malicious_scores_high(self, behavior_analyzer, malicious_sandbox):
        result = behavior_analyzer.analyze(malicious_sandbox)
        assert result["threat_level"] == "malicious"

    def test_password_form_flagged_in_rule_based_fallback(self):
        """
        Tests the RULE-BASED FALLBACK's specific weighting for password-form
        detection — instantiates a fresh BehaviorAnalyzer pointed at a
        nonexistent model path to force the fallback path, since the trained
        model legitimately learned a different (lower) weight for this
        signal from the synthetic training data, where password forms
        appeared in both benign and malicious archetypes roughly equally.
        That's a real, documented finding (see
        ml/behavior/TRAINING_NOTES.md) — not a bug — but it means this
        specific rule-based weighting assertion no longer holds for the
        trained-model path by design.
        """
        from ml.behavior.analyzer import BehaviorAnalyzer
        fallback_analyzer = BehaviorAnalyzer(model_path="/nonexistent/path.joblib")
        assert fallback_analyzer._model is None  # confirm we're actually testing the fallback

        sandbox = {
            "network_requests": [],
            "process_events": [],
            "logs": [{"level": "alert", "category": "visual",
                      "message": "Password input field detected"}],
            "file_operations": [],
        }
        result = fallback_analyzer.analyze(sandbox)
        assert result["model_source"] == "rule_based_fallback"
        assert result["score"] > 0.0

    def test_empty_sandbox_safe(self, behavior_analyzer):
        result = behavior_analyzer.analyze({})
        assert result["threat_level"] == "safe"
        # Don't assert score == 0.0 exactly — the trained model may return a
        # small nonzero baseline probability even for empty input, which is
        # normal for a probabilistic classifier (unlike the rule-based
        # fallback's purely additive scoring, which does hit exactly 0.0).
        assert result["score"] < 0.40


# ── Vision CNN tests ──────────────────────────────────────────────────────────

class TestVisionAnalyzer:
    def test_safe_page_scores_low(self, vision_analyzer):
        sandbox = {
            "screenshot_b64": None,
            "page_title": "GitHub — Build software better, together",
            "final_url": "https://github.com",
        }
        result = vision_analyzer.analyze(sandbox)
        assert result["score"] < 0.30

    def test_brand_mismatch_flagged(self, vision_analyzer):
        sandbox = {
            "screenshot_b64": None,
            "page_title": "PayPal: Confirm Your Account",
            "final_url": "http://paypal-verify-account.xyz/login",
        }
        result = vision_analyzer.analyze(sandbox)
        assert result["score"] >= 0.40
        assert any("PayPal" in r or "brand" in r.lower() for r in result["reasoning"])

    def test_urgency_language_raises_score(self, vision_analyzer):
        sandbox = {
            "screenshot_b64": None,
            "page_title": "URGENT: Verify your account immediately - Security Alert",
            "final_url": "http://example.com",
        }
        result = vision_analyzer.analyze(sandbox)
        assert result["score"] > 0.0
        assert any("urgency" in r.lower() or "Urgency" in r for r in result["reasoning"])

    def test_no_screenshot_reduces_confidence(self, vision_analyzer):
        with_screenshot = {
            "screenshot_b64": None,
            "page_title": "PayPal - Verify",
            "final_url": "http://paypal-verify.xyz",
        }
        result = vision_analyzer.analyze(with_screenshot)
        assert result["confidence"] < 0.80

    def test_result_schema(self, vision_analyzer):
        result = vision_analyzer.analyze({"screenshot_b64": None, "page_title": "", "final_url": ""})
        assert all(k in result for k in ["score", "threat_level", "confidence", "reasoning", "features", "model_source"])

    def test_no_screenshot_uses_fallback(self, vision_analyzer):
        """Without a screenshot, the CNN path can't run — must use rule-based fallback."""
        result = vision_analyzer.analyze({"screenshot_b64": None, "page_title": "PayPal", "final_url": "http://x.com"})
        assert result["model_source"] == "rule_based_fallback"


# ── Aggregate scoring test ────────────────────────────────────────────────────

class TestAggregateScore:
    def test_high_risk_aggregate(self, url_analyzer, behavior_analyzer, vision_analyzer, malicious_sandbox):
        url_r = url_analyzer.analyze("http://192.168.1.45/payload.exe")
        beh_r = behavior_analyzer.analyze(malicious_sandbox)
        vis_r = vision_analyzer.analyze(malicious_sandbox)

        aggregate = (
            0.25 * url_r["score"] +
            0.45 * beh_r["score"] +
            0.30 * vis_r["score"]
        )
        assert aggregate >= 0.50, f"Expected high aggregate risk, got {aggregate:.2f}"

    def test_safe_aggregate(self, url_analyzer, behavior_analyzer, vision_analyzer, safe_sandbox):
        url_r = url_analyzer.analyze("https://github.com")
        beh_r = behavior_analyzer.analyze(safe_sandbox)
        vis_r = vision_analyzer.analyze(safe_sandbox)

        aggregate = (
            0.25 * url_r["score"] +
            0.45 * beh_r["score"] +
            0.30 * vis_r["score"]
        )
        assert aggregate < 0.40, f"Expected low aggregate risk, got {aggregate:.2f}"
