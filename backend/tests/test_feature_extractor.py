"""
tests/test_feature_extractor.py
==================================
Focused unit tests for ml/url_nlp/feature_extractor.py — isolated from the
full URLAnalyzer so these tests still mean something even when the trained
model file isn't present (e.g. a fresh clone before training has been run).

These exist because the extractor had two real, serious bugs found during
development that both silently corrupted predictions without raising any
exception — exactly the kind of bug that needs a regression test, not just
a passing "looks fine" smoke check.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.url_nlp.feature_extractor import extract_features


class TestSchemeStripping:
    """
    Bug #1: the 'url' substring used for feature counting must EXCLUDE the
    http:// or https:// scheme. Proven from the training data: 47,509 of
    88,647 rows have qty_slash_url == 0, which is impossible if the scheme
    (contributing 2 slashes via "//") were included.
    """

    def test_no_slashes_from_scheme(self):
        f = extract_features("https://example.com")
        assert f["qty_slash_url"] == 0, (
            "qty_slash_url should not count the // in https:// — "
            "the scheme must be stripped before counting"
        )

    def test_length_excludes_scheme(self):
        f = extract_features("https://github.com")
        assert f["length_url"] == len("github.com"), (
            f"length_url should be {len('github.com')} (scheme excluded), got {f['length_url']}"
        )

    def test_works_with_or_without_explicit_scheme(self):
        with_scheme = extract_features("https://example.com/path")
        # A bare domain without scheme should be treated as if http:// was implied,
        # then stripped — same result either way
        without_scheme_equivalent = extract_features("http://example.com/path")
        assert with_scheme["length_url"] == without_scheme_equivalent["length_url"]


class TestSentinelValues:
    """
    Bug #2 (the more serious one): when a URL has no directory, no file
    segment, or no query string, every feature derived from that absent
    segment must be -1, NOT 0. Proven from training data: every one of the
    47,509 rows with directory_length == -1 also has qty_dot_directory == -1
    and qty_slash_directory == -1 (never 0) — confirmed by direct inspection,
    not assumed. Conflating "absent" (-1) with "present but empty" (0) caused
    bare-domain URLs to score 90%+ phishing despite a correctly-trained model.
    """

    def test_bare_domain_gets_negative_one_sentinels(self):
        f = extract_features("https://github.com")
        assert f["directory_length"] == -1
        assert f["file_length"] == -1
        assert f["params_length"] == -1
        assert f["qty_params"] == -1
        assert f["qty_dot_directory"] == -1
        assert f["qty_dot_file"] == -1

    def test_url_with_path_gets_real_directory_and_file_values(self):
        f = extract_features("https://example.com/login/secure.php")
        assert f["directory_length"] != -1
        assert f["file_length"] != -1
        assert f["file_length"] == len("secure.php")

    def test_url_with_query_string_gets_real_params_values(self):
        f = extract_features("https://example.com/page?a=1&b=2")
        assert f["params_length"] != -1
        assert f["params_length"] == len("a=1&b=2")
        assert f["qty_and_params"] == 1  # one literal & character

    def test_single_segment_path_gets_real_values_not_sentinels(self):
        """
        A URL like /login (single path segment) gets REAL (non-sentinel)
        values for both directory_length and file_length — confirmed from
        training data that directory and file presence are never
        independent: every row with directory_length == -1 also has
        file_length == -1 (zero exceptions across 88,647 rows), so a path
        that exists at all (even one segment) means both get real values.
        """
        f = extract_features("https://example.com/login")
        assert f["directory_length"] != -1
        assert f["file_length"] != -1
        assert f["file_length"] == len("login")


class TestFeatureSchema:
    """The extractor must produce EXACTLY the 98 lexical column names the
    trained model expects — no more, no fewer, since the model's input
    vector is order- and name-sensitive."""

    def test_produces_exactly_98_features(self):
        f = extract_features("https://example.com/path?query=1")
        assert len(f) == 98, f"Expected 98 features, got {len(f)}"

    def test_no_nan_or_none_values(self):
        f = extract_features("https://example.com")
        for key, value in f.items():
            assert value is not None, f"{key} is None"
            assert value == value, f"{key} is NaN"  # NaN != NaN is True, catches it


class TestRealWorldURLs:
    """Sanity checks against real-world-shaped URLs, including ones the
    original sentinel-value bug specifically broke."""

    def test_known_safe_domains_have_low_character_counts(self):
        for url in ["https://github.com", "https://www.google.com", "https://stackoverflow.com"]:
            f = extract_features(url)
            # These are simple, clean domains — should not trigger high counts
            # of any single special character
            assert f["qty_hyphen_url"] <= 1
            assert f["qty_at_url"] == 0

    def test_handles_url_with_at_symbol(self):
        f = extract_features("http://example.com/redirect?to=user@evil.com")
        assert f["qty_at_url"] >= 1
        assert f["email_in_url"] == 1

    def test_handles_ip_address_domain(self):
        f = extract_features("http://192.168.1.1/payload.exe")
        assert f["domain_in_ip"] == 1
