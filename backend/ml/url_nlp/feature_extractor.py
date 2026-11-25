"""
ml/url_nlp/training/feature_extractor.py
===========================================
Reproduces the lexical/structural feature schema from the
GregaVrbancic/Phishing-Dataset paper (Vrbančič, Fister Jr., Podgorelec —
"Datasets for Phishing Websites Detection", Data in Brief 33, 2020) from a
raw URL string alone, with NO network access required.

Per the paper (Figure 1), each URL is split into 5 sub-strings:
  url        — the full URL string
  domain     — the registered domain (netloc)
  directory  — the path portion, excluding the final filename segment
  file       — the final filename segment of the path
  params     — the query string

For each sub-string, the same family of character-count features is computed
(dot, hyphen, underscore, slash, question mark, equals, at, ampersand,
exclamation, space, tilde, comma, plus, asterisk, hashtag, dollar, percent),
plus sub-string-specific extras (vowel count for domain, length for each
sub-string, IP-literal detection, etc).

This module is the bridge between the trained model (which expects this
exact 98-column vector, in this exact order) and URLAnalyzer.analyze(),
which only ever has a raw URL string at inference time.
"""
import re
from typing import Dict
from urllib.parse import urlparse
from ml.url_nlp.tld import extract as tld_extract


CHAR_FEATURES = [
    ("dot", "."), ("hyphen", "-"), ("underline", "_"), ("slash", "/"),
    ("questionmark", "?"), ("equal", "="), ("at", "@"), ("and", "&"),
    ("exclamation", "!"), ("space", " "), ("tilde", "~"), ("comma", ","),
    ("plus", "+"), ("asterisk", "*"), ("hashtag", "#"), ("dollar", "$"),
    ("percent", "%"),
]

IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
VOWELS = set("aeiouAEIOU")


def _char_counts(s: str, prefix: str) -> Dict[str, int]:
    """Counts each special character in CHAR_FEATURES, keyed as qty_{char}_{prefix}."""
    return {f"qty_{name}_{prefix}": s.count(char) for name, char in CHAR_FEATURES}


def _split_url(url: str):
    """Splits a URL into (full_url, domain, directory, file, params) per the
    paper's Figure 1 sub-string decomposition.

    IMPORTANT: the "url" sub-string EXCLUDES the scheme (http:// or https://).
    This was reverse-engineered, not assumed: 47,509 of 88,647 training rows
    have qty_slash_url == 0, which is only possible if the scheme's "//" is
    excluded from the substring being counted (the scheme alone contributes
    2 slashes otherwise, making qty_slash_url == 0 impossible for any URL).
    Confirmed against the actual training data distribution before fixing —
    this bug originally caused github.com to score 92.8% phishing because
    every feature was computed on a substring one URL-scheme too long.
    """
    if not url.startswith(("http://", "https://")):
        url_with_scheme = "http://" + url
    else:
        url_with_scheme = url

    parsed = urlparse(url_with_scheme)
    domain = parsed.netloc
    path = parsed.path
    params = parsed.query

    # The "url" substring for feature counting = everything after the scheme,
    # i.e. domain + path + (? + params if present) — NOT including "http://"
    url_no_scheme = domain + path
    if params:
        url_no_scheme += "?" + params

    # directory = path up to (not including) the final segment; file = final segment
    if "/" in path.rstrip("/"):
        directory, _, file = path.rpartition("/")
    else:
        directory, file = "", path.lstrip("/")

    return url_no_scheme, domain, directory, file, params


def extract_features(url: str) -> Dict[str, float]:
    """
    Returns a dict with the exact 98 lexical feature names the trained model
    expects (LOOKUP_DEPENDENT_COLUMNS already excluded), computed purely from
    the URL string with no network access.

    CRITICAL ENCODING NOTE (found via debugging, not assumed): when a
    sub-string (directory, file, or params) is ABSENT from the URL — not
    just empty, but structurally absent, e.g. a bare domain like
    "github.com" has no directory/file/params at all — every feature
    derived from that sub-string is -1, NOT 0. This was reverse-engineered
    from the training data: 47,509 rows have directory_length == -1 with
    EVERY qty_*_directory column also exactly -1 (never 0), and the same
    pattern holds for file_length (47,509 rows) and params_length (81,225
    rows). This -1 sentinel distinguishes "the directory exists and has 0
    dots" from "there is no directory to count dots in" — collapsing both
    to 0 (an earlier bug in this function) corrupted every feature for any
    URL without a path, which is most simple homepage URLs, and caused
    https://github.com to score 93%+ phishing probability despite the
    underlying model being correctly trained.
    """
    full_url, domain, directory, file, params = _split_url(url)
    directory_present, file_present = _path_has_directory_and_file(url)
    params_present = bool(params)

    features: Dict[str, float] = {}

    # ── URL-level character counts + length + TLD count (always present) ────
    features.update(_char_counts(full_url, "url"))
    features["qty_tld_url"] = len(tld_extract(full_url).suffix.split(".")) if tld_extract(full_url).suffix else 0
    features["length_url"] = len(full_url)

    # ── Domain-level character counts + extras (always present) ─────────────
    features.update(_char_counts(domain, "domain"))
    features["qty_vowels_domain"] = sum(1 for c in domain if c in VOWELS)
    features["domain_length"] = len(domain)
    host_only = domain.split(":")[0]  # strip port if present
    features["domain_in_ip"] = 1 if IP_PATTERN.match(host_only) else 0
    features["server_client_domain"] = 1 if ("server" in domain.lower() or "client" in domain.lower()) else 0

    # ── Directory-level: -1 sentinel if no directory segment exists at all ───
    if directory_present:
        features.update(_char_counts(directory, "directory"))
        features["directory_length"] = len(directory)
    else:
        for name, _ in CHAR_FEATURES:
            features[f"qty_{name}_directory"] = -1
        features["directory_length"] = -1

    # ── File-level: -1 sentinel if no file segment exists at all ─────────────
    if file_present:
        features.update(_char_counts(file, "file"))
        features["file_length"] = len(file)
    else:
        for name, _ in CHAR_FEATURES:
            features[f"qty_{name}_file"] = -1
        features["file_length"] = -1

    # ── Params-level: -1 sentinel if no query string exists at all ───────────
    if params_present:
        features.update(_char_counts(params, "params"))
        features["params_length"] = len(params)
        features["tld_present_params"] = 1 if re.search(r'\.[a-z]{2,}', params, re.IGNORECASE) else 0
        features["qty_params"] = params.count("&") + 1
    else:
        for name, _ in CHAR_FEATURES:
            features[f"qty_{name}_params"] = -1
        features["params_length"] = -1
        features["tld_present_params"] = -1
        features["qty_params"] = -1

    # ── URL-level extras not covered by the char-count loop (always present) ─
    features["email_in_url"] = 1 if re.search(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', full_url, re.IGNORECASE) else 0
    features["url_shortened"] = 1 if domain.lower() in {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
    } else 0

    return features


def _path_has_directory_and_file(url: str):
    """
    Returns (directory_present, file_present) — always identical to each
    other, confirmed empirically from training data: every one of the
    47,509 rows with directory_length == -1 ALSO has file_length == -1
    (std == 0 across the group — not a coincidence, a hard rule), and
    there are zero rows with one present and the other absent. So in this
    dataset's encoding, a URL either HAS a path (both directory and file
    get real values, even if one segment is empty-string) or has NO path
    at all (both get -1). A single-segment path like "/login" therefore
    gets real (non-sentinel) values for both — verified this is consistent
    with the only two patterns that actually occur in the 88,647-row
    dataset; the alternative encoding (file present, directory absent for
    single-segment paths) was an earlier untested assumption in this
    function and does not occur anywhere in the real data.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    path = urlparse(url).path

    if not path or path == "/":
        return False, False
    return True, True


def get_feature_order(feature_columns_from_training: list) -> list:
    """
    Returns features in the exact column order the trained model expects.
    Always call this with the `feature_columns` list saved alongside the
    trained model (in the .joblib bundle) — never assume dict insertion
    order matches training order, since that's fragile across Python/pandas
    versions and refactors.
    """
    return feature_columns_from_training
