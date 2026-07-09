"""
confidence.py
─────────────
Confidence scoring system for the Payload Engine.

Converts raw detection signals (regex match, entropy score, semantic context,
file-path metadata) into a single 0.0–1.0 confidence score, then maps that
score to a severity level (HIGH / MEDIUM / LOW).

Design goals:
  • Deterministic — no ML, no network, pure stdlib.
  • Configurable — all weights and thresholds live in CONFIDENCE_CONFIG.
  • Modular — new signals can be added by extending CONFIDENCE_CONFIG["weights"]
    and passing the signal in the signals dict.

Why this reduces false positives:
  Standalone entropy was the #1 source of noise. By requiring *multiple*
  corroborating signals before escalating severity, we keep real secrets
  (regex + context + entropy) at HIGH while pushing random high-entropy
  strings (entropy alone) down to LOW or suppressed.

DO NOT IMPORT network libraries here.
"""

from __future__ import annotations

import re
from pathlib import Path

# ── Configurable Confidence Configuration ─────────────────────────────────────
# All weights and thresholds in one dict so they can be tuned in a single place.
# Future: load overrides from a YAML/TOML config file if needed.

CONFIDENCE_CONFIG: dict = {
    # ── Signal weights (must sum to ≤ 1.0 for clean interpretation) ───────
    # Each weight represents the maximum confidence contribution from that
    # signal. A finding's total confidence = Σ(active signal weights).
    "weights": {
        "regex":          0.50,   # Regex pattern matched a known credential format
        "entropy":        0.15,   # Token has Shannon entropy > threshold
        "context":        0.20,   # Line contains a secret-related identifier nearby
        "sensitive_file": 0.15,   # File path suggests credentials / config / secrets
    },

    # ── Severity thresholds ───────────────────────────────────────────────
    # confidence >= high_threshold  → HIGH
    # confidence >= medium_threshold → MEDIUM
    # else                           → LOW
    "severity_thresholds": {
        "high":   0.70,
        "medium": 0.40,
    },

    # ── Path-based confidence adjustment ──────────────────────────────────
    # Boost: if ANY of these substrings appear in the normalised file path,
    #        add the sensitive_file weight.
    # Reduce: if ANY of these appear, subtract a penalty (but floor at 0).
    "path_boost_patterns": [
        ".env", "config", "credentials", "secrets", "secret",
        "docker-compose", "kubernetes", "k8s", "terraform",
        ".tfvars", "deploy", "ansible", "vault",
    ],
    "path_reduce_patterns": [
        "docs/", "examples/", "samples/", "fixtures/",
        "testdata/", "test_data/", "benchmarks/", "fuzz/",
        "corpus/", "generated/", "unicode", "vendor/",
        "node_modules/", "migrations/",
    ],
    "path_reduce_penalty": 0.10,

    # ── Entropy-skip path heuristics ──────────────────────────────────────
    # Entropy scanning is skipped when a file's *path* (not just extension)
    # matches low-value heuristics AND the filename does NOT look credential-
    # related.
    #
    # Why path-based instead of extension-only:
    #   "credentials.txt" should be scanned; "docs/README.txt" should not.
    "entropy_skip_path_patterns": [
        "docs/", "documentation/", "examples/", "samples/",
        "README", "CHANGELOG", "LICENSE", "CONTRIBUTING",
        "HISTORY", "AUTHORS",
    ],
    # Files matching these name substrings are NEVER skipped, even if they
    # sit inside a low-value directory.
    "entropy_never_skip_name_patterns": [
        "credential", "secret", "password", "token", "key",
        ".env", "config", "auth", "deploy", "connection",
    ],
}

# ── Context keywords ──────────────────────────────────────────────────────────
# When any of these appear near a high-entropy token on the same line, it's a
# strong signal that the token is a real secret, not random data.
SECRET_CONTEXT_KEYWORDS: frozenset[str] = frozenset({
    "password", "passwd", "pwd",
    "secret", "secret_key",
    "token", "access_token", "auth_token", "refresh_token",
    "api_key", "apikey", "api_secret",
    "access_key", "secret_access_key",
    "auth", "authorization", "bearer",
    "credential", "credentials",
    "connection_string", "connection_url",
    "database_url", "db_url", "db_password",
    "private_key", "private",
    "client_secret", "client_id",
    "signing_key", "encryption_key",
    "webhook_secret",
})

# Pre-compiled regex for fast context scanning.
# Matches any SECRET_CONTEXT_KEYWORDS as whole "words" in a case-insensitive way,
# where word boundaries include underscores, hyphens, dots, and whitespace.
_CONTEXT_RE = re.compile(
    r"(?i)(?:^|[\s=:\"'\-_.({,])("
    + "|".join(re.escape(kw) for kw in sorted(SECRET_CONTEXT_KEYWORDS, key=len, reverse=True))
    + r")(?:[\s=:\"'\-_.)},]|$)"
)


# ── Public API ────────────────────────────────────────────────────────────────

def calculate_confidence(signals: dict[str, bool]) -> float:
    """
    Compute a 0.0–1.0 confidence score from a dict of active signals.

    Args:
        signals: Mapping of signal name → whether it fired.
                 Keys must match CONFIDENCE_CONFIG["weights"] keys.
                 Example: {"regex": True, "entropy": True, "context": False,
                           "sensitive_file": True}

    Returns:
        Float in [0.0, 1.0]. Higher = more confident this is a real secret.

    Why this reduces false positives:
        Entropy alone contributes only 0.15 — far below the HIGH threshold
        (0.70). A finding needs regex OR multiple corroborating signals to
        reach HIGH.
    """
    weights = CONFIDENCE_CONFIG["weights"]
    total = 0.0
    for signal_name, is_active in signals.items():
        if is_active and signal_name in weights:
            total += weights[signal_name]
    return min(total, 1.0)


def confidence_to_severity(confidence: float) -> str:
    """
    Map a confidence score to a severity string.

    Uses thresholds from CONFIDENCE_CONFIG["severity_thresholds"].

    Why this reduces false positives:
        Previously, any entropy hit → HIGH. Now severity tracks confidence,
        so entropy-only findings (confidence ~0.15) → LOW.
    """
    thresholds = CONFIDENCE_CONFIG["severity_thresholds"]
    if confidence >= thresholds["high"]:
        return "HIGH"
    if confidence >= thresholds["medium"]:
        return "MEDIUM"
    return "LOW"


def has_secret_context(line: str) -> bool:
    """
    Return True if the line contains any secret-related identifier.

    Scans for keywords like "password", "api_key", "bearer", etc. near
    the high-entropy token. Case-insensitive.

    Why this reduces false positives:
        A random base64 blob in a Unicode table has no secret context.
        A line like `AWS_SECRET_ACCESS_KEY="xK9m..."` does.
    """
    return bool(_CONTEXT_RE.search(line))


def path_confidence_adjustment(file_path: str) -> float:
    """
    Return a confidence adjustment based on the file's path.

    - Sensitive paths (e.g., .env, config, credentials) → +sensitive_file weight
    - Low-value paths (e.g., docs/, examples/, fixtures/) → −penalty
    - Neutral paths → 0.0

    The adjustment is ADDED to the base confidence score. It can be negative
    (reducing confidence for docs/examples) but the final confidence is floored
    at 0.0 in calculate_confidence().

    Why this reduces false positives:
        A high-entropy string in "docs/unicode_tables.md" is almost certainly
        not a secret. One in ".env.production" almost certainly is.
    """
    normalised = str(file_path).replace("\\", "/").lower()

    # Check boost patterns first (sensitive files)
    for pattern in CONFIDENCE_CONFIG["path_boost_patterns"]:
        if pattern in normalised:
            return CONFIDENCE_CONFIG["weights"].get("sensitive_file", 0.15)

    # Check reduce patterns (low-value files)
    for pattern in CONFIDENCE_CONFIG["path_reduce_patterns"]:
        if pattern in normalised:
            return -CONFIDENCE_CONFIG["path_reduce_penalty"]

    return 0.0


def should_skip_entropy(file_path: str) -> bool:
    """
    Return True if entropy scanning should be skipped for this file.

    Uses PATH and FILENAME heuristics — not extension alone — so that files
    like "credentials.txt" are still scanned while "docs/README.txt" is not.

    Decision logic:
      1. If the filename contains a credential-related substring → NEVER skip
      2. If the file path matches a low-value pattern → skip
      3. Otherwise → don't skip

    Why this reduces false positives:
        Markdown docs, changelogs, and example files generate massive entropy
        noise but almost never contain real secrets. Credential-related files
        are explicitly excluded from skipping.

    Used by engine._enrich_candidates() to gate entropy enrichment per file.
    """
    normalised = str(file_path).replace("\\", "/").lower()
    basename = Path(file_path).name.lower()

    # Rule 1: Never skip files whose name looks credential-related.
    for pattern in CONFIDENCE_CONFIG["entropy_never_skip_name_patterns"]:
        if pattern in basename:
            return False

    # Rule 2: Skip if the path matches a low-value heuristic.
    for pattern in CONFIDENCE_CONFIG["entropy_skip_path_patterns"]:
        if pattern.lower() in normalised:
            return True

    return False


def build_evidence(
    *,
    regex_pattern_name: str | None = None,
    entropy_score: float | None = None,
    context_keywords_found: list[str] | None = None,
    file_path_signal: str | None = None,
    binary_detected: bool = False,
) -> list[str]:
    """
    Build a human-readable evidence list explaining which signals contributed
    to a finding.

    Each entry is a short string like:
      "regex:P-01-AWS-ACCESS-KEY"
      "entropy:4.82"
      "context:password,api_key"
      "file_path:sensitive(.env)"
      "binary:true"

    Why this helps:
        Makes tuning and debugging dramatically easier. When reviewing
        findings you can immediately see *why* something was flagged instead
        of guessing from the severity alone.
    """
    evidence: list[str] = []

    if regex_pattern_name:
        evidence.append(f"regex:{regex_pattern_name}")

    if entropy_score is not None and entropy_score > 0:
        evidence.append(f"entropy:{entropy_score:.2f}")

    if context_keywords_found:
        evidence.append(f"context:{','.join(context_keywords_found)}")

    if file_path_signal:
        evidence.append(f"file_path:{file_path_signal}")

    if binary_detected:
        evidence.append("binary:true")

    return evidence


def extract_context_keywords(line: str) -> list[str]:
    """
    Return the list of secret-context keywords found on the given line.

    Used by build_evidence() to populate the context signal detail.
    """
    found: list[str] = []
    for m in _CONTEXT_RE.finditer(line):
        kw = m.group(1).lower()
        if kw not in found:
            found.append(kw)
    return found
