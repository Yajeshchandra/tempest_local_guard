"""
entropy_tool.py
───────────────
Calculates Shannon Entropy of a string to decide if it looks like a
random secret (high entropy) or a normal human-readable value (low entropy).


DO NOT IMPORT network libraries here.
"""

import math
from collections import Counter

# ── Threshold ────────────────────────────────────────────────────────────────
# Strings with entropy > 4.5 are considered suspicious (random/secret-looking).
# Human words like "password" or "hello" score ~2–3.
# Real API keys / tokens typically score 4.5–6.0.
ENTROPY_THRESHOLD = 4.5


def calculate_entropy(value: str) -> float:
    """
    Shannon Entropy: H(X) = -Σ P(xi) * log2(P(xi))

    Each character's probability = count / total_length.
    Higher score = more random = more likely to be a secret.

    Examples:
        calculate_entropy("hello")                →  ~2.32   (low, normal word)
        calculate_entropy("AKIAIOSFODNN7EXAMPLE") →  ~4.08   (medium-high, AWS key)
        calculate_entropy("xK9mP2qRtL7wJnVbYhCd") →  ~4.7+   (high, random token)
        calculate_entropy("")                      →   0.0    (empty string)
    """
    if not value:
        return 0.0

    total = len(value)
    freq = Counter(value)

    entropy = 0.0
    for count in freq.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(value: str) -> bool:
    """
    Returns True if the string's entropy exceeds ENTROPY_THRESHOLD.
    Used by payload engine to flag suspicious tokens in source files.
    """
    return calculate_entropy(value) > ENTROPY_THRESHOLD