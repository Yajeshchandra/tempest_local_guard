"""
candidate.py
────────────
Internal Candidate dataclass for the Payload Engine pipeline.

A Candidate represents a *potential* secret/PII hit produced by a Provider
(regex, PII, or assignment).  It is enriched with evidence signals (entropy,
context keywords, file-path metadata) and then evaluated by Policy Evaluation
before being converted into a finding dict.

Design rules
─────────────
• Candidates are INTERNAL ONLY.  They are never exported from the payload
  package, never returned by any MCP tool, and never persisted.
• Only engine.py._emit_finding() converts a Candidate → finding dict.
• Entropy NEVER creates a Candidate.  It only enriches existing ones.

DO NOT IMPORT network libraries here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Candidate ────────────────────────────────────────────────────────────────


@dataclass
class Candidate:
    """
    A candidate secret or PII hit awaiting evidence enrichment and policy
    evaluation.

    Fields
    ──────
    file            : Absolute path of the file being scanned.
    line            : 1-based line number.
    raw_value       : The matched token / value (plain text, never logged).
    redacted_value  : Safe-to-log version (e.g. "AKIA****").
    policy_type     : Problem code ("P-01", "P-04", …).
    candidate_kind  : Source of the candidate: "regex" | "pii" | "assignment".
    base_severity   : Starting severity ("HIGH" | "MEDIUM" | "LOW").
                      For confidence_locked=True this is the final severity.
                      For confidence_locked=False this is overwritten by the
                      policy evaluator using confidence_to_severity().
    evidence        : Accumulated human-readable signal strings, e.g.
                        ["regex:P-01-AWS-ACCESS-KEY", "entropy:4.82",
                         "context:password", "file_path:sensitive"]
    confidence      : 0.0–1.0 score computed by policy evaluation from the
                      evidence signals.  Always computed independently of
                      severity — even when confidence_locked=True.
    metadata        : Free-form dict for additional data:
                        entropy     (float) — raw Shannon entropy of raw_value
                        path_adj    (float) — path confidence adjustment applied
                        context_keywords (list[str])
                        pattern_name     (str, regex candidates)
                        pii_label        (str, PII candidates)
                        description      (str, human-readable finding text)
    confidence_locked
                    : If True, severity is pinned to base_severity regardless
                      of the computed confidence score.  Set True for regex
                      and PII candidates (authoritative patterns).  Set False
                      for assignment candidates (must earn their severity).
    required_signals
                    : The policy evaluator drops the candidate if these signal
                      prefixes are not present in candidate.evidence.
                      Empty set → no requirement (always passes).
                        regex/pii  candidates: set()         — pattern match is sufficient
                        assignment candidates: {"entropy"}   — must have high entropy
    """

    file: str
    line: int
    raw_value: str
    redacted_value: str
    policy_type: str
    candidate_kind: str
    base_severity: str

    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    confidence_locked: bool = True
    required_signals: set[str] = field(default_factory=set)


# ── Factory helpers ───────────────────────────────────────────────────────────
# Use these instead of constructing Candidate() directly so that
# confidence_locked / required_signals are always set correctly for each kind.


def make_regex_candidate(
    *,
    file: str,
    line: int,
    raw_value: str,
    redacted_value: str,
    policy_type: str,
    base_severity: str,
    pattern_name: str,
    description: str,
) -> Candidate:
    """
    Create a candidate from a regex pattern match.

    Regex candidates are *authoritative*:
      • confidence_locked = True  → severity is always the pattern-defined value
      • required_signals  = set() → no additional signals required
    """
    return Candidate(
        file=file,
        line=line,
        raw_value=raw_value,
        redacted_value=redacted_value,
        policy_type=policy_type,
        candidate_kind="regex",
        base_severity=base_severity,
        evidence=[f"regex:{pattern_name}"],
        confidence=0.0,
        metadata={
            "pattern_name": pattern_name,
            "description": description,
        },
        confidence_locked=True,
        required_signals=set(),
    )


def make_pii_candidate(
    *,
    file: str,
    line: int,
    raw_value: str,
    redacted_value: str,
    policy_type: str,
    base_severity: str,
    pii_label: str,
) -> Candidate:
    """
    Create a candidate from a PII pattern match.

    PII candidates are *structurally validated*:
      • confidence_locked = True  → severity is always the pattern-defined value
      • required_signals  = set() → no entropy required (entropy is irrelevant for PII)

    Enrichment will add context keywords and file-path signals but will
    skip the entropy computation step entirely.
    """
    return Candidate(
        file=file,
        line=line,
        raw_value=raw_value,
        redacted_value=redacted_value,
        policy_type=policy_type,
        candidate_kind="pii",
        base_severity=base_severity,
        evidence=[f"pii:{pii_label}"],
        confidence=0.0,
        metadata={
            "pii_label": pii_label,
            "description": f"PII detected: {pii_label}",
        },
        confidence_locked=True,
        required_signals=set(),
    )


def make_assignment_candidate(
    *,
    file: str,
    line: int,
    raw_value: str,
    redacted_value: str,
    policy_type: str,
    key_name: str,
    syntax: str,
) -> Candidate:
    """
    Create a candidate from a generic key=value / key: value assignment.

    Assignment candidates are *unconfirmed*:
      • confidence_locked = False     → severity is derived from computed confidence
      • required_signals  = {"entropy"} → must have confirmed high entropy to survive
      • base_severity starts at LOW; policy evaluation raises it with evidence

    The *syntax* parameter records which config format matched the line
    (e.g. "env", "yaml", "json", "toml", "ini", "python", "properties").
    """
    return Candidate(
        file=file,
        line=line,
        raw_value=raw_value,
        redacted_value=redacted_value,
        policy_type=policy_type,
        candidate_kind="assignment",
        base_severity="LOW",
        evidence=[f"assignment:{syntax}"],
        confidence=0.0,
        metadata={
            "key_name": key_name,
            "syntax": syntax,
            "description": (
                f"Secret-like assignment detected ({syntax} syntax): "
                f"key '{key_name}' has a high-entropy value"
            ),
        },
        confidence_locked=False,
        required_signals={"entropy"},
    )
