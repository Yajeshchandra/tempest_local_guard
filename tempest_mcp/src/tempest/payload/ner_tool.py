"""
ner_tool.py
───────────
Named Entity Recognition (NER) for PII detection in fixture files and
VCR cassettes. Uses ONLY rule-based / regex heuristics — no external
models, no network calls — to stay fully air-gapped.

Covers:
    P-04  Customer PII in test fixture files (names, emails, phones, SSNs,
          credit card numbers, IP addresses, passport-style IDs)
    P-07  PII in recorded VCR cassette response bodies

NO external model downloads. NO network imports.
"""

import re
import sys

# ── PII Patterns ──────────────────────────────────────────────────────────────
# Each entry:
#   regex       : raw pattern
#   label       : human-readable PII category name
#   severity    : HIGH / MEDIUM
#   type        : P-04 or P-07

PII_PATTERNS: list[dict] = [

    # Email addresses
    {
        "regex": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        "label": "Email address",
        "severity": "HIGH",
        "type": "P-04",
    },

    # US Social Security Numbers (123-45-6789 or 123456789)
    {
        "regex": r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b',
        "label": "US Social Security Number (SSN)",
        "severity": "HIGH",
        "type": "P-04",
    },

    # Credit card numbers (Visa, MC, Amex, Discover)
    {
        "regex": r'\b(?:4[0-9]{12}(?:[0-9]{3})?'           # Visa
                 r'|5[1-5][0-9]{14}'                         # Mastercard
                 r'|3[47][0-9]{13}'                          # Amex
                 r'|6(?:011|5[0-9]{2})[0-9]{12})\b',        # Discover
        "label": "Credit card number",
        "severity": "HIGH",
        "type": "P-04",
    },

    # Phone numbers (US format: (123) 456-7890 / 123-456-7890 / +1-123-456-7890)
    {
        "regex": r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b',
        "label": "Phone number",
        "severity": "MEDIUM",
        "type": "P-04",
    },

    # IPv4 addresses that look real (not 0.x.x.x, not loopback 127.x.x.x)
    {
        "regex": r'\b(?!0\.|127\.|255\.)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                 r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        "label": "Non-loopback IPv4 address",
        "severity": "MEDIUM",
        "type": "P-04",
    },

    # Passport-style IDs (letter + 7-9 digits, common format)
    {
        "regex": r'\b[A-Z]{1,2}[0-9]{7,9}\b',
        "label": "Passport or government ID number",
        "severity": "HIGH",
        "type": "P-04",
    },

    # Date of birth patterns (YYYY-MM-DD or MM/DD/YYYY)
    {
        "regex": r'\b(?:19|20)\d{2}[/-](?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])\b',
        "label": "Date of birth (YYYY-MM-DD format)",
        "severity": "MEDIUM",
        "type": "P-04",
    },

    # UK National Insurance Numbers
    {
        "regex": r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b',
        "label": "UK National Insurance Number",
        "severity": "HIGH",
        "type": "P-04",
    },

    # IBAN bank account numbers
    {
        "regex": r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b',
        "label": "IBAN bank account number",
        "severity": "HIGH",
        "type": "P-04",
    },
]

# Compile all PII patterns once at module load
_COMPILED_PII: list[tuple[dict, re.Pattern]] = []
for _meta in PII_PATTERNS:
    try:
        _COMPILED_PII.append((_meta, re.compile(_meta["regex"])))
    except re.error as e:
        print(f"[ner_tool] WARNING: Could not compile PII pattern '{_meta['label']}': {e}",
              file=sys.stderr)


def _redact_pii(value: str, label: str) -> str:
    """
    Redact PII for safe logging. Strategy differs by type:
      - Email  : show domain only  → ****@gmail.com
      - Phone  : show last 4 only  → ****7890
      - Others : show type tag     → [REDACTED:SSN]
    """
    if "Email" in label and "@" in value:
        domain = value.split("@", 1)[1]
        return f"****@{domain}"
    if "Phone" in label:
        digits = re.sub(r'\D', '', value)
        return f"****{digits[-4:]}" if len(digits) >= 4 else "****"
    if "Credit card" in label:
        digits = re.sub(r'\D', '', value)
        return f"****{digits[-4:]}" if len(digits) >= 4 else "****"
    return f"[REDACTED:{label.split()[0].upper()}]"


def scan_line_for_pii(line: str, line_number: int, file_path: str) -> list[dict]:
    """
    Scan a single line of text for PII patterns.

    Args:
        line        : Raw text content of the line
        line_number : 1-based line number
        file_path   : Path of the file being scanned

    Returns:
        List of PII finding dicts. Empty list if nothing found.
    """
    findings: list[dict] = []
    seen_labels: set[str] = set()   # one finding per PII type per line

    for meta, pattern in _COMPILED_PII:
        match = pattern.search(line)
        if not match:
            continue

        label_key = f"{meta['label']}:{line_number}"
        if label_key in seen_labels:
            continue
        seen_labels.add(label_key)

        raw_value = match.group(0)
        findings.append({
            "file": file_path,
            "line": line_number,
            "type": meta["type"],
            "severity": meta["severity"],
            "match_redacted": _redact_pii(raw_value, meta["label"]),
            "description": f"PII detected: {meta['label']}",
            "source": "payload",
            "entropy": 0.0,
        })

    return findings


def calculate_pii_density(lines: list[str]) -> float:
    """
    Calculate what fraction of lines in a file contain PII.
    Used to decide severity: high-density PII files are more alarming
    than a single accidental occurrence.

    Returns: float between 0.0 (no PII) and 1.0 (every line has PII)
    """
    if not lines:
        return 0.0

    pii_line_count = 0
    for i, line in enumerate(lines, start=1):
        if scan_line_for_pii(line, i, ""):
            pii_line_count += 1

    return pii_line_count / len(lines)