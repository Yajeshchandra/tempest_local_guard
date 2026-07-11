"""
regex_tool.py
─────────────
Cryptographic regex patterns for detecting hardcoded secrets, credentials,
and sensitive data in source files.

Covers:
    P-01  Hardcoded credentials (AWS keys, DB URIs, API keys, tokens)
    P-02  Secrets in un-ignored .env files
    P-06  Secrets inside build artifacts (detected at extension level)
    P-07  VCR cassette files with recorded API responses containing tokens
    P-08  IDE artifact files (e.g. .vscode/settings.json with tokens)

NO network imports. Pure regex only.
"""

import re
import sys
from typing import Optional
from tempest.payload.entropy_tool import calculate_entropy

# ── Master Pattern Registry ───────────────────────────────────────────────────
# Each entry defines:
#   regex       : raw pattern string
#   description : human-readable explanation shown in the finding
#   severity    : HIGH / MEDIUM / LOW
#   type        : problem code P-XX
#
# ORDER MATTERS — more specific patterns come first to avoid shadowing.

PATTERNS: dict[str, dict] = {

    # ── P-01: AWS Credentials ────────────────────────────────────────────────
    "P-01-AWS-ACCESS-KEY": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "description": "AWS access key ID hardcoded in source file",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-AWS-SECRET-KEY": {
        "regex": r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        "description": "AWS secret access key hardcoded in source file",
        "severity": "HIGH",
        "type": "P-01",
    },

    # ── P-01: Database Connection Strings ────────────────────────────────────
    "P-01-DB-URI-POSTGRES": {
        "regex": r'postgres(?:ql)?://\S+:\S+@[^\s"\']+',
        "description": "PostgreSQL connection string with embedded credentials",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-DB-URI-MYSQL": {
        "regex": r'mysql(?:\+\w+)?://\S+:\S+@[^\s"\']+',
        "description": "MySQL connection string with embedded credentials",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-DB-URI-MONGODB": {
        "regex": r'mongodb(?:\+srv)?://\S+:\S+@[^\s"\']+',
        "description": "MongoDB connection string with embedded credentials",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-DB-URI-REDIS": {
        "regex": r'redis://\S+:\S+@[^\s"\']+',
        "description": "Redis connection string with embedded credentials",
        "severity": "HIGH",
        "type": "P-01",
    },

    # ── P-01: Generic API Keys ───────────────────────────────────────────────
    "P-01-GENERIC-API-KEY": {
        "regex": r'(?i)api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
        "description": "Hardcoded API key assignment detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-GENERIC-SECRET": {
        "regex": r'(?i)(?:secret|token|private[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9\-_/+=.]{16,})["\']',
        "description": "Hardcoded secret or token value detected",
        "severity": "HIGH",
        "type": "P-01",
    },

    # ── P-01: Passwords ──────────────────────────────────────────────────────
    "P-01-HARDCODED-PASSWORD": {
        "regex": r'(?i)password\s*[=:]\s*["\']([^"\']{6,})["\']',
        "description": "Hardcoded password value detected",
        "severity": "HIGH",
        "type": "P-01",
    },

    # ── P-01: Service-Specific Tokens ────────────────────────────────────────
    "P-01-GITHUB-TOKEN": {
        "regex": r'gh[pousr]_[A-Za-z0-9]{36,}',
        "description": "GitHub personal access token detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-SLACK-TOKEN": {
        "regex": r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}',
        "description": "Slack API token detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-STRIPE-KEY": {
        "regex": r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
        "description": "Stripe API key (live or test) detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-SENDGRID-KEY": {
        "regex": r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}',
        "description": "SendGrid API key detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-TWILIO-SID": {
        "regex": r'AC[a-z0-9]{32}',
        "description": "Twilio Account SID detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-GCP-API-KEY": {
        "regex": r'AIza[0-9A-Za-z\-_]{35}',
        "description": "Google Cloud / Firebase API key detected",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-PRIVATE-KEY-BLOCK": {
        "regex": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "description": "Private key PEM block detected in source file",
        "severity": "HIGH",
        "type": "P-01",
    },
    "P-01-JWT-TOKEN": {
        "regex": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        "description": "JWT token hardcoded in source file",
        "severity": "HIGH",
        "type": "P-01",
    },

    # ── P-02: .env File Secrets ──────────────────────────────────────────────
    "P-02-ENV-KEY-VALUE": {
        "regex": r'^(?:SECRET|TOKEN|KEY|PASSWORD|PRIVATE|CREDENTIAL|AUTH)[_A-Z0-9]*\s*=\s*["\']?(\S{8,})["\']?',
        "description": "Secret value assigned in environment configuration file",
        "severity": "HIGH",
        "type": "P-02",
    },
    "P-02-ANY-TOKEN-ENV": {
        "regex": r'^[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASS|PWD|CREDENTIAL)\s*=\s*["\']?(\S{8,})["\']?',
        "description": "Secret value assigned in environment configuration file",
        "severity": "HIGH",
        "type": "P-02",
    },

    # ── P-07: VCR Cassette Authorization Headers ─────────────────────────────
    "P-07-VCR-AUTH-HEADER": {
        "regex": r'(?i)(?:Authorization|X-Api-Key|Bearer):\s*([A-Za-z0-9\-_=+/]{20,})',
        "description": "Authorization header with token recorded in VCR cassette",
        "severity": "HIGH",
        "type": "P-07",
    },
    "P-07-VCR-BASIC-AUTH": {
        "regex": r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})',
        "description": "Basic auth credentials recorded in VCR cassette file",
        "severity": "HIGH",
        "type": "P-07",
    },

    # ── P-08: IDE Artifact Secrets ───────────────────────────────────────────
    "P-08-IDE-ENV-VALUE": {
        # Only real secret-bearing JSON keys — NOT generic "value"/"key", which
        # match ordinary request-field metadata (Postman collections, OpenAPI
        # specs) and produced dozens of false positives per file.
        "regex": r'(?i)"(?:secret|token|password|passwd|api[_\-]?key|access[_\-]?key|client[_\-]?secret|private[_\-]?key)"\s*:\s*"([A-Za-z0-9\-_=+/]{16,})"',
        "description": "Secret value found inside IDE configuration artifact",
        "severity": "MEDIUM",
        "type": "P-08",
    },
}


# Bare `password = "..."` is the weakest P-01 signal — test fixtures are full of
# dummy passwords. Suppress obvious placeholders and low-entropy values so they
# don't bury the real secrets. Real random/prod passwords clear the entropy floor.
_PLACEHOLDER_SECRET_VALUES: frozenset[str] = frozenset({
    "password", "passw0rd", "password1", "password123", "changeme", "change_me",
    "changethis", "secret", "test", "testtest", "testpass", "example", "admin",
    "root", "letmein", "myprecious", "foobar", "foobarbaz", "foobarbaz123",
    "hunter2", "123456", "qwerty", "yourpassword", "your_password", "placeholder",
    "dummy", "notarealpassword",
})
_MIN_PASSWORD_ENTROPY: float = 3.5

# Local/dev DB hosts. A connection string to one of these, with dummy creds, is
# a local/CI setup (docker-compose, GitHub Actions), not a prod-credential leak.
_LOCAL_DB_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})
_DSN_CREDS_RE = re.compile(r'://([^:@/\s]+):([^@/\s]+)@([^:/\s"\']+)')


def _is_dummy_local_dsn(uri: str) -> bool:
    """True if a DB connection string points at a local/bare host with dummy
    credentials (user==password, or a placeholder password). Requires BOTH so a
    real prod DSN (distinct creds, dotted prod host) is never suppressed."""
    m = _DSN_CREDS_RE.search(uri)
    if not m:
        return False
    user, pw, host = m.group(1), m.group(2), m.group(3)
    local_host = host.lower() in _LOCAL_DB_HOSTS or "." not in host  # bare docker-service name
    dummy_cred = user == pw or pw.lower() in _PLACEHOLDER_SECRET_VALUES
    return local_host and dummy_cred


# ── Compiled pattern cache (compile once, reuse on every line) ────────────────
_COMPILED: dict[str, Optional[re.Pattern]] = {}

def _get_compiled(name: str, pattern_str: str) -> Optional[re.Pattern]:
    """Compile and cache regex. Returns None if pattern is invalid."""
    if name not in _COMPILED:
        try:
            _COMPILED[name] = re.compile(pattern_str)
        except re.error as e:
            print(f"[regex_tool] WARNING: Invalid regex '{name}': {e}", file=sys.stderr)
            _COMPILED[name] = None
    return _COMPILED[name]


def _redact(value: str) -> str:
    """
    Redact a matched secret for safe logging.
    Keeps the first 4 characters so the developer can identify the type,
    then replaces the rest with '****'.

    Examples:
        _redact("AKIAIOSFODNN7EXAMPLE")  →  "AKIA****"
        _redact("sk_live_abc123")        →  "sk_l****"
        _redact("hi")                    →  "****"     (too short to show any chars)
    """
    if len(value) <= 4:
        return "****"
    return value[:4] + "****"


def scan_line(line: str, line_number: int, file_path: str) -> list[dict]:
    """
    Run all PATTERNS against a single line of text.

    Args:
        line        : Raw text of the line (no newline character needed)
        line_number : 1-based line number in the file
        file_path   : Full path of the file being scanned

    Returns:
        List of finding dicts. Empty list if nothing found.
        Each finding has keys: file, line, type, severity,
                               match_redacted, description, source, entropy
    """
    findings: list[dict] = []
    seen_types_on_line: set[str] = set()   # avoid duplicate type per line

    from pathlib import Path
    is_env_file = ".env" in Path(file_path).name.lower()

    for name, meta in PATTERNS.items():
        if meta["type"] == "P-02" and not is_env_file:
            continue

        pattern = _get_compiled(name, meta["regex"])
        if pattern is None:
            continue  # skip broken patterns, already logged

        match = pattern.search(line)
        if not match:
            continue

        # Use the first capture group if present, else the whole match
        raw_match = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

        # Bare-password gate: drop placeholder / low-entropy dummy passwords.
        # ponytail: entropy+denylist only. A weak password in a prod-referencing
        # file is missed — upgrade path: pass a file-level prod-identifier flag.
        if name == "P-01-HARDCODED-PASSWORD":
            val = raw_match.strip()
            if val.lower() in _PLACEHOLDER_SECRET_VALUES or calculate_entropy(val) < _MIN_PASSWORD_ENTROPY:
                continue

        # DB-URI gate: skip local/CI connection strings with dummy creds
        # (postgres:postgres@db, ...@localhost) — not a prod-credential leak.
        if name.startswith("P-01-DB-URI") and _is_dummy_local_dsn(match.group(0)):
            continue

        # De-duplicate: one finding per (type, line) — same type cannot appear twice on same line
        dedup_key = f"{meta['type']}:{line_number}"
        if dedup_key in seen_types_on_line:
            continue
        seen_types_on_line.add(dedup_key)

        findings.append({
            "file": file_path,
            "line": line_number,
            "type": meta["type"],
            "severity": meta["severity"],
            "match_redacted": _redact(raw_match),
            "description": meta["description"],
            "source": "payload",
            "entropy": round(calculate_entropy(raw_match), 2),
        })

    return findings