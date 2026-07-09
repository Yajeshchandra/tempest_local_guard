"""
payload_engine.py
─────────────────
Tier 2 Detection Engine — Content-Based Leaks.

Solves ALL four Tier 2 threat categories:

    P-01  Hardcoded credentials (AWS keys, DB URIs, API keys, private keys,
          service tokens: GitHub, Slack, Stripe, SendGrid, Twilio, GCP, JWT)
    P-02  Secrets in un-ignored .env files
    P-04  Customer PII in test fixture files (emails, SSNs, credit cards,
          phone numbers, IP addresses, passport IDs)
    P-05  PII embedded in Jupyter notebook cell outputs (.ipynb files)
    P-06  Secrets inside binary build artifacts (.jar, .class, .pyc, etc.)
    P-07  Authorization tokens in VCR cassette files (.yaml cassette files)
    P-08  Secrets inside IDE artifact files (.vscode/settings.json, etc.)

Architecture — Candidate/Evidence Pipeline
───────────────────────────────────────────
Every text line is processed through four stages:

  1. Provider Layer  — Regex, PII, and Assignment providers each produce
                       Candidate objects.  No findings are emitted here.

  2. Enrichment      — Entropy score, context keywords, and file-path
                       signals are added to each Candidate's evidence list.
                       should_skip_entropy() gates entropy enrichment per file.
                       PII candidates skip entropy enrichment entirely.

  3. Policy Evaluation — required_signals gate drops Candidates that lack
                         mandatory evidence (e.g. assignment candidates without
                         high entropy).  Confidence is always computed from
                         evidence signals.  Severity is locked for regex/PII
                         (confidence_locked=True) and derived from confidence
                         for assignment candidates (confidence_locked=False).

  4. Emission        — _emit_finding() is the ONLY place that produces a
                       finding dict.  No other function in any module may
                       construct a finding dict.

Architecture position:
    payload/scan.py  →  PayloadEngine.scan(file_paths)  →  findings list
    Driven by the standalone content scan (`tempest_scan_content` MCP tool),
    which walks the whole repo tree. Independent of the graph/dataflow pipeline
    (`tempest_detect`); needs no graph.json.

Import:
    from tempest.payload.engine import PayloadEngine
"""

import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

from tempest.payload.entropy_tool import (
    calculate_entropy,
    is_high_entropy,
    ENTROPY_THRESHOLD,
)
from tempest.payload.candidate import (
    Candidate,
    make_assignment_candidate,
)
from tempest.payload.regex_tool import collect_regex_candidates
from tempest.payload.ner_tool import collect_pii_candidates
from tempest.payload.confidence import (
    calculate_confidence,
    confidence_to_severity,
    has_secret_context,
    should_skip_entropy,
    path_confidence_adjustment,
    build_evidence,
    extract_context_keywords,
    SECRET_CONTEXT_KEYWORDS,
    CONFIDENCE_CONFIG,
)

# ── Extension Classification ──────────────────────────────────────────────────

# Binary extensions: NEVER read content. Flag immediately as P-06.
BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".jar", ".class", ".pyc", ".pyo", ".pyd",
    ".exe", ".dll", ".so", ".dylib",
    ".bin", ".obj", ".o", ".a",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".war", ".ear",                       # Java archives
    ".wasm",                              # WebAssembly
    ".lock",                              # lock files (binary-like)
})

# IDE artifact extensions / paths that trigger P-08 scanning
IDE_ARTIFACT_PATHS: frozenset[str] = frozenset({
    ".vscode/settings.json",
    ".idea/workspace.xml",
    ".idea/dataSources.xml",
    ".idea/dataSources.local.xml",
    ".eclipse/org.eclipse.core.runtime",
})

# VCR cassette patterns that trigger P-07 scanning
VCR_CASSETTE_PATTERNS: tuple[str, ...] = (
    "cassettes/",
    "fixtures/vcr/",
    ".yaml",     # most cassettes are .yaml
    ".json",     # some cassettes are .json
)

# Test fixture patterns that trigger P-04 (PII) scanning
FIXTURE_PATTERNS: tuple[str, ...] = (
    "fixtures/",
    "testdata/",
    "test_data/",
    "seed",
    "factory",
    "factories/",
    "spec/support/",
    "seeds/",
)

# File extensions we actively scan (everything else is silently ignored).
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".cs", ".php",   # source
    ".env", ".env.local", ".env.test", ".env.example",            # env files
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".config", # config
    ".xml", ".properties",                                         # more config
    ".ipynb",                                                      # Jupyter
    ".txt", ".md",                                                 # text
    ".sh", ".bash", ".zsh",                                        # shell
    ".tf", ".tfvars",                                              # Terraform
    ".sql",                                                        # DB scripts
})

# Number of bytes to read for binary detection heuristic.
_BINARY_CHECK_SIZE = 4096

# High PII-density threshold: if >20% of lines have PII, escalate to HIGH
PII_DENSITY_ESCALATION_THRESHOLD = 0.20

# ── Policy Refinement Constants ───────────────────────────────────────────────

# Domains that are RFC-reserved for documentation and testing.
RFC_DOMAINS: tuple[str, ...] = ("@example.com", "@example.org", "@example.net", "@example.test")

# Bounded words that indicate a value is a placeholder, not a real secret.
PLACEHOLDER_WORDS: set[str] = {"fake", "dummy", "example", "placeholder", "sample", "mock", "test"}
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9])(" + "|".join(PLACEHOLDER_WORDS) + r")(?:[^a-z0-9]|$)"
)

# Known local development database hosts.
LOCAL_DB_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})


# ── Assignment provider patterns ──────────────────────────────────────────────
#
# A generalised pattern that matches key=value / key: value assignments across
# common configuration syntaxes: shell env, YAML, JSON, TOML, INI, Python,
# and .properties files.
#
# Capture groups:
#   group "key"   — the variable / parameter name
#   group "value" — the assigned value (at least 8 non-whitespace chars)
_ASSIGNMENT_RE = re.compile(
    r"""
    (?:^|[\s,{])                         # start of line or preceding delimiter
    ["']?                                # optional opening quote on key
    (?P<key>[A-Za-z0-9._\-]{2,60})      # key name (2–60 word chars)
    ["']?                                # optional closing quote on key
    \s*[:=]\s*                           # separator: colon or equals
    ["']?                                # optional opening quote on value
    (?P<value>[^\s"',;}{>\]\[\n]{8,})   # value: ≥8 non-whitespace chars
    ["']?                                # optional closing quote
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Values that look like bare URL schemes (no credentials embedded).
_BARE_URL_RE = re.compile(r'^[a-z][a-z0-9+\-.]{1,20}://[^:@\s]{1,}$', re.IGNORECASE)

# Secret context keyword set — imported from confidence.py so it stays in sync.
_SECRET_KEYWORDS_LOWER: frozenset[str] = frozenset(
    kw.lower().replace("_", "").replace("-", "")
    for kw in SECRET_CONTEXT_KEYWORDS
)


def _key_looks_secret(key: str) -> bool:
    """
    Return True if the key name suggests it holds a secret value.

    We normalise the key by stripping underscores, hyphens, and dots, then
    check if any secret context keyword is a substring of the normalised key.

    Examples:
        "PASSWORD"           → True   ("password" substring)
        "api_key"            → True   ("apikey" after normalisation)
        "DB.Password"        → True   ("password" substring)
        "sha512"             → False
        "integrity"          → False
        "PatchJson6902"      → False
    """
    normalised = key.lower().replace("_", "").replace("-", "").replace(".", "")
    return any(kw in normalised for kw in _SECRET_KEYWORDS_LOWER)


def _value_looks_like_secret(value: str) -> bool:
    """
    Return True if the value passes the basic non-plaintext checks:
      • Not purely alphabetic (rejects "changeme", "placeholder", "example")
      • Not a bare URL without credentials
      • Minimum length 8 chars (already enforced in the regex, double-checked here)
    """
    if len(value) < 8:
        return False
    # Reject purely alphabetic values — these are placeholder words
    if value.isalpha():
        return False
    # Reject bare URL schemes (no embedded credentials)
    if _BARE_URL_RE.match(value):
        return False
    return True


class PayloadEngine:
    """
    Tier 2 content-based leak detector.

    Scans staged files for hardcoded credentials, PII, and secrets.
    Operates entirely locally — zero network calls.

    Problem codes handled:
        P-01  Hardcoded credentials in source / config files
        P-02  Secrets in .env files
        P-04  Customer PII in fixture / test data files
        P-05  PII or secrets in Jupyter notebook outputs
        P-06  Binary build artifacts staged for commit
        P-07  Auth tokens in VCR cassette recordings
        P-08  Secrets in IDE configuration artifacts
    """

    # ── Public Interface (called by orchestrator.py) ──────────────────────────

    def scan(self, file_paths: list[str]) -> list[dict]:
        """
        Main entry point. Called by payload/scan.py with the repo's file list.

        Args:
            file_paths: List of absolute or relative paths to staged files.

        Returns:
            Deduplicated list of finding dicts, each with keys:
                file, line, type, severity, match_redacted,
                description, source, entropy, confidence, evidence
        """
        all_findings: list[dict] = []

        for path in file_paths:
            try:
                findings = self._route_file(path)
                all_findings.extend(findings)
            except Exception as e:
                # Never crash the git hook — log and continue
                print(f"[payload_engine] ERROR scanning '{path}': {e}", file=sys.stderr)

        return self._deduplicate(all_findings)

    # ── File Router ───────────────────────────────────────────────────────────

    def _route_file(self, file_path: str) -> list[dict]:
        """
        Decide HOW to scan a file based on its extension and path.
        Returns list of findings (may be empty).
        """
        path = Path(file_path)
        ext = path.suffix.lower()
        basename = path.name.lower()

        # ── Guard 1: File must exist ─────────────────────────────────────────
        if not path.exists():
            print(f"[payload_engine] SKIP (not found): {file_path}", file=sys.stderr)
            return []

        # ── Guard 2: Known binary extension → P-06, no content read ──────────
        if ext in BINARY_EXTENSIONS:
            return [self._make_binary_finding(file_path)]

        # ── Guard 3: Handle dotfiles like ".env" ──────────────────────────────
        if basename.startswith(".env"):
            if self._is_binary_file(file_path):
                return [self._make_binary_finding(file_path)]
            return self._scan_text_file(file_path, scan_pii=False)

        # ── Guard 4: Unsupported extension → skip silently ───────────────────
        if ext not in SUPPORTED_EXTENSIONS:
            return []

        # ── Guard 5: Content-based binary detection ──────────────────────────
        if self._is_binary_file(file_path):
            return [self._make_binary_finding(file_path)]

        # ── Route by file type ────────────────────────────────────────────────
        path_str = str(file_path).replace("\\", "/")   # normalise Windows paths

        if ext == ".ipynb":
            return self._scan_notebook(file_path)

        if self._is_ide_artifact(path_str):
            return self._scan_text_file(file_path, scan_pii=False, extra_type_tag="P-08")

        if self._is_vcr_cassette(path_str):
            return self._scan_text_file(file_path, scan_pii=True, vcr_mode=True)

        if self._is_fixture_file(path_str):
            return self._scan_text_file(file_path, scan_pii=True)

        if ext in {".env", ".env.local", ".env.test", ".env.example"}:
            return self._scan_text_file(file_path, scan_pii=False)

        # Default: source/config file — P-01 regex + assignment
        return self._scan_text_file(file_path, scan_pii=False)

    # ── Core Text Scanner ─────────────────────────────────────────────────────

    def _scan_text_file(
        self,
        file_path: str,
        scan_pii: bool = False,
        vcr_mode: bool = False,
        extra_type_tag: str = "",
    ) -> list[dict]:
        """
        Read a text file line by line and drive the candidate/evidence pipeline
        for each line via _scan_logical_line().
        """
        lines = self._read_file_lines(file_path)
        if lines is None:
            return []

        findings: list[dict] = []

        for line_number, line in enumerate(lines, start=1):
            stripped = line.rstrip("\n")
            line_findings = self._scan_logical_line(
                stripped, line_number, file_path, scan_pii=scan_pii
            )

            if extra_type_tag:
                for f in line_findings:
                    f["type"] = extra_type_tag
                    if vcr_mode:
                        f["description"] = f["description"].replace(
                            "source file", "VCR cassette"
                        )
            findings.extend(line_findings)

        # PII density escalation
        if scan_pii and lines:
            from tempest.payload.ner_tool import calculate_pii_density
            density = calculate_pii_density(lines)
            if density >= PII_DENSITY_ESCALATION_THRESHOLD:
                for f in findings:
                    if f["type"] in ("P-04", "P-07") and f["severity"] == "MEDIUM":
                        f["severity"] = "HIGH"
                        f["description"] += f" [escalated: {density:.0%} of file is PII]"

        return findings

    # ── Jupyter Notebook Scanner (P-05) ───────────────────────────────────────

    def _scan_notebook(self, file_path: str) -> list[dict]:
        """
        Jupyter notebooks are JSON. Code and outputs are buried inside cells.
        This method unwraps the JSON structure and scans the actual content.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                notebook = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[payload_engine] SKIP (invalid JSON notebook): {file_path}: {e}", file=sys.stderr)
            return []
        except Exception as e:
            print(f"[payload_engine] SKIP (cannot read notebook): {file_path}: {e}", file=sys.stderr)
            return []

        findings: list[dict] = []
        virtual_line = 1

        cells = notebook.get("cells", [])
        for cell_index, cell in enumerate(cells):
            cell_type = cell.get("cell_type", "unknown")

            source_lines = cell.get("source", [])
            if isinstance(source_lines, str):
                source_lines = source_lines.splitlines()

            output_lines: list[str] = []
            for output in cell.get("outputs", []):
                text = output.get("text", [])
                if isinstance(text, str):
                    text = text.splitlines()
                output_lines.extend(text)

                data = output.get("data", {})
                for key in ("text/plain", "application/json"):
                    rich = data.get(key, [])
                    if isinstance(rich, str):
                        rich = rich.splitlines()
                    elif isinstance(rich, dict):
                        rich = [json.dumps(rich)]
                    output_lines.extend(rich)

            all_cell_lines = source_lines + output_lines

            for line in all_cell_lines:
                stripped = str(line).rstrip("\n")
                cell_prefix = f"[Cell {cell_index+1}/{cell_type}] "

                line_findings = self._scan_logical_line(
                    stripped, virtual_line, file_path, scan_pii=True
                )
                for f in line_findings:
                    f["type"] = "P-05"
                    f["description"] = cell_prefix + f["description"]
                findings.extend(line_findings)

                virtual_line += 1

        return findings

    # ── Candidate/Evidence Pipeline ───────────────────────────────────────────

    def _scan_logical_line(
        self,
        line: str,
        line_number: int,
        file_path: str,
        scan_pii: bool = False,
    ) -> list[dict]:
        """
        Full pipeline for a single logical line of text:
          1. Collect candidates from all providers
          2. Enrich candidates with evidence signals
          3. Evaluate candidates (required_signals gate + confidence + severity)
          4. Emit findings
        """
        candidates = self._collect_candidates(line, line_number, file_path, scan_pii)
        candidates = self._enrich_candidates(candidates, line, file_path)
        candidates = self._evaluate_candidates(candidates, file_path)
        return [self._emit_finding(c) for c in candidates]

    def _collect_candidates(
        self,
        line: str,
        line_number: int,
        file_path: str,
        scan_pii: bool,
    ) -> list[Candidate]:
        """
        Call all three providers and merge their candidates into one pool.
        Deduplicates by (policy_type, raw_value).
        """
        pool: list[Candidate] = []

        pool.extend(collect_regex_candidates(line, line_number, file_path))

        if scan_pii:
            pool.extend(collect_pii_candidates(line, line_number, file_path))

        pool.extend(self._collect_assignment_candidates(line, line_number, file_path))

        # ── Detector Coordination ─────────────────────────────────────────────
        # Suppress PII Email candidates if they are fully contained inside a DB URI match.
        db_uris = [
            c.raw_value for c in pool
            if c.candidate_kind == "regex" and str(c.metadata.get("pattern_name", "")).startswith("P-01-DB-URI-")
        ]

        coordinated_pool = []
        for c in pool:
            if c.candidate_kind == "pii" and "Email" in str(c.metadata.get("pii_label", "")):
                # If the email string is a substring of any DB URI string from the same line, drop it.
                if any(c.raw_value in db_uri for db_uri in db_uris):
                    continue
            coordinated_pool.append(c)

        # ── Deduplication ─────────────────────────────────────────────────────
        seen: set[str] = set()
        unique: list[Candidate] = []
        for c in coordinated_pool:
            key = f"{c.policy_type}:{c.raw_value}"
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    def _collect_assignment_candidates(
        self,
        line: str,
        line_number: int,
        file_path: str,
    ) -> list[Candidate]:
        """
        Detect generic key=value / key: value assignments where the key name
        suggests the value is a secret.

        Supports common config syntaxes:
          • Shell env  : SECRET_TOKEN=supersecret123
          • Quoted env : SECRET_TOKEN="supersecret123"
          • Python/TOML: password = "Xh82Js91"
          • YAML bare  : password: Xh82Js91
          • YAML quoted: password: "Xh82Js91"
          • JSON       : "password": "Xh82Js91"
          • INI        : password = Xh82Js91
          • Properties : db.password=Xh82Js91

        A candidate is created only when ALL of:
          ✓ key name contains a secret context keyword
          ✓ value length >= 8 characters (enforced in regex)
          ✓ value is not purely alphabetic
          ✓ value is not a bare URL scheme without credentials
        """
        candidates: list[Candidate] = []
        seen_keys: set[str] = set()

        for match in _ASSIGNMENT_RE.finditer(line):
            key = match.group("key")
            value = match.group("value")

            value = value.rstrip("'\"\\,;")

            if not _key_looks_secret(key):
                continue
            if not _value_looks_like_secret(value):
                continue

            dedup_key = f"{key.lower()}:{line_number}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            syntax = self._detect_assignment_syntax(line, match)

            redacted = value[:4] + "****" if len(value) > 4 else "****"
            candidates.append(
                make_assignment_candidate(
                    file=file_path,
                    line=line_number,
                    raw_value=value,
                    redacted_value=redacted,
                    policy_type="P-01",
                    key_name=key,
                    syntax=syntax,
                )
            )

        return candidates

    @staticmethod
    def _detect_assignment_syntax(line: str, match: re.Match) -> str:
        """Infer which config syntax the matched assignment belongs to."""
        full = line.strip()
        sep = line[match.start():match.end()]
        if ":" in sep and "=" not in sep:
            if full.startswith('"') or full.startswith("'"):
                return "json"
            return "yaml"
        if full.startswith("[") or ("=" in sep and "." in match.group("key")):
            return "ini"
        if "." in match.group("key"):
            return "properties"
        key_upper = match.group("key").upper()
        if key_upper == match.group("key"):
            return "env"
        return "python"

    def _enrich_candidates(
        self,
        candidates: list[Candidate],
        line: str,
        file_path: str,
    ) -> list[Candidate]:
        """
        Add evidence signals to each Candidate in the pool.

        Signal application:
          • Entropy  — skipped for PII candidates (structurally validated);
                       also skipped when should_skip_entropy(file_path) is True.
          • Context  — secret-related keywords on the same line.
                       Applied to ALL candidates including PII.
          • File path — sensitive/low-value path signal.
                        Applied to ALL candidates including PII.
        """
        skip_entropy = should_skip_entropy(file_path)
        path_adj = path_confidence_adjustment(file_path)
        context_keywords = extract_context_keywords(line)

        for candidate in candidates:

            # ── Entropy enrichment ───────────────────────────────────────────
            if candidate.candidate_kind != "pii" and not skip_entropy:
                score = calculate_entropy(candidate.raw_value)
                candidate.metadata["entropy"] = score
                if is_high_entropy(candidate.raw_value):
                    candidate.evidence.append(f"entropy:{score:.2f}")
            else:
                candidate.metadata["entropy"] = calculate_entropy(candidate.raw_value)

            # ── Context keyword enrichment ───────────────────────────────────
            if context_keywords:
                candidate.evidence.append(f"context:{','.join(context_keywords)}")
                candidate.metadata["context_keywords"] = context_keywords

            # ── File path enrichment ─────────────────────────────────────────
            candidate.metadata["path_adj"] = path_adj
            if path_adj > 0:
                candidate.evidence.append("file_path:sensitive")
            elif path_adj < 0:
                candidate.evidence.append("file_path:low-value")

        return candidates

    def _passes_policy_filters(self, candidate: Candidate, file_path: str) -> bool:
        """
        Evaluate candidate against semantic policy refinements.
        Returns True if the candidate should survive, False if it should be suppressed.
        """
        # 1. Restrict P-08 to IDE artifacts
        if candidate.policy_type == "P-08" and not self._is_ide_artifact(file_path):
            return False

        # 2. Suppress local development database URIs
        if candidate.candidate_kind == "regex" and str(candidate.metadata.get("pattern_name", "")).startswith("P-01-DB-URI-"):
            try:
                parsed = urllib.parse.urlparse(candidate.raw_value)
                if parsed.hostname and parsed.hostname.lower() in LOCAL_DB_HOSTS:
                    return False
            except Exception:
                pass

        # 3. Suppress RFC reserved email domains
        if candidate.candidate_kind == "pii" and "Email" in str(candidate.metadata.get("pii_label", "")):
            if candidate.raw_value.lower().endswith(RFC_DOMAINS):
                return False

        # 4. Suppress placeholder credentials for generic assignments/keys
        # (Authoritative keys bypass this to avoid accidental suppression)
        is_generic = (
            candidate.candidate_kind == "assignment" or
            (candidate.candidate_kind == "regex" and str(candidate.metadata.get("pattern_name", "")) in 
             {"P-01-GENERIC-API-KEY", "P-01-GENERIC-SECRET", "P-01-HARDCODED-PASSWORD"})
        )
        if is_generic and PLACEHOLDER_RE.search(candidate.raw_value):
            return False

        return True

    def _evaluate_candidates(
        self,
        candidates: list[Candidate],
        file_path: str,
    ) -> list[Candidate]:
        """
        Apply the required_signals gate, compute confidence, and determine
        final severity.

        required_signals gate:
            Drop any candidate that does not have all of its required signal
            prefixes present in its evidence list.

        Confidence:
            Always computed from evidence signals — independent of severity.

        Severity:
            confidence_locked=True  → base_severity unchanged (pattern-defined)
            confidence_locked=False → confidence_to_severity(confidence)
        """
        surviving: list[Candidate] = []

        for candidate in candidates:
            # ── Required signals gate ────────────────────────────────────────
            present_prefixes = {e.split(":")[0] for e in candidate.evidence}
            if not candidate.required_signals.issubset(present_prefixes):
                continue

            # ── Policy Refinement Filters ────────────────────────────────────
            if not self._passes_policy_filters(candidate, file_path):
                continue

            # ── Confidence scoring (always, independent of severity lock) ────
            signals = {
                "regex":          any(e.startswith("regex:")    for e in candidate.evidence),
                "entropy":        any(e.startswith("entropy:")  for e in candidate.evidence),
                "context":        any(e.startswith("context:")  for e in candidate.evidence),
                "sensitive_file": "file_path:sensitive"         in candidate.evidence,
            }
            raw_conf = calculate_confidence(signals)
            path_adj = candidate.metadata.get("path_adj", 0.0)
            candidate.confidence = max(0.0, min(1.0, raw_conf + path_adj))

            # ── Severity determination ───────────────────────────────────────
            if not candidate.confidence_locked:
                candidate.base_severity = confidence_to_severity(candidate.confidence)

            surviving.append(candidate)

        return surviving

    def _emit_finding(self, candidate: Candidate) -> dict:
        """
        Convert a fully-evaluated Candidate into a finding dict.

        This is the ONLY function in the codebase allowed to construct a
        finding dict.
        """
        description = candidate.metadata.get("description", "")

        if candidate.candidate_kind == "assignment":
            key = candidate.metadata.get("key_name", "?")
            syntax = candidate.metadata.get("syntax", "")
            entropy_score = candidate.metadata.get("entropy", 0.0)
            ctx = candidate.metadata.get("context_keywords", [])
            description = (
                f"Secret-like assignment detected ({syntax} syntax): "
                f"key '{key}' has a high-entropy value "
                f"(entropy: {entropy_score:.2f}, confidence: {candidate.confidence:.2f})."
                + (f" Secret context found: {', '.join(ctx)}." if ctx else
                   " No additional context keywords found.")
            )

        return {
            "file": candidate.file,
            "line": candidate.line,
            "type": candidate.policy_type,
            "severity": candidate.base_severity,
            "match_redacted": candidate.redacted_value,
            "description": description,
            "source": "payload",
            "entropy": round(candidate.metadata.get("entropy", 0.0), 2),
            "confidence": round(candidate.confidence, 2),
            "evidence": candidate.evidence,
        }

    # ── Findings Factory ──────────────────────────────────────────────────────

    def _make_binary_finding(self, file_path: str) -> dict:
        """P-06: Binary build artifact staged for commit."""
        ext = Path(file_path).suffix
        return {
            "file": file_path,
            "line": 0,
            "type": "P-06",
            "severity": "HIGH",
            "match_redacted": f"{ext}****",
            "description": (
                f"Binary build artifact ({ext}) staged for commit. "
                "Binary files may contain embedded secrets that are invisible to text scanners. "
                "Add this extension to .gitignore."
            ),
            "source": "payload",
            "entropy": 0.0,
            "confidence": 1.0,
            "evidence": build_evidence(binary_detected=True),
        }

    # ── File Classifier Helpers ───────────────────────────────────────────────

    def _is_ide_artifact(self, path_str: str) -> bool:
        return any(pattern in path_str for pattern in IDE_ARTIFACT_PATHS)

    def _is_vcr_cassette(self, path_str: str) -> bool:
        return any(pattern in path_str for pattern in VCR_CASSETTE_PATTERNS) and (
            "cassette" in path_str or "vcr" in path_str.lower()
        )

    def _is_fixture_file(self, path_str: str) -> bool:
        return any(pattern in path_str for pattern in FIXTURE_PATTERNS)

    # ── File Reader ───────────────────────────────────────────────────────────

    @staticmethod
    def _is_binary_file(file_path: str) -> bool:
        """
        Determine whether a file is binary by inspecting its content.

        Reads the first 4KB and applies two checks:
          1. If NUL bytes (\\x00) are present → binary.
          2. Attempt strict UTF-8 decoding of the chunk.
             If UTF-8 fails → binary.
        """
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(_BINARY_CHECK_SIZE)
        except OSError:
            return True

        if not chunk:
            return False

        if b"\x00" in chunk:
            return True

        try:
            chunk.decode("utf-8")
        except UnicodeDecodeError:
            return True

        return False

    def _read_file_lines(self, file_path: str) -> list[str] | None:
        """
        Read file content as a list of lines (UTF-8 only).
        Returns None if the file cannot be read.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.readlines()
        except UnicodeDecodeError:
            print(f"[payload_engine] SKIP (not UTF-8 text): {file_path}", file=sys.stderr)
            return None
        except OSError as e:
            print(f"[payload_engine] SKIP (OS error): {file_path}: {e}", file=sys.stderr)
            return None

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """
        Remove duplicate findings.
        Two findings are duplicates if they share: file + line + type.
        """
        seen: set[str] = set()
        unique: list[dict] = []
        for f in findings:
            key = f"{f['file']}:{f['line']}:{f['type']}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique