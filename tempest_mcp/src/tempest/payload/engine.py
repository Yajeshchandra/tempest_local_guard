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
from pathlib import Path

from tempest.payload.entropy_tool import (
    calculate_entropy,
    is_high_entropy,
    ENTROPY_THRESHOLD,
)
from tempest.payload.regex_tool import scan_line
from tempest.payload.ner_tool import scan_line_for_pii, calculate_pii_density

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

# File extensions we actively scan (everything else is silently ignored)
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".cs", ".php",   # source
    ".env", ".env.local", ".env.test", ".env.example",            # env files
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".config", # config
    ".xml", ".properties",                                         # more config
    ".csv", ".tsv",                                                # tabular fixtures (P-04 PII)
    ".ipynb",                                                      # Jupyter
    ".txt", ".md",                                                 # text
    ".sh", ".bash", ".zsh",                                        # shell
    ".tf", ".tfvars",                                              # Terraform
    ".sql",                                                        # DB scripts
    "",                                                            # files like .env (no extension)
})

# Config-file types where a production-resource REFERENCE (not a credential) is
# itself a leak when the file is non-prod: a staging manifest / dev compose that
# points DATABASE_URL / DB_HOST / bucket / broker at a prod resource. Complements
# the credential regexes (which need embedded user:pass) — this catches the bare
# prod-identifier references graphify never sees (config files aren't in the graph).
CONFIG_FILE_EXTENSIONS: frozenset[str] = frozenset({
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".config", ".properties",
    ".tf", ".tfvars",
})
# Resource-reference keys — a prod identifier in one of these values points at a
# real backing resource, not incidental prose. Unanchored substring match (not
# \b-bounded): config keys are commonly SNAKE_CASE (REDIS_URL, S3_BUCKET) where
# `_` is a \w character and blocks a \b boundary before the keyword. Safe
# without boundaries because a P-09 finding also requires a prod-identifier
# regex match on the same line — the AND keeps this precise.
_CONFIG_RESOURCE_KEY_RE = re.compile(
    r'(?i)(url|uri|host|hostname|server|endpoint|bucket|broker|dsn|database|'
    r'db|connection|conn|image|addr|address|backend|datasource)'
)

# Minimum token length for entropy checking (short tokens = too many false positives)
MIN_ENTROPY_TOKEN_LENGTH = 10

# Token splitter: split lines on whitespace, quotes, equals, commas, colons
TOKEN_SPLITTER = re.compile(r'[\s="\',:{}\[\]()]+')

# High PII-density threshold: if >20% of lines have PII, escalate to HIGH
PII_DENSITY_ESCALATION_THRESHOLD = 0.20

# ── Phase 1 precision: false-positive suppression ────────────────────────────

# Dependency lockfiles scanned as text (the .lock ones already hit
# BINARY_EXTENSIONS). Their body is integrity hashes, never real secrets —
# skip entirely so the entropy scanner doesn't emit hundreds of P-01 FPs
# (package-lock.json alone produced 150+ per repo). Basenames, lowercase.
DEPENDENCY_LOCKFILES: frozenset[str] = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
    "yarn.lock", "go.sum",
})

# Build-tool wrapper jars: the one sanctioned committed-binary exception
# (Gradle/Maven docs recommend committing them). Don't flag as P-06.
WRAPPER_JARS: frozenset[str] = frozenset({
    "gradle-wrapper.jar", "maven-wrapper.jar",
})

# Text lockfiles wrongly swept up by the `.lock` BINARY_EXTENSIONS rule — they
# are reviewable text, not opaque binaries. Reported at LOW, not HIGH. Lowercase.
TEXT_LOCKFILE_NAMES: frozenset[str] = frozenset({
    "cargo.lock", "poetry.lock", "uv.lock", "gemfile.lock",
    "composer.lock", "pipfile.lock", "mix.lock",
})

# High-entropy tokens that are well-known non-secret identifiers — LLM tool-call
# / message / completion IDs recorded in cassettes and logs. Real API keys have
# their own regex patterns (sk-, phc_, ghp_, AKIA, ...) and are unaffected.
NON_SECRET_TOKEN_PREFIXES: tuple[str, ...] = (
    "call_", "toolu_", "chatcmpl-", "msg_", "run_", "asst_", "fc_",
)

# Generated-code filename signatures — codegen output, never hand-written
# secrets (protobuf, EF Core migrations, gRPC stubs). Matched on normalised path.
GENERATED_FILENAME_SUFFIXES: tuple[str, ...] = (
    "_pb2.py", "_pb2_grpc.py", ".pb.go", ".pb.cc", ".pb.h",
    ".designer.cs", ".g.cs", ".generated.cs", "_pb.js", "_pb.ts", "_grpc.pb.go",
)

# Generated-code header markers — scanned in the first few lines of a file.
GENERATED_HEADER_MARKERS: tuple[str, ...] = (
    "auto-generated", "autogenerated", "do not edit", "do not modify",
    "generated by the protocol buffer compiler", "@generated",
    "code generated by", "this file was automatically generated",
    "<auto-generated",
)

# Declaration lines whose high-entropy tokens are namespaces/qualified names,
# not secrets (Java `import static a.b.C`, C# `using A.B`, Go `package x`).
_DECLARATION_LINE_RE = re.compile(
    r'^\s*(import\b|from\b|using\b|package\b|namespace\b|#include\b|require\s*\()'
)
# Leading comment markers — entropy in a comment is almost never a real secret.
_COMMENT_PREFIXES: tuple[str, ...] = ("#", "//", "--", "*", "/*")


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

    def __init__(self, prod_identifiers: list[str] | None = None) -> None:
        """prod_identifiers: boundary.prod_identifier_patterns from the tempest
        config, used by the config-file prod-reference check (P-09). Optional so
        existing callers — `PayloadEngine()` — keep working unchanged."""
        self._prod_id_res = [re.compile(p, re.IGNORECASE) for p in (prod_identifiers or [])]

    # ── Public Interface (called by orchestrator.py) ──────────────────────────

    def scan(self, file_paths: list[str]) -> list[dict]:
        """
        Main entry point. Called by payload/scan.py with the repo's file list.

        Args:
            file_paths: List of absolute or relative paths to staged files.

        Returns:
            Deduplicated list of finding dicts, each with keys:
                file, line, type, severity, match_redacted,
                description, source, entropy
        """
        all_findings: list[dict] = []

        for path in file_paths:
            try:
                findings = self._route_file(path)
                # Config files aren't in the code graph, so structural Rule (a)
                # never sees them — catch prod-resource references here (P-09).
                if self._is_config_file(path) and Path(path).exists():
                    findings = findings + self._scan_config_prod_reference(path)
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
        path_str = str(file_path).replace("\\", "/")   # normalise Windows paths

        # ── Guard 1: File must exist ─────────────────────────────────────────
        if not path.exists():
            print(f"[payload_engine] SKIP (not found): {file_path}", file=sys.stderr)
            return []

        # ── Guard 2: Binary → P-06, no content read ──────────────────────────
        if ext in BINARY_EXTENSIONS:
            if self._is_wrapper_jar(path_str):
                return []   # gradle/maven wrapper — sanctioned committed binary
            return [self._make_binary_finding(file_path)]

        # ── Guard 3: Unsupported extension → skip silently ───────────────────
        if ext not in SUPPORTED_EXTENSIONS:
            return []

        # ── Guard 4: Dependency lockfiles / generated code → skip ────────────
        # Their content is integrity hashes or codegen output, never real
        # secrets; scanning them is the dominant false-positive source.
        # (Checked before routing so e.g. pnpm-lock.yaml can't route to VCR.)
        if self._is_dependency_lockfile(path_str) or self._is_generated_file(file_path, path_str):
            return []

        # ── Route by file type ────────────────────────────────────────────────
        if ext == ".ipynb":
            # P-05: Jupyter notebook
            return self._scan_notebook(file_path)

        if self._is_ide_artifact(path_str):
            # P-08: IDE configuration file
            return self._scan_text_file(file_path, scan_pii=False, extra_type_tag="P-08")

        if self._is_vcr_cassette(path_str):
            # P-07: VCR cassette file — scan for auth headers AND PII
            return self._scan_text_file(file_path, scan_pii=True, vcr_mode=True)

        if self._is_fixture_file(path_str):
            # P-04: Test fixture / seed data — PII focused
            return self._scan_text_file(file_path, scan_pii=True)

        if ext in {".env", ".env.local", ".env.test", ".env.example"}:
            # P-02: .env file — scan for secrets
            return self._scan_text_file(file_path, scan_pii=False)

        # Handle .env files without dot-prefix (e.g. file named ".env" has ext="" on some systems)
        basename = path.name.lower()
        if basename.startswith(".env"):
            return self._scan_text_file(file_path, scan_pii=False)

        # Default: source/config file — P-01 regex + entropy
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
        Read a text file line by line and apply:
          1. Regex pattern matching (regex_tool.scan_line)
          2. Shannon entropy scoring on each token
          3. PII detection (ner_tool.scan_line_for_pii) — only when scan_pii=True

        Args:
            file_path     : Path to the file
            scan_pii      : Whether to run PII detection (P-04 / P-07)
            vcr_mode      : Whether this is a VCR cassette (slightly different messaging)
            extra_type_tag: Override finding type (used for P-08 IDE files)
        """
        lines = self._read_file_lines(file_path)
        if lines is None:
            return []    # unreadable file, already logged

        findings: list[dict] = []

        for line_number, line in enumerate(lines, start=1):
            stripped = line.rstrip("\n")

            # Step 1: Regex scan
            regex_findings = scan_line(stripped, line_number, file_path)
            if extra_type_tag:
                for f in regex_findings:
                    f["type"] = extra_type_tag
                    if vcr_mode:
                        f["description"] = f["description"].replace(
                            "source file", "VCR cassette"
                        )
            findings.extend(regex_findings)

            # Step 2: Entropy scan — check every token on the line
            # Skip if we already found something on this line via regex
            line_already_flagged = any(
                f["line"] == line_number for f in regex_findings
            )
            if not line_already_flagged:
                entropy_findings = self._entropy_scan_line(stripped, line_number, file_path)
                findings.extend(entropy_findings)

            # Step 3: PII scan (fixtures, cassettes)
            if scan_pii:
                pii_findings = scan_line_for_pii(stripped, line_number, file_path)
                findings.extend(pii_findings)

        # PII density escalation: if fixture file has lots of PII, escalate all MEDIUM → HIGH
        if scan_pii and lines:
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

        Notebook structure:
            notebook["cells"] → list of cells
            cell["source"]    → list of code lines (the written code)
            cell["outputs"]   → list of output blocks
              output["text"]                      → printed output lines
              output["data"]["text/plain"]         → rich output
              output["data"]["application/json"]   → JSON output
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
        virtual_line = 1   # virtual line counter across all cells

        cells = notebook.get("cells", [])
        for cell_index, cell in enumerate(cells):
            cell_type = cell.get("cell_type", "unknown")

            # Extract source lines (the code the developer wrote)
            source_lines = cell.get("source", [])
            if isinstance(source_lines, str):
                source_lines = source_lines.splitlines()

            # Extract output lines (what the cell printed / returned)
            output_lines: list[str] = []
            for output in cell.get("outputs", []):
                # Standard text output (print statements)
                text = output.get("text", [])
                if isinstance(text, str):
                    text = text.splitlines()
                output_lines.extend(text)

                # Rich display output
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

                # Regex scan
                regex_findings = scan_line(stripped, virtual_line, file_path)
                # Tag all findings with P-05 since they came from a notebook
                for f in regex_findings:
                    f["description"] = f"[Cell {cell_index+1}/{cell_type}] " + f["description"]
                findings.extend(regex_findings)

                # Entropy scan
                line_already_flagged = any(f["line"] == virtual_line for f in regex_findings)
                if not line_already_flagged:
                    entropy_findings = self._entropy_scan_line(stripped, virtual_line, file_path)
                    for f in entropy_findings:
                        f["type"] = "P-05"
                        f["description"] = f"[Cell {cell_index+1}/{cell_type}] " + f["description"]
                    findings.extend(entropy_findings)

                # PII scan (notebooks can also contain PII in outputs)
                pii_findings = scan_line_for_pii(stripped, virtual_line, file_path)
                for f in pii_findings:
                    f["type"] = "P-05"
                    f["description"] = f"[Cell {cell_index+1}/{cell_type}] " + f["description"]
                findings.extend(pii_findings)

                virtual_line += 1

        return findings

    # ── Entropy Scanner ───────────────────────────────────────────────────────

    def _entropy_scan_line(self, line: str, line_number: int, file_path: str) -> list[dict]:
        """
        Split a line into tokens and flag any token that:
          - Is at least MIN_ENTROPY_TOKEN_LENGTH characters long
          - Has Shannon entropy above ENTROPY_THRESHOLD
          - Looks like a value (not a keyword or variable name)

        One finding per line maximum (first suspicious token wins).
        """
        # Declaration lines (import/using/namespace/package) and comments carry
        # high-entropy qualified names, not secrets — the entropy heuristic's
        # dominant false-positive source. Real secrets in these lines are still
        # caught by the regex path (which runs regardless).
        if _DECLARATION_LINE_RE.match(line):
            return []
        if line.lstrip().startswith(_COMMENT_PREFIXES):
            return []

        tokens = TOKEN_SPLITTER.split(line)
        for token in tokens:
            # Skip short tokens and common keywords
            if len(token) < MIN_ENTROPY_TOKEN_LENGTH:
                continue
            if not self._looks_like_value(token):
                continue

            entropy_score = calculate_entropy(token)
            if entropy_score > ENTROPY_THRESHOLD:
                return [{
                    "file": file_path,
                    "line": line_number,
                    "type": "P-01",
                    "severity": "HIGH",
                    "match_redacted": token[:4] + "****",
                    "description": (
                        f"High-entropy string detected (entropy score: {entropy_score:.2f}, "
                        f"threshold: {ENTROPY_THRESHOLD}). Likely a hardcoded secret."
                    ),
                    "source": "payload",
                    "entropy": round(entropy_score, 2),
                }]
        return []

    # ── Helper: Does This Token Look Like a Value? ────────────────────────────

    # Common Python/JS/etc keywords and short names that are high-entropy
    # by coincidence but are NOT secrets. Filter these out.
    _COMMON_KEYWORDS: frozenset[str] = frozenset({
        "return", "import", "except", "lambda", "isinstance", "continue",
        "True", "False", "None", "class", "def", "elif", "else", "pass",
        "yield", "async", "await", "raise", "assert", "global", "nonlocal",
        "function", "const", "let", "var", "export", "default", "require",
    })

    def _looks_like_value(self, token: str) -> bool:
        """
        Return True if the token is likely to be a value (not a keyword).
        Filters out:
          - Pure Python/JS keywords
          - Tokens that are all lowercase (likely variable names)
          - Tokens that are valid English words (no digits, no mixed case)
          - File paths (contain / or \\)
        """
        if token in self._COMMON_KEYWORDS:
            return False
        if token.startswith(NON_SECRET_TOKEN_PREFIXES):
            return False  # LLM tool-call / message IDs, not credentials
        if "/" in token or "\\" in token:
            return False  # file paths
        if "${" in token or "{{" in token or token.startswith("$"):
            return False  # env-var / template interpolation, not a literal value
        if "<" in token or ">" in token:
            return False  # generic type params / markup (Foo<Bar>) — code, not a secret
        # Dotted qualified name (namespace, member access, fully-qualified type):
        # every dot-separated segment is a bare identifier -> code, not a secret.
        # (e.g. Npgsql.EntityFrameworkCore, Assert.ThrowsExactly). JWT/connection
        # strings have non-identifier segments and are caught by the regex path.
        if "." in token:
            segments = [s for s in token.split(".") if s]
            if segments and all(s.isidentifier() for s in segments):
                return False
        if token.isalpha() and token.islower():
            return False  # plain lowercase words
        # Must have at least one digit or mixed case to look like a secret value
        has_digit = any(c.isdigit() for c in token)
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        if not (has_digit or (has_upper and has_lower)):
            return False
        return True

    # ── Findings Factory ──────────────────────────────────────────────────────

    def _make_binary_finding(self, file_path: str) -> dict:
        """P-06: Binary build artifact staged for commit."""
        ext = Path(file_path).suffix
        # Text lockfiles (Cargo.lock, poetry.lock, ...) get swept up by the
        # `.lock` binary rule but are reviewable text, not opaque binaries.
        # Report at LOW as an FYI, not a HIGH "may hide secrets" alarm.
        if Path(file_path).name.lower() in TEXT_LOCKFILE_NAMES:
            return {
                "file": file_path,
                "line": 0,
                "type": "P-06",
                "severity": "LOW",
                "match_redacted": f"{ext}****",
                "description": (
                    f"Committed dependency lockfile ({ext}). Text, not a binary — "
                    "reviewable and normally safe to commit; flagged only for awareness."
                ),
                "source": "payload",
                "entropy": 0.0,
            }
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
        }

    # ── File Classifier Helpers ───────────────────────────────────────────────

    def _is_wrapper_jar(self, path_str: str) -> bool:
        """gradle-wrapper.jar / maven-wrapper.jar — sanctioned committed binary."""
        return path_str.rsplit("/", 1)[-1].lower() in WRAPPER_JARS

    def _is_dependency_lockfile(self, path_str: str) -> bool:
        """package-lock.json / yarn.lock / ... — integrity hashes, never secrets."""
        return path_str.rsplit("/", 1)[-1].lower() in DEPENDENCY_LOCKFILES

    def _is_generated_file(self, file_path: str, path_str: str) -> bool:
        """Codegen output (protobuf, EF migrations, gRPC stubs): by filename
        signature, else by a generated-header marker in the first few lines."""
        low = path_str.lower()
        if any(low.endswith(sfx) for sfx in GENERATED_FILENAME_SUFFIXES):
            return True
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                head = "".join(f.readline() for _ in range(5)).lower()
        except OSError:
            return False
        return any(marker in head for marker in GENERATED_HEADER_MARKERS)

    def _is_ide_artifact(self, path_str: str) -> bool:
        """Return True if the path looks like an IDE configuration artifact."""
        return any(pattern in path_str for pattern in IDE_ARTIFACT_PATHS)

    def _is_vcr_cassette(self, path_str: str) -> bool:
        """Return True if the path looks like a VCR cassette recording."""
        return any(pattern in path_str for pattern in VCR_CASSETTE_PATTERNS) and (
            "cassette" in path_str or "vcr" in path_str.lower()
        )

    def _is_fixture_file(self, path_str: str) -> bool:
        """Return True if the path looks like a test fixture or seed data file."""
        return any(pattern in path_str for pattern in FIXTURE_PATTERNS)

    def _is_config_file(self, file_path: str) -> bool:
        """Config/IaC files whose values point at backing resources (yaml/toml/
        ini/tf, Dockerfile, .env)."""
        p = Path(file_path)
        name = p.name.lower()
        return (
            p.suffix.lower() in CONFIG_FILE_EXTENSIONS
            or name.startswith("dockerfile")
            or name.startswith(".env")
        )

    def _scan_config_prod_reference(self, file_path: str) -> list[dict]:
        """P-09: a non-prod config file that points a resource key (DATABASE_URL,
        DB_HOST, bucket, broker, image, ...) at a PROD identifier
        (prod-db.internal, prod-user-uploads, redis://prod-redis, ...). Env-blind
        here; scan.py drops PROD-file hits (a prod config referencing prod is
        expected, not a leak)."""
        if not self._prod_id_res:
            return []
        lines = self._read_file_lines(file_path)
        if lines is None:
            return []
        findings: list[dict] = []
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith(_COMMENT_PREFIXES):
                continue
            if not _CONFIG_RESOURCE_KEY_RE.search(line):
                continue
            for rx in self._prod_id_res:
                m = rx.search(line)
                if m:
                    findings.append({
                        "file": file_path,
                        "line": i,
                        "type": "P-09",
                        "severity": "HIGH",
                        "match_redacted": m.group(0)[:32],
                        "description": (
                            "Non-prod config references a production resource "
                            f"('{m.group(0)[:40]}')"
                        ),
                        "source": "payload",
                        "subtype": "config-prod-ref",
                        "entropy": 0.0,
                    })
                    break
        return findings

    # ── File Reader ───────────────────────────────────────────────────────────

    def _read_file_lines(self, file_path: str) -> list[str] | None:
        """
        Read file content as a list of lines.
        Tries UTF-8 first, then falls back to latin-1 (which never fails).
        Returns None if the file cannot be read at all.
        """
        for encoding in ("utf-8", "latin-1"):
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    return f.readlines()
            except UnicodeDecodeError:
                continue
            except OSError as e:
                print(f"[payload_engine] SKIP (OS error): {file_path}: {e}", file=sys.stderr)
                return None
        print(f"[payload_engine] SKIP (encoding error): {file_path}", file=sys.stderr)
        return None

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """
        Remove duplicate findings.
        Two findings are duplicates if they share: file + line + type.
        Keeps the first occurrence (regex findings before entropy findings).
        """
        seen: set[str] = set()
        unique: list[dict] = []
        for f in findings:
            key = f"{f['file']}:{f['line']}:{f['type']}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique