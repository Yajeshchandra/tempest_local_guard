"""PROD/NON-PROD + Production Boundary Node (PBN) classification.

A node is PROD-tagged via the ordered heuristic chain in env_map.py, plus a
content-based regex pass (connection-string/identifier patterns near the
node's source_location) that can *upgrade* a node to PROD even if its path
alone didn't indicate it. Manual overrides (boundary_overrides.json) always
win over every heuristic.

A node is a Production Boundary Node (PBN) only if it is BOTH:
  (a) PROD-tagged, AND
  (b) structurally a resource boundary (database/storage/messaging/network),
      per the config-driven `pbn_patterns` table matched against the node's
      label/norm_label.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from tempest.paths import RepoPaths
from tempest.rie.env_map import ENV_DEV, ENV_PROD, ENV_TEST, ENV_UNKNOWN, classify_env_for_path

PBN_TYPE_NONE = None


@dataclass
class NodeClassification:
    node_id: str
    env_tag: str
    is_prod: bool
    is_pbn: bool
    pbn_type: str | None
    reasons: list[str]
    overridden: bool = False

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "env_tag": self.env_tag,
            "is_prod": self.is_prod,
            "is_pbn": self.is_pbn,
            "pbn_type": self.pbn_type,
            "reasons": self.reasons,
            "overridden": self.overridden,
        }


def load_overrides(repo_root: str | Path) -> dict[str, dict]:
    """Load manual boundary overrides for a repo, keyed by node_id.

    Each entry may set `env_tag` (e.g. "PROD"/"NON_PROD") and/or `is_pbn`
    (bool) and/or `pbn_type`. Missing keys fall through to heuristic values.
    """
    paths = RepoPaths(repo_root)
    if not paths.overrides_file.exists():
        return {}
    with open(paths.overrides_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("overrides", data) if isinstance(data, dict) else {}


def save_override(
    repo_root: str | Path,
    node_id: str,
    env_tag: str | None = None,
    is_pbn: bool | None = None,
    pbn_type: str | None = None,
) -> None:
    paths = RepoPaths(repo_root)
    paths.ensure_tempest_dir()
    overrides = load_overrides(repo_root)
    entry = overrides.get(node_id, {})
    if env_tag is not None:
        entry["env_tag"] = env_tag
    if is_pbn is not None:
        entry["is_pbn"] = is_pbn
    if pbn_type is not None:
        entry["pbn_type"] = pbn_type
    overrides[node_id] = entry
    with open(paths.overrides_file, "w", encoding="utf-8") as f:
        json.dump({"overrides": overrides}, f, indent=2)


def _relativize(source_file: str | None, repo_root: Path) -> str | None:
    """Convert an absolute source_file path to repo-relative, so folder/file
    heuristics only see path segments inside the scanned repo — not
    ancestor directory names from wherever the repo happens to sit on disk
    (e.g. a repo checked out under a path containing '.../tests/...' must
    not have every node misclassified as TEST because of that)."""
    if not source_file:
        return source_file
    try:
        p = Path(source_file)
        if p.is_absolute():
            return str(p.resolve().relative_to(repo_root.resolve()))
        return source_file
    except ValueError:
        # Not under repo_root (shouldn't normally happen) — fall back to
        # the original path rather than failing classification.
        return source_file


def _compile_prod_identifier_patterns(config: dict[str, Any]) -> list[re.Pattern]:
    patterns = config.get("boundary", {}).get("prod_identifier_patterns", []) or []
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue
    return compiled


def _compile_scanner_patterns(config: dict[str, Any]) -> dict[str, re.Pattern]:
    patterns = config.get("scanner_patterns", {})
    compiled = {}
    for name, p in patterns.items():
        try:
            compiled[name] = re.compile(p, re.IGNORECASE)
        except re.error:
            continue
    return compiled

_SOURCE_TEXT_CACHE: dict[str, str] = {}


def _read_source_near(source_file: str | None, repo_root: Path) -> str:
    """Best-effort read of the file's content for content-based regex
    checks. Cached per-process since the same file backs many nodes."""
    if not source_file:
        return ""
    key = source_file
    if key in _SOURCE_TEXT_CACHE:
        return _SOURCE_TEXT_CACHE[key]

    candidate = Path(source_file)
    if not candidate.is_absolute():
        candidate = repo_root / source_file

    text = ""
    try:
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    _SOURCE_TEXT_CACHE[key] = text
    return text


_STRING_LITERAL_RE = re.compile(r"""(['"])((?:(?!\1).)*)\1""")


def _extract_string_literals(text: str) -> list[str]:
    """Pull out quoted string-literal contents, ignoring surrounding prose.
    This keeps the prod-identifier regex from matching comments/docstrings
    that merely *mention* a prod hostname (e.g. explaining what NOT to do),
    which would otherwise misclassify the whole non-prod file as PROD."""
    return [m.group(2) for m in _STRING_LITERAL_RE.finditer(text)]


def _content_matches_prod_identifier(
    source_file: str | None, repo_root: Path, patterns: list[re.Pattern]
) -> bool:
    if not patterns or not source_file:
        return False
    text = _read_source_near(source_file, repo_root)
    if not text:
        return False
    literals = _extract_string_literals(text)
    return any(p.search(lit) for lit in literals for p in patterns)


def _content_matches_nonprod_import(
    source_file: str | None, repo_root: Path, config: dict[str, Any]
) -> bool:
    """True if the file imports a test/mock/dev framework (pytest, faker, moto,
    …). The strongest generalized signal that code is non-prod regardless of
    its name or folder. Checked against full file text (imports aren't string
    literals)."""
    markers = config.get("nonprod_import_markers", [])
    if not markers or not source_file:
        return False
    text = _read_source_near(source_file, repo_root)
    if not text:
        return False
    low = text.lower()
    return any(m.lower() in low for m in markers)


def _annotate_scanner_findings(
    node_data: dict, source_file: str | None, repo_root: Path, patterns: dict[str, re.Pattern]
) -> None:
    if not patterns or not source_file:
        return
    text = _read_source_near(source_file, repo_root)
    if not text:
        return
    literals = _extract_string_literals(text)
    findings = node_data.setdefault("scanner_findings", {})
    for name, p in patterns.items():
        for lit in literals:
            if p.search(lit):
                findings[name] = True
                break


def _matches_any(label: str, keywords: list[str]) -> bool:
    label_lower = (label or "").lower()
    return any(kw.lower() in label_lower for kw in keywords)


def _classify_boundary(
    node_data: dict, config: dict[str, Any], is_prod: bool
) -> tuple[bool, str | None]:
    """Is this node a resource boundary (database/storage/messaging/network),
    and of what type?

    Two confidence tiers:
      • High-confidence signals — connection-string scanner findings and precise
        resource-client patterns — fire REGARDLESS of env tag, because on real
        repos the resource sits in no prod/ folder; it's just "the database".
      • Broad label-substring `pbn_patterns` stay PROD-gated (noisy on their own).
    """
    # 0. Synthetic multi-language resource-client node (from augment_graph_
    #    multilang) carries its type explicitly — trust it (we created it from a
    #    verified client call/inheritance regex; no graphify label to match).
    if node_data.get("_pbn_type"):
        return True, node_data["_pbn_type"]

    # 1. Connection-string / cloud-resource scanner findings — high confidence,
    #    env-agnostic.
    findings = node_data.get("scanner_findings", {})
    if findings:
        mapping = {
            "database_url": "database",
            "aws_s3_uri": "storage",
            "azure_storage_url": "storage",
            "gcp_gcs_uri": "storage",
        }
        for finding_name in findings:
            if finding_name in mapping:
                return True, mapping[finding_name]
        # General cloud identifiers imply a network boundary if not specifically storage/db
        if any(k in findings for k in ("aws_arn", "azure_resource_id", "gcp_service_account", "azure_key_vault")):
            return True, "network"

    label = (node_data.get("norm_label") or node_data.get("label") or "").lower()

    # 2. Precise resource-client patterns — env-agnostic (e.g. create_engine,
    #    boto3.client, MongoClient). Unambiguously an external resource.
    for boundary_type, patterns in config.get("resource_client_patterns", {}).items():
        for pat in patterns:
            if pat.lower() in label:
                return True, boundary_type

    # 3. Broad label-substring heuristics — PROD-gated (would over-match on a
    #    real repo where many nodes are named *db*/*session*/*connection*).
    if is_prod:
        for pbn_type, keywords in config.get("pbn_patterns", {}).items():
            if _matches_any(label, keywords):
                return True, pbn_type
    return False, None


def classify_node(
    node_id: str,
    node_data: dict,
    config: dict[str, Any],
    repo_root: Path,
    overrides: dict[str, dict],
    prod_identifier_patterns: list[re.Pattern] | None = None,
    scanner_patterns: dict[str, re.Pattern] | None = None,
) -> NodeClassification:
    reasons: list[str] = []

    source_file = node_data.get("source_file")
    relative_source_file = _relativize(source_file, repo_root)
    env_tag = classify_env_for_path(relative_source_file, config)
    if env_tag != ENV_UNKNOWN:
        reasons.append(f"path heuristic -> {env_tag} ({source_file})")

    if prod_identifier_patterns is None:
        prod_identifier_patterns = _compile_prod_identifier_patterns(config)
    if scanner_patterns is None:
        scanner_patterns = _compile_scanner_patterns(config)

    # Annotate graph node with discovery scanner findings
    _annotate_scanner_findings(node_data, source_file, repo_root, scanner_patterns)

    # Framework-import signal: the strongest generalized non-prod marker. A
    # file importing pytest/faker/moto/... is test/dev code wherever it lives —
    # upgrade an otherwise-unclassified node to TEST so its reach into a prod
    # resource is caught even with no test/ folder or test_* filename. Checked
    # before the prod-identifier content check so a test file that merely holds
    # a prod hostname string stays TEST (the leak), not PROD.
    if env_tag == ENV_UNKNOWN and _content_matches_nonprod_import(source_file, repo_root, config):
        env_tag = ENV_TEST
        reasons.append("content matched nonprod_import_markers")

    # Content-based regex is the lowest-priority signal in the heuristic
    # chain: it only fires when the path itself gave no signal at all
    # (env_tag is still the ENV_UNKNOWN default). It must never override an
    # explicit folder/file tag (e.g. a file under tests/ or dev/ that merely
    # *mentions* a prod hostname in a comment/docstring/log message should
    # stay TEST/DEV — that's exactly the non-prod-code-referencing-prod
    # scenario Rule (a) is meant to flag as a finding, not a boundary flip).
    if env_tag == ENV_UNKNOWN and _content_matches_prod_identifier(
        source_file, repo_root, prod_identifier_patterns
    ):
        env_tag = ENV_PROD
        reasons.append("content matched prod_identifier_patterns")

    is_prod = env_tag == ENV_PROD

    # A node is a Production Boundary Node if it is structurally a resource
    # boundary AND not an explicit local/test double. High-confidence resource
    # clients (connection strings, precise SDK/driver patterns) are detected
    # regardless of env tag; a DEV LocalDatabase or a TEST fake is a resource
    # boundary but not a *production* one, so it's excluded here.
    #
    # Exception, scoped to `_synthetic` nodes only (inserted by the AST
    # augmentation pass for third-party client calls graphify doesn't emit,
    # e.g. `psycopg2.connect(PROD_DSN)` inside a scripts/ debug helper): a
    # synthetic node's own call site, if the file also holds a literal prod
    # identifier, IS the real production resource, not a stub/fake — promote
    # it to PBN and to is_prod. This must stay scoped to synthetic nodes: a
    # blanket file-wide check would also promote every ordinary node sharing
    # a file with a prod-looking string (e.g. Rule a's own planted-secret
    # fixtures), which would wrongly hide them from Rule a's is_prod-gated scan.
    is_boundary, boundary_type = _classify_boundary(node_data, config, is_prod)
    has_companion_prod_identifier = False
    if node_data.get("_synthetic") and is_boundary and env_tag in (ENV_DEV, ENV_TEST):
        has_companion_prod_identifier = _content_matches_prod_identifier(
            source_file, repo_root, prod_identifier_patterns
        )
        if has_companion_prod_identifier:
            is_prod = True
            reasons.append(
                "prod_identifier_patterns matched in same file -> promoted despite DEV/TEST env"
            )
    is_pbn = is_boundary and (env_tag not in (ENV_DEV, ENV_TEST) or has_companion_prod_identifier)
    pbn_type = boundary_type if is_pbn else None
    if is_pbn:
        reasons.append(f"structural PBN match -> {pbn_type}")

    overridden = False
    override = overrides.get(node_id)
    if override:
        overridden = True
        if "env_tag" in override:
            env_tag = override["env_tag"]
            is_prod = env_tag == ENV_PROD
            reasons.append(f"manual override -> env_tag={env_tag}")
        if "is_pbn" in override:
            is_pbn = override["is_pbn"]
            reasons.append(f"manual override -> is_pbn={is_pbn}")
        if "pbn_type" in override:
            pbn_type = override["pbn_type"]

    return NodeClassification(
        node_id=node_id,
        env_tag=env_tag,
        is_prod=is_prod,
        is_pbn=is_pbn,
        pbn_type=pbn_type,
        reasons=reasons,
        overridden=overridden,
    )


def classify_graph(
    graph: nx.DiGraph, config: dict[str, Any], repo_root: str | Path
) -> dict[str, NodeClassification]:
    """Classify every node in the graph. Returns a dict of node_id -> NodeClassification."""
    repo_root = Path(repo_root)
    # The source-text cache is keyed by path and lives for the process. The MCP
    # server is long-lived across many repos and re-syncs, so clear it per run
    # to avoid serving stale file content after an edit + re-sync.
    _SOURCE_TEXT_CACHE.clear()
    overrides = load_overrides(repo_root)
    prod_identifier_patterns = _compile_prod_identifier_patterns(config)
    scanner_patterns = _compile_scanner_patterns(config)

    classifications: dict[str, NodeClassification] = {}
    for node_id, node_data in graph.nodes(data=True):
        classifications[node_id] = classify_node(
            node_id,
            node_data,
            config,
            repo_root,
            overrides,
            prod_identifier_patterns=prod_identifier_patterns,
            scanner_patterns=scanner_patterns,
        )
    return classifications


def get_pbn_ids(classifications: dict[str, NodeClassification]) -> list[str]:
    return [nid for nid, c in classifications.items() if c.is_pbn]
