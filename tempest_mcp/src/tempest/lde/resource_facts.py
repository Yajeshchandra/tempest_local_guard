"""Resource-identity facts + the cross-file/cross-language join (Phases 2 & 4).

graphify's call graph can't link a leak that crosses language/process
boundaries (a `.sh` seed script → a DB defined in a k8s manifest → a Python
service). What ties those files together is a shared **resource identity** — the
same normalized DSN / bucket / topic string, which is byte-identical across
YAML, `.sh`, `.py`, `.cs`. So instead of inventing cross-language graph edges,
extract resource facts from every file and JOIN on resource_id: a non-prod-role
file that references a resource ALSO declared with a positive prod signal (an
explicit prod marker, or committed credentials in a manifest/config) is a leak.

This is a generalization of `evaluate_rule_b_content` ("file does a DB op", from
text, no edge) — here: "non-prod file references a prod-declared resource".

Ceiling: catches leaks that share an *identifiable resource literal*. A repo
whose environments differ only by deploy-time cluster (same service name
everywhere, e.g. bank-of-anthos `accounts-db`) has no resource-identity signal
to join on — correct behavior is to stay quiet and let the content engine catch
the committed creds/PII.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tempest.rie.env_map import ENV_PROD, ENV_DEV, ENV_TEST, classify_env_for_path

# scheme://[user[:pass]@]host[:port][/path]
_CONN_RE = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|s3)"
    r"://(?:(?P<cred>[^@/\s\"']+)@)?(?P<host>[^/\s:\"']+)(?::\d+)?(?:/(?P<path>[^\s?\"'#]*))?",
    re.IGNORECASE,
)

# Local / non-routable hosts are never a production resource identity — a
# localhost/loopback/compose-service DSN is a dev or CI database, not prod.
_LOCAL_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal",
})

# Template/example files are intentionally non-secret and must never anchor.
_EXAMPLE_MARKERS = (".example", ".sample", ".template", ".dist")


@dataclass(frozen=True)
class ResourceFact:
    resource_id: str          # normalized scheme://host/path (no creds/port)
    scheme: str
    file: str
    line: int
    role: str                 # env classification of the file (PROD/TEST/DEV/NON_PROD)
    is_prod_anchor: bool       # positive prod signal: explicit prod marker or committed creds in a declaration file
    is_nonprod_ref: bool       # referenced from a test/dev/seed-role file
    has_credentials: bool


def _normalize_resource_id(scheme: str, host: str, path: str | None) -> str:
    scheme = scheme.lower().replace("postgres", "postgresql").replace("postgresqlql", "postgresql")
    host = host.lower()
    path = (path or "").strip("/").lower()
    return f"{scheme}://{host}/{path}" if path else f"{scheme}://{host}"


def extract_resource_facts(
    files: list[str], repo_root: str | Path, config: dict[str, Any]
) -> list[ResourceFact]:
    """Scan text files for connection strings, tagging each with the declaring
    file's env role and whether it's a prod anchor / a non-prod reference. A
    prod anchor requires a POSITIVE prod signal (prod host/path marker) — a
    localhost/CI DSN or an .example template never anchors."""
    repo_root = Path(repo_root)
    prod_id_res = [
        re.compile(p, re.IGNORECASE)
        for p in config.get("boundary", {}).get("prod_identifier_patterns", [])
    ]
    facts: list[ResourceFact] = []
    for f in files:
        p = Path(f)
        rel = str(p.relative_to(repo_root)).replace("\\", "/") if p.is_absolute() and _under(p, repo_root) else str(f).replace("\\", "/")
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "://" not in text:
            continue
        rel_low = rel.lower()
        role = classify_env_for_path(rel, config)
        is_example = any(m in rel_low for m in _EXAMPLE_MARKERS)
        for i, line in enumerate(text.splitlines(), 1):
            for m in _CONN_RE.finditer(line):
                host = m.group("host")
                # Skip interpolation / env-var hosts and local/CI hosts — no
                # production resource identity.
                if host.startswith(("$", "{")) or "${" in m.group(0):
                    continue
                if host.lower() in _LOCAL_HOSTS:
                    continue
                rid = _normalize_resource_id(m.group("scheme"), host, m.group("path"))
                has_creds = bool(m.group("cred")) and ":" in (m.group("cred") or "")
                # Positive prod signal only: prod/production in host or path, an
                # explicit PROD role, or a prod_identifier_patterns host match.
                prod_signal = (
                    role == ENV_PROD
                    or "prod" in host.lower() or "production" in host.lower()
                    or "prod" in rel_low or "production" in rel_low
                    or any(r.search(host) for r in prod_id_res)
                )
                prod_anchor = prod_signal and not is_example
                nonprod_ref = role in (ENV_TEST, ENV_DEV)
                facts.append(ResourceFact(
                    resource_id=rid, scheme=m.group("scheme").lower(), file=rel, line=i,
                    role=role, is_prod_anchor=prod_anchor, is_nonprod_ref=nonprod_ref,
                    has_credentials=has_creds,
                ))
    return facts


def _under(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def join_cross_resource_leaks(facts: list[ResourceFact]) -> list[dict]:
    """A leak = a non-prod-role file references a resource_id that is prod-
    anchored in a DIFFERENT file. Returns evidence dicts (one per non-prod ref)."""
    anchors: dict[str, ResourceFact] = {}
    for f in facts:
        if f.is_prod_anchor and f.resource_id not in anchors:
            anchors[f.resource_id] = f

    leaks: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for f in facts:
        if not f.is_nonprod_ref:
            continue
        anchor = anchors.get(f.resource_id)
        if anchor is None or anchor.file == f.file:
            continue
        key = (f.file, f.resource_id)
        if key in seen:
            continue
        seen.add(key)
        leaks.append({
            "resource_id": f.resource_id,
            "nonprod_file": f.file, "nonprod_line": f.line, "nonprod_role": f.role,
            "prod_declared_in": anchor.file, "prod_line": anchor.line,
        })
    return leaks
