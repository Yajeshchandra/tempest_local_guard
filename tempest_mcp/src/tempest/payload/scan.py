"""Standalone content scan orchestrator.

Walks a whole repository tree, runs the vendored Payload Engine over it
(secrets / PII / entropy / format-specific leaks), tags each finding with a
path-based environment label, and writes a *separate* JSON report under
`<repo>/.tempest/content_scan_report.json`.

This is intentionally decoupled from Tempest's graph/dataflow pipeline: it
needs no `graph.json` and does not require `tempest_sync`. It reuses only the
path-only env classifier (`classify_env_for_path`) and the repo `.tempest/`
layout — nothing in the existing detection pipeline is touched.
"""

from __future__ import annotations

import json
import os
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tempest.config import load_config
from tempest.paths import RepoPaths
from tempest.payload.engine import PayloadEngine
from tempest.rie.env_map import classify_env_for_path

REPORT_NAME = "content_scan_report.json"

# Directories never worth scanning. Pruned during the walk so we don't descend
# into them at all.
# ponytail: ignore dirs hardcoded; move to config only if a repo needs custom ignores.
IGNORE_DIRS: frozenset[str] = frozenset({
    ".git", ".tempest", "node_modules", "__pycache__",
    ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache",
})


def _iter_repo_files(repo_root: Path) -> list[str]:
    """Walk the repo, pruning ignored dirs, returning absolute file paths."""
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            files.append(os.path.join(dirpath, name))
    return files


def run_content_scan(repo_root: str | Path) -> dict[str, Any]:
    """Scan the whole repo tree for content-based leaks and write a report.

    Returns the report dict (also persisted to
    `<repo>/.tempest/content_scan_report.json`).
    """
    paths = RepoPaths(repo_root)
    root = paths.repo_root
    config = load_config(str(root))

    files = _iter_repo_files(root)
    raw_findings = PayloadEngine().scan(files)

    findings: list[dict[str, Any]] = []
    for f in raw_findings:
        # Report file paths relative to the repo for readability; env tagging
        # uses the same relative path (matches how tempest classifies files).
        try:
            rel = str(Path(f["file"]).resolve().relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = f["file"]
        entry = dict(f)
        entry["file"] = rel
        entry["env"] = classify_env_for_path(rel, config)
        findings.append(entry)

    report = {
        "scan_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-" + uuid.uuid4().hex[:8],
        "repo": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(findings),
            "files_scanned": len(files),
            "by_type": dict(Counter(f["type"] for f in findings)),
            "by_severity": dict(Counter(f["severity"] for f in findings)),
            "by_env": dict(Counter(f["env"] for f in findings)),
        },
        "findings": findings,
    }

    paths.ensure_tempest_dir()
    (paths.tempest_dir / REPORT_NAME).write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report
