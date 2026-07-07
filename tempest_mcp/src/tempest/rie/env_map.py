"""DEV/QA/TEST/STAGING/PROD environment tagging per file/node.

Ordered heuristic chain (first match wins), per the Tempest design:
  1. Explicit glob overrides in tempest.config.yaml (path_overrides)
  2. Filename / env-file markers (.env.prod vs .env.dev, etc.)
  3. Folder-naming conventions (prod/, dev/, tests/, fixtures/)
  4. Connection-string/identifier regex heuristics on string literals
     near a node's source_location (handled by boundary.py, which layers
     PROD-only signal on top of this module's folder/file tagging)

Unmatched nodes default to NON-PROD (safe default — avoids false negatives
from under-tagging, since Tempest cares about things *reaching* PROD).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath
from typing import Any

ENV_PROD = "PROD"
ENV_STAGING = "STAGING"
ENV_QA = "QA"
ENV_TEST = "TEST"
ENV_DEV = "DEV"
ENV_UNKNOWN = "NON_PROD"  # generic non-prod bucket when no specific tag applies

# Priority order when multiple folder markers match different segments of a
# path (e.g. "tests/prod_fixtures/"): more specific/dangerous envs win.
_ENV_PRIORITY = [ENV_PROD, ENV_STAGING, ENV_QA, ENV_TEST, ENV_DEV]

# Non-prod environments treated as leak SOURCES by Rule (b): only EXPLICITLY
# marked non-prod roles — test and dev (which includes seed scripts / dev
# tooling via folder_markers). The generic ENV_UNKNOWN bucket is deliberately
# EXCLUDED: on a real repo with no prod/ folder, the app's own production data
# layer (e.g. app/services.py) also lands in ENV_UNKNOWN, and flagging it would
# be a false positive. STAGING/QA are excluded too (a different concern).
NONPROD_LEAK_ENVS = frozenset({ENV_TEST, ENV_DEV})


def _normalize_path(source_file: str) -> str:
    """Normalize a possibly-absolute, possibly-backslashed path to forward
    slashes for glob/segment matching."""
    return source_file.replace("\\", "/")


def _match_env_file_markers(filename: str, markers: dict[str, list[str]]) -> str | None:
    filename_lower = filename.lower()
    for env, patterns in markers.items():
        for pattern in patterns:
            if filename_lower == pattern.lower() or filename_lower.endswith("/" + pattern.lower()):
                return env.upper()
    return None


def _match_folder_markers(path: str, markers: dict[str, list[str]]) -> str | None:
    segments = [s.lower() for s in PurePosixPath(path).parts]
    matches = []
    for env, keywords in markers.items():
        for kw in keywords:
            if kw.lower() in segments:
                matches.append(env.upper())
                break
    if not matches:
        return None
    # Resolve conflicts (e.g. a path under both "prod" and "tests") using
    # priority order: most specific/dangerous wins.
    for env in _ENV_PRIORITY:
        if env in matches:
            return env
    return matches[0]


def classify_env_for_path(source_file: str | None, config: dict[str, Any]) -> str:
    """Return an environment tag (PROD/STAGING/QA/TEST/DEV/NON_PROD) for a
    given file path, using the ordered heuristic chain. Does not consider
    manual overrides or content-based regex — see boundary.py for the full
    classification pipeline that layers those on top."""
    if not source_file:
        return ENV_UNKNOWN

    boundary_cfg = config.get("boundary", {})
    path = _normalize_path(source_file)

    # (1) Explicit glob overrides.
    path_overrides = boundary_cfg.get("path_overrides", {})
    for glob in path_overrides.get("prod", []) or []:
        if fnmatch.fnmatch(path, glob):
            return ENV_PROD
    for glob in path_overrides.get("non_prod", []) or []:
        if fnmatch.fnmatch(path, glob):
            return ENV_UNKNOWN

    # (2) Filename / env-file markers.
    env_file_markers = boundary_cfg.get("env_file_markers", {})
    filename_hit = _match_env_file_markers(path, env_file_markers)
    if filename_hit:
        return filename_hit

    # (3) Folder-naming conventions.
    folder_markers = boundary_cfg.get("folder_markers", {})
    folder_hit = _match_folder_markers(path, folder_markers)
    if folder_hit:
        return folder_hit

    # (4) Regex/identifier heuristics are content-based and handled
    # separately in boundary.py, since they need access to source text,
    # not just the path.

    return ENV_UNKNOWN


def is_prod_env(env_tag: str) -> bool:
    return env_tag == ENV_PROD


def is_test_env(env_tag: str) -> bool:
    return env_tag == ENV_TEST
