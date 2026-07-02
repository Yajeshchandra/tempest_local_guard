"""Subprocess wrapper around `graphify update`.

Tempest treats `graphify update` as a black-box graph builder and
`graph.json` (standard NetworkX node-link JSON) as the sole data contract.
We never import graphify internals and never talk to graphify's own MCP
server — we shell out to its CLI exactly as a developer would.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from tempest.paths import GRAPHIFY_OUT_DIR_NAME, TEMPEST_DIR_NAME, RepoPaths
from tempest.rie.branch_state import get_branch_state


class GraphifyNotFoundError(RuntimeError):
    """Raised when the `graphify` CLI cannot be located on PATH."""


class GraphifyExtractError(RuntimeError):
    """Raised when `graphify update` exits non-zero or produces no graph.json."""


@dataclass
class SyncResult:
    repo_root: str
    graph_json_path: str
    node_count: int
    edge_count: int
    branch: str
    commit_sha: str | None
    is_default_branch: bool
    branch_warning: str | None
    duration_seconds: float
    stdout_tail: str = ""
    synced_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict:
        return {
            "repo_root": self.repo_root,
            "graph_json_path": self.graph_json_path,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "is_default_branch": self.is_default_branch,
            "branch_warning": self.branch_warning,
            "duration_seconds": self.duration_seconds,
            "synced_at": self.synced_at,
        }


def _find_graphify_executable() -> str:
    """Locate the `graphify` CLI.

    Prefers an executable installed alongside the current Python
    interpreter (i.e. in the same venv as `tempest`), then falls back to
    PATH lookup.
    """
    venv_scripts = Path(sys.executable).parent
    candidates = [
        venv_scripts / "graphify.exe",
        venv_scripts / "graphify",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    found = shutil.which("graphify")
    if found:
        return found

    raise GraphifyNotFoundError(
        "Could not find the `graphify` CLI. Install it with `pip install graphifyy` "
        "into the same environment as tempest_mcp."
    )


def run_graphify_extract(repo_root: str | Path, timeout_seconds: int = 600) -> Path:
    """Run `graphify update <repo_root>` (AST-only, no LLM) with output
    redirected into `<repo_root>/.tempest/graphify-out`.

    `graphify extract` also does semantic LLM extraction of docs/images and
    hard-fails without an API key (or silently calls out to whatever LLM key
    happens to be in the environment) — `update` is graphify's AST-only path
    and is all Tempest's graph needs, matching the "fully local" guarantee.

    Returns the path to the resulting graph.json. Raises GraphifyExtractError
    on failure or if the expected output file is missing afterward.
    """
    paths = RepoPaths(repo_root)
    paths.ensure_tempest_dir()
    paths.ensure_gitignore_entry()

    graphify_exe = _find_graphify_executable()

    cmd = [
        graphify_exe,
        "update",
        str(paths.repo_root),
        "--no-cluster",
        "--force",
    ]
    # `update` has no --out flag; it writes to <repo_root>/<GRAPHIFY_OUT>.
    env = {**os.environ, "GRAPHIFY_OUT": f"{TEMPEST_DIR_NAME}/{GRAPHIFY_OUT_DIR_NAME}"}
    # ponytail: on Windows, graphify's parallel ProcessPoolExecutor workers can
    # inherit our capture_output pipe and hold it open after graph.json is
    # written, hanging communicate() forever. graphify's own git hook forces
    # sequential extraction for this exact "agent shell fragile pipe" case
    # (graphify/hooks.py); mirror it. Drop this if graphify stops leaking the
    # pipe, or switch extraction to file-redirected stdout instead of PIPE.
    if sys.platform == "win32":
        env.setdefault("GRAPHIFY_MAX_WORKERS", "1")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(paths.repo_root),
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise GraphifyExtractError(
            f"`graphify update` timed out after {timeout_seconds}s"
        ) from exc
    except OSError as exc:
        raise GraphifyExtractError(f"Failed to launch graphify: {exc}") from exc

    if proc.returncode != 0:
        raise GraphifyExtractError(
            f"`graphify update` exited with code {proc.returncode}.\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    if not paths.graph_json.exists():
        raise GraphifyExtractError(
            f"`graphify update` completed but no graph.json was found at "
            f"{paths.graph_json}.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    return paths.graph_json


def sync_repo(repo_root: str | Path, timeout_seconds: int = 600) -> SyncResult:
    """Full sync: run graphify update, record branch state, write last_sync.json."""
    start = time.monotonic()
    paths = RepoPaths(repo_root)

    graph_json_path = run_graphify_extract(repo_root, timeout_seconds=timeout_seconds)

    with open(graph_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    node_count = len(data.get("nodes", []))
    edge_count = len(data.get("links", data.get("edges", [])))

    branch_state = get_branch_state(paths.repo_root)

    duration = time.monotonic() - start

    result = SyncResult(
        repo_root=str(paths.repo_root),
        graph_json_path=str(graph_json_path),
        node_count=node_count,
        edge_count=edge_count,
        branch=branch_state.branch,
        commit_sha=branch_state.commit_sha,
        is_default_branch=branch_state.is_default_branch,
        branch_warning=branch_state.warning,
        duration_seconds=duration,
    )

    with open(paths.last_sync_file, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    return result
