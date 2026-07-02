"""Git branch/HEAD checks.

"Prod" = the GitHub main/master/default branch is the source of truth; the
local graph tracks the developer's working tree, which should stay in sync
with it. We warn (don't block) if the working tree isn't on the default
branch, since the graph would then reflect in-progress work rather than the
deployed baseline.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BRANCH_CANDIDATES = ("main", "master")


@dataclass
class BranchState:
    branch: str
    commit_sha: str | None
    is_default_branch: bool
    warning: str | None


def _run_git(repo_root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            # -c core.fsmonitor=false: in a repo with core.fsmonitor=true, the
            # first git command spawns a detached `git fsmonitor--daemon` that
            # inherits our capture_output pipe and holds it open forever, so
            # communicate() never sees EOF and hangs — even with timeout set,
            # because the child exits but the pipe stays open (the sync then
            # wedges after graphify already finished). These are one-shot reads
            # that don't benefit from fsmonitor. stdin=DEVNULL so a credential
            # helper can't block on a prompt either.
            ["git", "-c", "core.fsmonitor=false", *args],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _detect_default_branch(repo_root: Path) -> str | None:
    # Try the remote HEAD symref first (most reliable indicator of the
    # repo's actual default branch).
    ref = _run_git(repo_root, "symbolic-ref", "refs/remotes/origin/HEAD")
    if ref:
        return ref.rsplit("/", 1)[-1]
    return None


def get_branch_state(repo_root: str | Path) -> BranchState:
    repo_root = Path(repo_root)

    branch = _run_git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    commit_sha = _run_git(repo_root, "rev-parse", "HEAD")

    if branch is None:
        # Not a git repo (or git unavailable) — this is fine, Tempest still
        # works on a plain directory; just no branch-sync warning possible.
        return BranchState(
            branch="(no-git)",
            commit_sha=None,
            is_default_branch=True,
            warning=None,
        )

    default_branch = _detect_default_branch(repo_root)
    if default_branch is not None:
        is_default = branch == default_branch
    else:
        is_default = branch in DEFAULT_BRANCH_CANDIDATES

    warning = None
    if not is_default:
        expected = default_branch or "/".join(DEFAULT_BRANCH_CANDIDATES)
        warning = (
            f"Working tree is on branch '{branch}', not the default branch "
            f"('{expected}'). The scanned graph reflects this branch's code, "
            f"which may differ from what's actually deployed to prod."
        )

    return BranchState(
        branch=branch,
        commit_sha=commit_sha,
        is_default_branch=is_default,
        warning=warning,
    )
