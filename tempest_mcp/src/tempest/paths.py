"""Per-target-repo runtime state layout.

Every repo Tempest scans gets a `.tempest/` directory created inside it
(not inside tempest_mcp itself):

    <target-repo>/.tempest/
        graphify-out/            graphify's own working dir (opaque)
        graph.json                canonical input to Tempest's graph load
        tempest.config.yaml       optional user-editable policy/boundary config
        boundary_overrides.json   manual PROD/NON-PROD overrides
        tempest.db                 SQLite: scan history + findings
        last_sync.json
"""

from __future__ import annotations

from pathlib import Path


TEMPEST_DIR_NAME = ".tempest"
GRAPHIFY_OUT_DIR_NAME = "graphify-out"
GRAPH_JSON_NAME = "graph.json"
CONFIG_NAME = "tempest.config.yaml"
OVERRIDES_NAME = "boundary_overrides.json"
DB_NAME = "tempest.db"
LAST_SYNC_NAME = "last_sync.json"


class RepoPaths:
    """Resolves all `.tempest/` paths for a given target repository root."""

    def __init__(self, repo_root: str | Path):
        self.repo_root = Path(repo_root).resolve()
        self.tempest_dir = self.repo_root / TEMPEST_DIR_NAME

    @property
    def graphify_out_dir(self) -> Path:
        return self.tempest_dir / GRAPHIFY_OUT_DIR_NAME

    @property
    def graph_json(self) -> Path:
        # graphify update writes graph.json into <repo>/<GRAPHIFY_OUT>, and we
        # set GRAPHIFY_OUT=.tempest/graphify-out (see rie/sync.py).
        return self.graphify_out_dir / GRAPH_JSON_NAME

    @property
    def config_file(self) -> Path:
        return self.tempest_dir / CONFIG_NAME

    @property
    def overrides_file(self) -> Path:
        return self.tempest_dir / OVERRIDES_NAME

    @property
    def db_file(self) -> Path:
        return self.tempest_dir / DB_NAME

    @property
    def last_sync_file(self) -> Path:
        return self.tempest_dir / LAST_SYNC_NAME

    def ensure_tempest_dir(self) -> None:
        self.tempest_dir.mkdir(parents=True, exist_ok=True)

    def ensure_gitignore_entry(self) -> None:
        """Best-effort: add `.tempest/` to the target repo's .gitignore."""
        gitignore = self.repo_root / ".gitignore"
        entry = TEMPEST_DIR_NAME + "/"
        try:
            if gitignore.exists():
                content = gitignore.read_text(encoding="utf-8", errors="ignore")
                lines = [ln.strip() for ln in content.splitlines()]
                if entry.rstrip("/") in [ln.rstrip("/") for ln in lines]:
                    return
                sep = "" if content.endswith("\n") or not content else "\n"
                gitignore.write_text(
                    content + sep + entry + "\n", encoding="utf-8"
                )
            else:
                gitignore.write_text(entry + "\n", encoding="utf-8")
        except OSError:
            # Non-fatal: not being able to touch .gitignore shouldn't block a sync.
            pass
