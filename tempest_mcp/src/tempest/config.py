"""Config file loading/merging.

Loads the shipped baseline `tempest/data/tempest.default.yaml` (bundled as
package data, read via importlib.resources so it works from any install —
editable, wheel, or pipx) and, if present, deep-merges the target repo's
`.tempest/tempest.config.yaml` on top of it. User config always wins on
conflicting keys; lists in the user config replace (not append to) the
corresponding default list, except where noted.
"""

from __future__ import annotations

import copy
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from tempest.paths import RepoPaths


def _read_default_config_text() -> str:
    return files("tempest").joinpath("data/tempest.default.yaml").read_text(encoding="utf-8")


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_default_config() -> dict[str, Any]:
    data = yaml.safe_load(_read_default_config_text())
    return data or {}


def load_config(repo_root: str | Path) -> dict[str, Any]:
    """Return the effective config for a target repo: defaults merged with
    the repo's own .tempest/tempest.config.yaml, if any."""
    config = load_default_config()

    paths = RepoPaths(repo_root)
    if paths.config_file.exists():
        with open(paths.config_file, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        config = _deep_merge(config, user_config)

    return config


def write_default_user_config_if_missing(repo_root: str | Path) -> Path:
    """On first sync, drop a copy of the default config into the target repo's
    .tempest/ dir so the developer has something editable. No-op if it
    already exists."""
    paths = RepoPaths(repo_root)
    paths.ensure_tempest_dir()
    if not paths.config_file.exists():
        content = _read_default_config_text()
        header = (
            "# Tempest per-repo config. Values here override "
            "the shipped tempest/data/tempest.default.yaml.\n"
            "# Delete this file (or clear a section) to fall back to defaults.\n\n"
        )
        paths.config_file.write_text(header + content, encoding="utf-8")
    return paths.config_file
