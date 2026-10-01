"""Where the kit keeps its files.

``AIGUARD_HOME`` (environment) wins; otherwise ``~/.aiguard``. Every function
takes an optional ``home`` so callers that already know their home directory
(the Flask app, tests) can pass it explicitly.

Layout::

    <home>/logs/       run logs (.log human, .jsonl structured)
    <home>/reports/    demo reports (JSON + HTML)
    <home>/state.json  rollback points + last-used connection (no secrets)
    <home>/config.json optional user defaults (no secrets)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

__all__ = [
    "ENV_HOME",
    "aiguard_home",
    "logs_dir",
    "reports_dir",
    "state_path",
    "config_path",
]

ENV_HOME = "AIGUARD_HOME"

PathLike = Union[str, "os.PathLike[str]", Path]


def aiguard_home(home: Optional[PathLike] = None) -> Path:
    """The kit's home directory (not created here)."""
    if home is not None and str(home).strip():
        return Path(home).expanduser()
    env = os.environ.get(ENV_HOME, "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".aiguard"


def _ensure_dir(path: Path) -> Path:
    # 0o700: logs and state are redacted, but they still describe the lab.
    # (The mode is ignored on Windows; existing directories are left alone.)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def logs_dir(home: Optional[PathLike] = None, *, create: bool = True) -> Path:
    """``<home>/logs``; created (with parents) unless ``create=False``."""
    path = aiguard_home(home) / "logs"
    return _ensure_dir(path) if create else path


def reports_dir(home: Optional[PathLike] = None, *, create: bool = True) -> Path:
    """``<home>/reports``; created (with parents) unless ``create=False``."""
    path = aiguard_home(home) / "reports"
    return _ensure_dir(path) if create else path


def state_path(home: Optional[PathLike] = None) -> Path:
    """``<home>/state.json`` (the directory is created when State writes)."""
    return aiguard_home(home) / "state.json"


def config_path(home: Optional[PathLike] = None) -> Path:
    """``<home>/config.json``."""
    return aiguard_home(home) / "config.json"
