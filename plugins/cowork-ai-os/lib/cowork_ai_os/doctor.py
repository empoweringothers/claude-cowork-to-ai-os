"""Platform-aware Cowork root detection using bounded session metadata."""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .discovery import recognized_session_metadata_file
from .safety import contains_forbidden_part, forbidden_name


MAX_DOCTOR_ENTRIES = 10000


def _has_session_metadata(root: Path) -> bool:
    """Recognize documented layouts only when metadata has a supported shape."""

    stack = [(root, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    visited += 1
                    if visited > MAX_DOCTOR_ENTRIES:
                        return False
                    entries.append(entry)
        except OSError:
            return False
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if (
                    entry.is_file(follow_symlinks=False)
                    and entry.name.startswith("local_")
                    and entry.name.endswith(".json")
                ):
                    if recognized_session_metadata_file(Path(entry.path), root):
                        return True
                if depth < 2 and entry.is_dir(follow_symlinks=False):
                    path = Path(entry.path)
                    if not forbidden_name(path) and not contains_forbidden_part(path):
                        stack.append((path, depth + 1))
            except OSError:
                continue
    return False


def default_cowork_roots(
    home: Optional[Path] = None,
    platform_name: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> List[Path]:
    env = dict(os.environ if environ is None else environ)
    home_path = (home or Path.home()).expanduser()
    system = (platform_name or platform.system()).casefold()
    if system == "darwin":
        base = home_path / "Library" / "Application Support" / "Claude"
        candidates = [base / "local-agent-mode-sessions"]
    elif system == "windows":
        roaming = Path(env.get("APPDATA", str(home_path / "AppData" / "Roaming")))
        local = Path(env.get("LOCALAPPDATA", str(home_path / "AppData" / "Local")))
        candidates = [
            local
            / "Packages"
            / "Claude_pzs8sxrjxfjjc"
            / "LocalCache"
            / "Roaming"
            / "Claude"
            / "local-agent-mode-sessions",
            roaming / "Claude" / "local-agent-mode-sessions",
            local / "Claude" / "local-agent-mode-sessions",
        ]
    else:
        config = Path(env.get("XDG_CONFIG_HOME", str(home_path / ".config")))
        candidates = [config / "Claude" / "local-agent-mode-sessions"]
    # An explicit environment override is useful for portable/test installs and
    # does not cause any directory contents to be read.
    override = env.get("COWORK_AI_OS_ROOTS", "")
    if override:
        candidates = [Path(item).expanduser() for item in override.split(os.pathsep) if item.strip()] + candidates
    unique: List[Path] = []
    seen = set()
    for candidate in candidates:
        marker = str(candidate)
        if marker not in seen:
            seen.add(marker)
            unique.append(candidate)
    return unique


def doctor_report(extra_roots: Sequence[Path] = (), agent_safe: bool = False) -> Dict[str, Any]:
    # Explicit roots narrow the inspection boundary; they never cause an
    # implicit second scan of the current user's default Cowork stores.
    candidates = list(extra_roots) if extra_roots else default_cowork_roots()
    rows: List[Dict[str, Any]] = []
    seen = set()
    for candidate in candidates:
        candidate = candidate.expanduser()
        marker = str(candidate)
        if marker in seen:
            continue
        seen.add(marker)
        protected = contains_forbidden_part(candidate) or forbidden_name(candidate)
        exists = False
        is_directory = False
        is_symlink = False
        try:
            mode = candidate.lstat().st_mode
            exists = True
            is_symlink = stat.S_ISLNK(mode)
            is_directory = stat.S_ISDIR(mode)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        layout_recognized = (
            not protected
            and exists
            and is_directory
            and not is_symlink
            and _has_session_metadata(candidate)
        )
        row = {
            "exists": exists,
            "is_directory": is_directory,
            "is_symlink": is_symlink,
            "protected": protected,
            "layout": "recognized" if layout_recognized else "no-session-metadata",
            "usable": layout_recognized,
        }
        if agent_safe:
            row["label"] = "candidate-{}".format(len(rows) + 1)
            row["basename"] = candidate.name or "root"
        else:
            row["path"] = str(candidate)
        rows.append(row)
    return {
        "schema": "cowork-ai-os.doctor.v1",
        "agent_safe": agent_safe,
        "inspection": "bounded-session-metadata",
        "network": "disabled-by-design",
        "roots": rows,
        "usable_root_count": sum(1 for row in rows if row["usable"]),
    }
