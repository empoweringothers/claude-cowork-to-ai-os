"""Metadata-only Cowork session discovery.

Inventory intentionally never opens transcript, instruction, upload, output,
or memory files. It parses each ``local_*.json`` task record but retains and
emits only an allowlist of metadata fields; all other source material is
represented with filesystem metadata from ``lstat``.
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from .safety import (
    SafetyError,
    assert_source_root,
    contains_forbidden_part,
    forbidden_name,
    is_relative_to,
    read_regular_bytes,
    redact_text,
)


METADATA_LIMIT = 8 * 1024 * 1024
MAX_LAYOUT_ENTRIES = 10000
MAX_ARTIFACT_STAT_ENTRIES = 20000
MAX_ARTIFACT_STAT_DEPTH = 16
NATIVE_TRANSCRIPT_NAMES = (
    "transcript.jsonl",
    "conversation.jsonl",
    "messages.jsonl",
    "transcript.json",
    "conversation.json",
    "messages.json",
)
AUDIT_TRANSCRIPT_NAMES = ("audit.jsonl", "audit-log.jsonl", "audit_log.jsonl")
ARTIFACT_FOLDER_KINDS = {
    "memory": ("memory", "memories"),
    "uploads": ("uploads", "attachments"),
    "outputs": ("outputs", "artifacts"),
}
EXCLUDED_SESSION_DESCENDANTS = {"subagent", "subagents", "subagent-sessions"}
SAFE_METADATA_KEYS = (
    "id",
    "sessionId",
    "session_id",
    "uuid",
    "cliSessionId",
    "cli_session_id",
    "title",
    "name",
    "sessionTitle",
    "project",
    "projectName",
    "spaceName",
    "workspaceName",
    "spaceId",
    "space_id",
    "projectId",
    "createdAt",
    "created_at",
    "updatedAt",
    "updated_at",
    "modifiedAt",
    "messageCount",
    "message_count",
    "turnCount",
    "selectedFolders",
    "selected_folders",
    "folderPaths",
    "workingDirectories",
    "allowedDirectories",
    "linkedFolders",
    "transcriptPath",
    "transcript_path",
    "conversationPath",
    "auditPath",
    "sessionPath",
    "session_path",
)
SESSION_IDENTITY_KEYS = (
    "id",
    "sessionId",
    "session_id",
    "uuid",
    "cliSessionId",
    "cli_session_id",
)
SESSION_ASSOCIATION_KEYS = (
    "transcriptPath",
    "transcript_path",
    "conversationPath",
    "auditPath",
    "sessionPath",
    "session_path",
)
SESSION_METADATA_CONTAINERS = ("session", "metadata", "conversation")


@dataclass
class SessionRecord:
    safe_id: str
    metadata_path: Path
    source_root: Path
    workspace_path: Path
    account_basename: str
    workspace_basename: str
    raw_identifier: str = field(repr=False)
    cli_session_identifier: str = field(default="", repr=False)
    title: str = "Untitled session"
    project: str = ""
    space_identifier: str = field(default="", repr=False)
    space_name: str = ""
    # Discovery never opens or stores instruction bodies.  A targeted lookup
    # happens only during an applied capture of this explicit session.
    space_has_instructions: Optional[bool] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    message_count: Optional[int] = None
    selected_folder_basenames: List[str] = field(default_factory=list)
    transcript_path: Optional[Path] = field(default=None, repr=False)
    transcript_kind: Optional[str] = None
    transcript_bytes: int = 0
    artifact_roots: Dict[str, List[Path]] = field(default_factory=dict, repr=False)
    artifact_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def agent_safe_dict(self) -> Dict[str, Any]:
        """Return the only representation exposed by inventory commands."""

        result: Dict[str, Any] = {
            "id": self.safe_id,
            "title": self.title,
            "project": self.project or None,
            "space": {
                "name": self.space_name or None,
                "has_instructions": self.space_has_instructions,
            },
            "dates": {"created": self.created_at, "updated": self.updated_at},
            "counts": {
                "messages": self.message_count,
                "memory_files": self.artifact_stats.get("memory", {}).get("files", 0),
                "uploads": self.artifact_stats.get("uploads", {}).get("files", 0),
                "outputs": self.artifact_stats.get("outputs", {}).get("files", 0),
            },
            "sizes": {
                "transcript_bytes": self.transcript_bytes,
                "memory_bytes": self.artifact_stats.get("memory", {}).get("bytes", 0),
                "upload_bytes": self.artifact_stats.get("uploads", {}).get("bytes", 0),
                "output_bytes": self.artifact_stats.get("outputs", {}).get("bytes", 0),
            },
            "selected_folders": list(self.selected_folder_basenames),
            "transcript": {"available": self.transcript_path is not None, "kind": self.transcript_kind},
        }
        return result


@dataclass
class InventoryResult:
    source_root: Path = field(repr=False)
    sessions: List[SessionRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def agent_safe_dict(self) -> Dict[str, Any]:
        return {
            "schema": "cowork-ai-os.inventory.v1",
            "agent_safe": True,
            "content_trust": "untrusted-metadata",
            "session_count": len(self.sessions),
            "sessions": [item.agent_safe_dict() for item in self.sessions],
            "warnings": sorted(self.warnings),
        }


def _regular_json(path: Path, root: Path) -> Any:
    data = read_regular_bytes(path, root, METADATA_LIMIT)
    return json.loads(data.decode("utf-8-sig"))


def recognized_session_metadata(data: Any) -> bool:
    """Conservatively recognize a Cowork session metadata object.

    A ``local_*.json`` filename alone is not evidence of the supported format.
    Require either an explicit session identity or a source association path at
    the top level or in one of the supported metadata containers.
    """

    if not isinstance(data, Mapping):
        return False
    containers: List[Mapping[str, Any]] = [data]
    for key in SESSION_METADATA_CONTAINERS:
        nested = data.get(key)
        if isinstance(nested, Mapping):
            containers.append(nested)
    for container in containers:
        for key in SESSION_IDENTITY_KEYS + SESSION_ASSOCIATION_KEYS:
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                return True
    return False


def recognized_session_metadata_file(path: Path, root: Path) -> bool:
    """Return whether a bounded local metadata file has a supported shape."""

    try:
        return recognized_session_metadata(_regular_json(path, root))
    except (SafetyError, UnicodeError, json.JSONDecodeError, RecursionError):
        return False


def _safe_text(value: Any, default: str = "") -> str:
    if not isinstance(value, str):
        return default
    value = value.replace("\x00", " ").strip()
    redacted, _ = redact_text(value[:4096])
    return redacted


def _first_value(data: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _first_text(data: Mapping[str, Any], keys: Sequence[str]) -> str:
    return _safe_text(_first_value(data, keys))


def _nested_mapping(data: Mapping[str, Any], keys: Sequence[str]) -> Mapping[str, Any]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _normalise_date(value: Any) -> Optional[str]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 100_000_000_000:
            number /= 1000.0
        try:
            return _datetime.datetime.fromtimestamp(number, tz=_datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    # Do not echo arbitrary metadata as a date.  Accept only recognizable ISO
    # or RFC3339-like values.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+-]+Z?)?", text):
        return None
    return text[:64]


def _nonnegative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _workspace_locations(root: Path) -> Iterator[Tuple[str, str, Path]]:
    """Yield direct, account/workspace, and legacy account layouts."""

    seen: set = set()

    def has_local_json(directory: Path) -> bool:
        try:
            entries = os.scandir(directory)
        except OSError:
            return False
        with entries:
            for index, entry in enumerate(entries):
                if index >= MAX_LAYOUT_ENTRIES:
                    return False
                if entry.is_file(follow_symlinks=False) and entry.name.startswith("local_") and entry.name.endswith(".json"):
                    return True
        return False

    if has_local_json(root):
        seen.add(root)
        yield root.name, root.name, root

    try:
        with os.scandir(root) as iterator:
            first_level = []
            for index, entry in enumerate(iterator):
                if index >= MAX_LAYOUT_ENTRIES:
                    break
                first_level.append(entry)
        first_level.sort(key=lambda item: item.name.casefold())
    except OSError as exc:
        raise SafetyError("unable to inspect source root") from exc
    for account_entry in first_level:
        if account_entry.is_symlink() or not account_entry.is_dir(follow_symlinks=False):
            continue
        account = Path(account_entry.path)
        if contains_forbidden_part(account) or forbidden_name(account):
            continue
        if has_local_json(account) and account not in seen:
            seen.add(account)
            yield account.name, account.name, account
        try:
            with os.scandir(account) as iterator:
                second_level = []
                for index, entry in enumerate(iterator):
                    if index >= MAX_LAYOUT_ENTRIES:
                        break
                    second_level.append(entry)
            second_level.sort(key=lambda item: item.name.casefold())
        except OSError:
            continue
        for workspace_entry in second_level:
            if workspace_entry.is_symlink() or not workspace_entry.is_dir(follow_symlinks=False):
                continue
            workspace = Path(workspace_entry.path)
            if contains_forbidden_part(workspace) or forbidden_name(workspace):
                continue
            if workspace not in seen and has_local_json(workspace):
                seen.add(workspace)
                yield account.name, workspace.name, workspace


def _metadata_files(workspace: Path) -> List[Path]:
    paths: List[Path] = []
    try:
        entries = os.scandir(workspace)
    except OSError:
        return paths
    with entries:
        for index, entry in enumerate(entries):
            if index >= MAX_LAYOUT_ENTRIES:
                break
            if (
                entry.name.startswith("local_")
                and entry.name.endswith(".json")
                and entry.is_file(follow_symlinks=False)
                and not entry.is_symlink()
            ):
                paths.append(Path(entry.path))
    return sorted(paths, key=lambda item: item.name.casefold())


def _space_objects(data: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, Mapping):
                yield item
        return
    if not isinstance(data, Mapping):
        return
    for key in ("spaces", "projects", "items"):
        container = data.get(key)
        if isinstance(container, list):
            for item in container:
                if isinstance(item, Mapping):
                    yield item
            return
        if isinstance(container, Mapping):
            for identifier, item in container.items():
                if isinstance(item, Mapping):
                    copied = dict(item)
                    copied.setdefault("id", identifier)
                    yield copied
            return
    # Some versions store a single space object or an id -> object map.
    if any(key in data for key in ("id", "spaceId", "projectId")):
        yield data
    else:
        for identifier, item in data.items():
            if isinstance(item, Mapping):
                copied = dict(item)
                copied.setdefault("id", identifier)
                yield copied


def _selected_basenames(data: Mapping[str, Any]) -> List[str]:
    values: List[Any] = []
    for key in (
        "selectedFolders",
        "selected_folders",
        "folderPaths",
        "workingDirectories",
        "allowedDirectories",
        "linkedFolders",
    ):
        value = data.get(key)
        if isinstance(value, list):
            values.extend(value)
    result: List[str] = []
    for value in values:
        if isinstance(value, Mapping):
            value = _first_value(value, ("path", "name", "folder"))
        if not isinstance(value, str):
            continue
        # Both slash styles occur in portable metadata.  Only the final opaque
        # basename is retained; full linked-folder paths never leave discovery.
        basename = re.split(r"[/\\]+", value.rstrip("/\\"))[-1]
        basename = _safe_text(basename)
        if basename:
            result.append(basename[:120])
    return sorted(set(result), key=str.casefold)


def _bounded_dirs(root: Path, max_depth: int = 4, max_entries: int = 10000) -> Iterator[Path]:
    stack: List[Tuple[Path, int]] = [(root, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    visited += 1
                    if visited > max_entries:
                        return
                    entries.append(entry)
            entries.sort(key=lambda item: item.name.casefold())
        except OSError:
            continue
        directories: List[Path] = []
        for entry in entries:
            if entry.is_symlink():
                continue
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                if (
                    forbidden_name(path)
                    or contains_forbidden_part(path)
                    or path.name.casefold() in EXCLUDED_SESSION_DESCENDANTS
                ):
                    continue
                yield path
                directories.append(path)
        for directory in reversed(directories):
            stack.append((directory, depth + 1))


def _hinted_paths(data: Mapping[str, Any], workspace: Path, source_root: Path) -> List[Path]:
    results: List[Path] = []
    try:
        workspace_real = workspace.resolve()
        source_real = source_root.resolve()
    except OSError:
        return results
    if not is_relative_to(workspace_real, source_real):
        return results
    for key in ("transcriptPath", "transcript_path", "conversationPath", "auditPath", "sessionPath", "session_path"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = workspace / candidate
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            continue
        # A selected session may never redirect discovery into another
        # workspace, even when the target remains under the broader source
        # root.  Retain only the canonical path so later relative operations do
        # not crash on platform aliases such as macOS /var -> /private/var.
        if (
            is_relative_to(resolved, workspace_real)
            and not contains_forbidden_part(resolved)
            and not forbidden_name(resolved)
        ):
            results.append(resolved)
    return results


def _is_excluded_session_path(path: Path, source_root: Path) -> bool:
    """Reject subagent trees and paths outside the selected source root."""

    try:
        relative = path.resolve(strict=False).relative_to(source_root)
    except (OSError, ValueError):
        return True
    return bool(
        EXCLUDED_SESSION_DESCENDANTS.intersection(
            part.casefold() for part in relative.parts
        )
    )


def _locate_transcript(
    data: Mapping[str, Any],
    workspace: Path,
    source_root: Path,
    raw_identifier: str,
    cli_session_identifier: str,
    metadata_path: Path,
) -> Tuple[Optional[Path], Optional[str], List[Path], bool]:
    tokens = {metadata_path.stem, metadata_path.stem.removeprefix("local_")}
    if raw_identifier:
        tokens.add(raw_identifier)
    if cli_session_identifier:
        tokens.add(cli_session_identifier)
    candidate_files: List[Path] = []
    candidate_dirs: List[Path] = []
    session_root_tokens = {
        token.casefold()
        for token in tokens
        if token and token not in {".", ".."} and "/" not in token and "\\" not in token
    }
    association_tokens = {token for token in session_root_tokens if len(token) >= 6}
    try:
        workspace_real = workspace.resolve()
    except OSError:
        return None, None, [], False
    for hint in _hinted_paths(data, workspace, source_root):
        if _is_excluded_session_path(hint, source_root):
            continue
        folded_parts = {part.casefold() for part in hint.parts}
        if association_tokens and not association_tokens.intersection(folded_parts):
            # A metadata path hint must still identify this selected session;
            # otherwise it could redirect capture into another session tree.
            continue
        try:
            mode = hint.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            continue
        if stat.S_ISREG(mode):
            candidate_files.append(hint)
            candidate_dirs.append(hint.parent)
        elif stat.S_ISDIR(mode):
            candidate_dirs.append(hint)
    for token in sorted(tokens):
        if not token or token in {".", ".."} or "/" in token or "\\" in token:
            continue
        for base in (workspace, metadata_path.parent):
            candidate = base / token
            if forbidden_name(candidate) or contains_forbidden_part(candidate):
                continue
            try:
                mode = candidate.lstat().st_mode
                resolved_candidate = candidate.resolve()
            except FileNotFoundError:
                continue
            except OSError:
                continue
            if (
                stat.S_ISDIR(mode)
                and not stat.S_ISLNK(mode)
                and is_relative_to(resolved_candidate, workspace_real)
                and not _is_excluded_session_path(resolved_candidate, source_root)
            ):
                candidate_dirs.append(resolved_candidate)
    if not candidate_dirs:
        folded_tokens = {token.casefold() for token in tokens if len(token) >= 6}
        for directory in _bounded_dirs(workspace):
            folded = directory.name.casefold()
            if (
                folded in folded_tokens
                and not _is_excluded_session_path(directory, source_root)
            ):
                candidate_dirs.append(directory)

    # Search only within directories tied to this metadata record.
    expanded_dirs: List[Path] = []
    for directory in candidate_dirs:
        if forbidden_name(directory) or contains_forbidden_part(directory):
            continue
        expanded_dirs.append(directory)
        expanded_dirs.extend(_bounded_dirs(directory, max_depth=3, max_entries=3000))
    dynamic_native_names = (
        (cli_session_identifier + ".jsonl", cli_session_identifier + ".json")
        if cli_session_identifier
        else ()
    )
    for directory in expanded_dirs:
        for name in NATIVE_TRANSCRIPT_NAMES + dynamic_native_names + AUDIT_TRANSCRIPT_NAMES:
            candidate = directory / name
            try:
                mode = candidate.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
                candidate_files.append(candidate)

    def classify(path: Path) -> Optional[str]:
        folded = path.name.casefold()
        if folded in NATIVE_TRANSCRIPT_NAMES:
            return "native"
        if folded in {name.casefold() for name in dynamic_native_names}:
            return "native"
        if folded in AUDIT_TRANSCRIPT_NAMES:
            return "audit-fallback"
        return None

    valid: List[Tuple[int, int, str, Path, str]] = []
    for path in set(candidate_files):
        kind = classify(path)
        if not kind:
            continue
        try:
            mode = path.lstat().st_mode
            resolved = path.resolve()
        except OSError:
            continue
        if (
            stat.S_ISLNK(mode)
            or not stat.S_ISREG(mode)
            or not is_relative_to(resolved, workspace_real)
            or forbidden_name(resolved)
            or contains_forbidden_part(resolved)
        ):
            continue
        path = resolved
        relative_parts = {part.casefold() for part in path.relative_to(workspace_real).parts}
        if EXCLUDED_SESSION_DESCENDANTS.intersection(relative_parts):
            continue
        dynamic = path.name.casefold() in {name.casefold() for name in dynamic_native_names}
        closest_depth = min(
            (
                len(path.relative_to(directory).parts)
                for directory in candidate_dirs
                if is_relative_to(path, directory)
            ),
            default=len(path.relative_to(workspace_real).parts),
        )
        priority = 0 if dynamic else (1 if kind == "native" else 2)
        valid.append(
            (
                priority,
                closest_depth,
                str(path.relative_to(workspace_real)).casefold(),
                path,
                kind,
            )
        )
    valid.sort(key=lambda item: (item[0], item[1], item[2]))
    if valid:
        if len(valid) > 1 and valid[0][:2] == valid[1][:2]:
            return None, None, [], True
        chosen = valid[0]
        # Artifacts may come only from the nearest session-identity directory
        # on the winning transcript's canonical lineage.  Losing transcript
        # candidates never contribute artifact roots.
        proven_root: Optional[Path] = None
        for parent in chosen[3].parents:
            if parent == workspace_real:
                break
            if not is_relative_to(parent, workspace_real):
                break
            if parent.name.casefold() in session_root_tokens:
                proven_root = parent
                break
        return chosen[3], chosen[4], [proven_root] if proven_root is not None else [], False
    return None, None, [], False


def _artifact_roots(
    session_dirs: Sequence[Path], source_root: Path, workspace: Path
) -> Dict[str, List[Path]]:
    result: Dict[str, List[Path]] = {key: [] for key in ARTIFACT_FOLDER_KINDS}
    seen: set = set()
    try:
        resolved_workspace = workspace.resolve()
    except OSError:
        return result
    for base in session_dirs:
        if _is_excluded_session_path(base, source_root):
            continue
        try:
            resolved_base = base.resolve()
        except OSError:
            continue
        if resolved_base == resolved_workspace or not is_relative_to(
            resolved_base, resolved_workspace
        ):
            continue
        # ``session_dirs`` contains only the proven root on the winning
        # transcript lineage.  Do not widen to its parent: that directory can
        # hold sibling-session artifacts.
        for candidate_base in (base,):
            for kind, names in ARTIFACT_FOLDER_KINDS.items():
                for name in names:
                    candidate = candidate_base / name
                    if candidate in seen:
                        continue
                    seen.add(candidate)
                    try:
                        mode = candidate.lstat().st_mode
                        resolved = candidate.resolve()
                    except OSError:
                        continue
                    if (
                        stat.S_ISDIR(mode)
                        and not stat.S_ISLNK(mode)
                        and is_relative_to(resolved, source_root)
                        and not contains_forbidden_part(candidate)
                    ):
                        result[kind].append(candidate)
    for key in result:
        result[key].sort(key=lambda item: str(item).casefold())
    return result


def _folder_stats(
    roots: Sequence[Path],
    max_entries: int = MAX_ARTIFACT_STAT_ENTRIES,
    max_depth: int = MAX_ARTIFACT_STAT_DEPTH,
) -> Dict[str, int]:
    count = 0
    size = 0
    scanned = 0
    truncated = False
    stack = [(root, 0) for root in reversed(roots)]
    seen: set = set()
    while stack and not truncated:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    scanned += 1
                    if scanned > max_entries:
                        truncated = True
                        break
                    entries.append(entry)
            entries.sort(key=lambda item: item.name.casefold())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            path = Path(entry.path)
            if forbidden_name(path) or contains_forbidden_part(path):
                continue
            if entry.is_dir(follow_symlinks=False):
                if depth >= max_depth:
                    truncated = True
                else:
                    stack.append((path, depth + 1))
            elif entry.is_file(follow_symlinks=False):
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                marker = (
                    ("inode", info.st_dev, info.st_ino)
                    if info.st_ino
                    else ("path", str(path.resolve(strict=False)).casefold())
                )
                if marker in seen:
                    continue
                seen.add(marker)
                count += 1
                size += info.st_size
    return {"files": count, "bytes": size, "truncated": int(truncated)}


def discover_sessions(source: Path) -> InventoryResult:
    root = assert_source_root(source)
    result = InventoryResult(source_root=root)
    safe_ids: Dict[str, Path] = {}
    for account_name, workspace_name, workspace in _workspace_locations(root):
        for metadata_path in _metadata_files(workspace):
            try:
                raw = _regular_json(metadata_path, root)
            except (json.JSONDecodeError, RecursionError):
                result.warnings.append("Skipped malformed metadata for a session.")
                continue
            except (SafetyError, UnicodeError):
                result.warnings.append("Skipped unreadable metadata for a session.")
                continue
            if not isinstance(raw, Mapping):
                result.warnings.append("Skipped non-object metadata for a session.")
                continue
            if not recognized_session_metadata(raw):
                result.warnings.append("Skipped unrecognized metadata for a session.")
                continue
            nested = _nested_mapping(raw, ("session", "metadata", "conversation"))
            data: Dict[str, Any] = {}
            # Top-level safe metadata wins because newer versions place fields
            # there.  Unsafe message/system fields are never consulted.
            for key in SAFE_METADATA_KEYS:
                if key in nested:
                    data[key] = nested[key]
                if key in raw:
                    data[key] = raw[key]

            raw_identifier = _first_text(data, ("id", "sessionId", "session_id", "uuid"))
            if not raw_identifier:
                raw_identifier = metadata_path.stem.removeprefix("local_")
            cli_session_identifier = _first_text(
                data, ("cliSessionId", "cli_session_id")
            )
            identity = "\x00".join((account_name, workspace_name, raw_identifier, metadata_path.name))
            safe_id = hashlib.sha256(("cowork-ai-os-session-v1\x00" + identity).encode("utf-8")).hexdigest()[:12]
            # A collision is exceptionally unlikely, but deterministic
            # expansion keeps prefix selection unambiguous if it occurs.
            if safe_id in safe_ids:
                safe_id = hashlib.sha256((identity + "\x00collision").encode("utf-8")).hexdigest()[:20]
            safe_ids[safe_id] = metadata_path

            title = _first_text(data, ("title", "sessionTitle", "name")) or "Untitled session"
            project_value = _first_value(data, ("project", "projectName"))
            if isinstance(project_value, Mapping):
                project = _first_text(project_value, ("name", "title"))
            else:
                project = _safe_text(project_value)
            space_id = _first_text(data, ("spaceId", "space_id", "projectId"))
            space_object = _nested_mapping(raw, ("space", "project"))
            if not space_id:
                space_id = _first_text(space_object, ("id", "spaceId", "projectId"))
            space_name = (
                _first_text(data, ("spaceName", "workspaceName"))
                or _first_text(space_object, ("name", "title"))
            )

            transcript, transcript_kind, session_dirs, transcript_ambiguous = _locate_transcript(
                data,
                workspace,
                root,
                raw_identifier,
                cli_session_identifier,
                metadata_path,
            )
            if transcript_ambiguous:
                result.warnings.append(
                    "Skipped ambiguous transcript candidates for session " + safe_id + "."
                )
            transcript_size = 0
            if transcript is not None:
                try:
                    transcript_size = transcript.lstat().st_size
                except OSError:
                    transcript = None
                    transcript_kind = None
                    session_dirs = []
            artifact_roots = _artifact_roots(session_dirs, root, workspace)
            artifact_stats = {kind: _folder_stats(paths) for kind, paths in artifact_roots.items()}
            if any(stats.get("truncated") for stats in artifact_stats.values()):
                result.warnings.append(
                    "Artifact metadata count was truncated for session " + safe_id + "."
                )

            record = SessionRecord(
                safe_id=safe_id,
                metadata_path=metadata_path,
                source_root=root,
                workspace_path=workspace,
                account_basename=account_name,
                workspace_basename=workspace_name,
                raw_identifier=raw_identifier,
                cli_session_identifier=cli_session_identifier,
                title=title,
                project=project,
                space_identifier=space_id,
                space_name=space_name,
                space_has_instructions=None,
                created_at=_normalise_date(_first_value(data, ("createdAt", "created_at"))),
                updated_at=_normalise_date(_first_value(data, ("updatedAt", "updated_at", "modifiedAt"))),
                message_count=_nonnegative_int(_first_value(data, ("messageCount", "message_count", "turnCount"))),
                selected_folder_basenames=_selected_basenames(data),
                transcript_path=transcript,
                transcript_kind=transcript_kind,
                transcript_bytes=transcript_size,
                artifact_roots=artifact_roots,
                artifact_stats=artifact_stats,
            )
            result.sessions.append(record)
    result.sessions.sort(key=lambda item: item.safe_id)
    if not result.sessions:
        result.warnings.append(
            "No recognized Cowork session metadata was found in the selected root."
        )
    return result


def select_sessions(sessions: Sequence[SessionRecord], selectors: Sequence[str]) -> List[SessionRecord]:
    """Resolve exact IDs or unique prefixes; selecting all is never implicit."""

    if not selectors:
        raise SafetyError("capture requires at least one explicit session ID or prefix")
    selected: Dict[str, SessionRecord] = {}
    for selector in selectors:
        clean = selector.strip().casefold()
        if not clean or not re.fullmatch(r"[0-9a-f]{4,64}", clean):
            raise SafetyError("session selectors must be opaque hexadecimal IDs or prefixes")
        exact = [item for item in sessions if item.safe_id.casefold() == clean]
        matches = exact or [item for item in sessions if item.safe_id.casefold().startswith(clean)]
        if not matches:
            raise SafetyError("session selector did not match the inventory")
        if len(matches) > 1:
            raise SafetyError("session selector is ambiguous; use a longer prefix")
        selected[matches[0].safe_id] = matches[0]
    return [selected[key] for key in sorted(selected)]
