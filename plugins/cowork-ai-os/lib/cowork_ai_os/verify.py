"""Offline integrity and secret verification for captures and scaffolds."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .safety import (
    SafetyError,
    detect_secrets,
    is_relative_to,
    iter_tree_no_symlinks,
    read_regular_bytes,
    sha256_file,
)


MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SECRET_SCAN_BYTES = 64 * 1024 * 1024
MAX_REVIEW_BYTES = 2 * 1024 * 1024


def _safe_manifest_relative(value: Any) -> Optional[PurePosixPath]:
    if not isinstance(value, str) or not value:
        return None
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    return candidate


def _load_manifest(path: Path, root: Path) -> Optional[Mapping[str, Any]]:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        data = read_regular_bytes(path, root, MAX_MANIFEST_BYTES)
        parsed = json.loads(data.decode("utf-8"))
    except (OSError, SafetyError, UnicodeError, json.JSONDecodeError, RecursionError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _identity_marker(info: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    # On Windows, path-based stat and handle-based fstat can expose different
    # ``st_ctime`` semantics, and Python has deprecated that field there.
    # File identity, link count, size, and mtime remain bound across the read;
    # normalize only the non-portable ctime component.
    ctime_ns = 0 if os.name == "nt" else info.st_ctime_ns
    return (
        stat.S_IFMT(info.st_mode),
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        ctime_ns,
    )


def _stream_secret_scan(
    path: Path,
    expected: Tuple[int, int, int, int, int, int, int],
    max_bytes: int = MAX_SECRET_SCAN_BYTES,
) -> Tuple[List[str], bool]:
    """Scan bounded chunks with overlap; return findings and oversize flag."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    findings = set()
    scanned = 0
    carry = b""
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity_marker(opened) != expected
        ):
            raise SafetyError("verification path changed into a special file")
        opened_ctime_ns = opened.st_ctime_ns
        oversize = opened.st_size > max_bytes
        while scanned < max_bytes:
            chunk = os.read(fd, min(1024 * 1024, max_bytes - scanned))
            if not chunk:
                break
            findings.update(detect_secrets(carry + chunk))
            carry = (carry + chunk)[-16384:]
            scanned += len(chunk)
        after = os.fstat(fd)
        if (
            _identity_marker(after) != expected
            or after.st_ctime_ns != opened_ctime_ns
        ):
            raise SafetyError("verification path changed while it was read")
        return sorted(findings), oversize
    finally:
        os.close(fd)


def _review_counts(root: Path) -> Tuple[int, int]:
    review = root / "Inbox" / "REVIEW.md"
    try:
        data = read_regular_bytes(review, root, MAX_REVIEW_BYTES)
    except (OSError, SafetyError):
        return 0, 0
    text = data.decode("utf-8", errors="replace")
    matches = list(re.finditer(r"(?m)^## Candidate(?:\s+.*)?$", text))
    unreviewed = 0
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.end() : end]
        status = re.search(
            r"(?im)^\s*-\s*Status:\s*`?(review|edit|approve|reject)\b", block
        )
        if status is None or status.group(1).casefold() in {"review", "edit"}:
            unreviewed += 1
    return len(matches), unreviewed


def verify_tree(root: Path) -> Dict[str, Any]:
    root = root.expanduser()
    errors: List[str] = []
    warnings: List[str] = []
    try:
        root_mode = root.lstat().st_mode
    except FileNotFoundError:
        raise SafetyError("verification target does not exist")
    if stat.S_ISLNK(root_mode):
        return {
            "schema": "cowork-ai-os.verify.v1",
            "target": str(root),
            "ok": False,
            "files_checked": 0,
            "manifests_checked": 0,
            "source_policy_declared_read_only": False,
            "capture_warning_count": 0,
            "review_entry_count": 0,
            "unreviewed_candidate_count": 0,
            "errors": ["Verification target is a symlink."],
            "warnings": [],
        }
    if not stat.S_ISDIR(root_mode):
        raise SafetyError("verification target must be a directory")
    root = root.resolve()
    if os.name != "nt" and (root_mode & 0o077):
        errors.append("Root directory permissions are not owner-only (expected 0700 or stricter).")

    regular_files: List[Path] = []
    regular_markers: Dict[Path, Tuple[int, int, int, int, int, int, int]] = {}
    source_policy_declared = False
    capture_warning_count = 0
    redacted_file_count = 0
    binary_review_file_count = 0
    for path in iter_tree_no_symlinks(root):
        try:
            info = path.lstat()
            mode = info.st_mode
        except OSError:
            errors.append("A path could not be inspected.")
            continue
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(mode):
            errors.append("Symlink found: " + relative)
        elif stat.S_ISDIR(mode):
            if os.name != "nt" and (mode & 0o077):
                errors.append("Directory permissions are not owner-only: " + relative)
            continue
        elif stat.S_ISREG(mode):
            if info.st_nlink > 1:
                errors.append("Hard-linked file found: " + relative)
            if os.name != "nt" and (mode & 0o077):
                errors.append("File permissions are not owner-only: " + relative)
            regular_files.append(path)
            regular_markers[path] = _identity_marker(info)
        else:
            errors.append("Special file found: " + relative)

    for path in regular_files:
        try:
            findings, oversize = _stream_secret_scan(
                path, regular_markers[path]
            )
        except (OSError, SafetyError):
            errors.append("File could not be read: " + path.relative_to(root).as_posix())
            continue
        if findings:
            errors.append(
                "Likely secret in {}: {}".format(path.relative_to(root).as_posix(), ", ".join(findings))
            )
        if oversize:
            errors.append(
                "File exceeds the bounded secret-scan limit: " + path.relative_to(root).as_posix()
            )

    for path in regular_files:
        try:
            current = path.lstat()
        except OSError:
            errors.append("File changed during verification: " + path.relative_to(root).as_posix())
            continue
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or _identity_marker(current) != regular_markers[path]
        ):
            errors.append("File changed during verification: " + path.relative_to(root).as_posix())

    manifests = sorted(
        [
            path
            for path in regular_files
            if path.name in {"manifest.json", "scaffold.json"}
            and (path.name == "manifest.json" or path.parent.name == "manifests")
        ],
        key=lambda item: str(item).casefold(),
    )
    checked_manifests = 0
    if not manifests:
        errors.append("No capture or scaffold manifest was found.")
    for manifest_path in manifests:
        manifest = _load_manifest(manifest_path, root)
        if manifest is None:
            errors.append("Malformed manifest: " + manifest_path.relative_to(root).as_posix())
            continue
        files = manifest.get("files")
        if not isinstance(files, list):
            errors.append("Manifest has no file list: " + manifest_path.relative_to(root).as_posix())
            continue
        checked_manifests += 1
        if manifest.get("schema") == "cowork-ai-os.capture.v1":
            source_policy_declared = source_policy_declared or manifest.get("source_policy") == "read-only"
            manifest_warnings = manifest.get("warnings")
            if isinstance(manifest_warnings, list):
                capture_warning_count += sum(1 for item in manifest_warnings if isinstance(item, str))
        # Capture manifests are relative to their own directory.  Scaffold
        # manifests explicitly declare their base as the scaffold root.
        if manifest.get("paths_relative_to") == "scaffold-root":
            base = root
        else:
            base = manifest_path.parent
        seen_manifest_paths = set()
        for entry in files:
            if not isinstance(entry, Mapping):
                errors.append("Manifest contains a malformed file entry.")
                continue
            relative = _safe_manifest_relative(entry.get("path"))
            expected = entry.get("sha256")
            if relative is None or not isinstance(expected, str) or len(expected) != 64:
                errors.append("Manifest contains an unsafe or incomplete file entry.")
                continue
            if relative.as_posix().casefold() in seen_manifest_paths:
                errors.append("Manifest contains a duplicate file entry: " + relative.as_posix())
                continue
            seen_manifest_paths.add(relative.as_posix().casefold())
            provenance = entry.get("provenance")
            if isinstance(provenance, Mapping):
                redactions = provenance.get("redactions")
                if isinstance(redactions, list) and redactions:
                    redacted_file_count += 1
                if provenance.get("requires_human_review") is True:
                    binary_review_file_count += 1
            target = base.joinpath(*relative.parts)
            try:
                target_mode = target.lstat().st_mode
                target_real = target.resolve()
            except OSError:
                errors.append("Manifest file is missing: " + relative.as_posix())
                continue
            if stat.S_ISLNK(target_mode) or not stat.S_ISREG(target_mode) or not is_relative_to(target_real, root):
                errors.append("Manifest file is unsafe: " + relative.as_posix())
                continue
            try:
                actual = sha256_file(target)
            except (OSError, SafetyError):
                errors.append("Manifest file could not be hashed: " + relative.as_posix())
                continue
            if actual != expected:
                errors.append("Hash mismatch: " + relative.as_posix())

        # A capture's source-relative mapping is deliberately outside the
        # shareable file list, but its hash is anchored by the root manifest.
        private = manifest.get("private_manifest")
        if manifest_path.parent == root and isinstance(private, Mapping) and private.get("included") is True:
            private_relative = _safe_manifest_relative(private.get("path"))
            private_hash = private.get("sha256")
            if private_relative is None or not isinstance(private_hash, str) or len(private_hash) != 64:
                errors.append("Capture manifest has malformed private provenance metadata.")
            else:
                private_target = root.joinpath(*private_relative.parts)
                try:
                    private_mode = private_target.lstat().st_mode
                    actual_private_hash = sha256_file(private_target)
                except (OSError, SafetyError):
                    errors.append("Private provenance manifest is missing or unreadable.")
                else:
                    if stat.S_ISLNK(private_mode) or not stat.S_ISREG(private_mode):
                        errors.append("Private provenance manifest is unsafe.")
                    elif actual_private_hash != private_hash:
                        errors.append("Private provenance manifest hash mismatch.")

    actual_relatives = {path.relative_to(root).as_posix() for path in regular_files}
    root_capture = _load_manifest(root / "manifest.json", root)
    if isinstance(root_capture, Mapping) and root_capture.get("schema") == "cowork-ai-os.capture.v1":
        declared = {"manifest.json"}
        files = root_capture.get("files")
        if isinstance(files, list):
            for entry in files:
                relative = _safe_manifest_relative(entry.get("path") if isinstance(entry, Mapping) else None)
                if relative is not None:
                    declared.add(relative.as_posix())
        private = root_capture.get("private_manifest")
        if not isinstance(private, Mapping) or private.get("included") is not True:
            errors.append("Capture manifest must declare private provenance metadata.")
        else:
            relative = _safe_manifest_relative(private.get("path"))
            private_hash = private.get("sha256")
            if (
                relative is None
                or not isinstance(private_hash, str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", private_hash)
            ):
                errors.append("Capture manifest has malformed private provenance metadata.")
            else:
                declared.add(relative.as_posix())
        for unexpected in sorted(actual_relatives - declared):
            errors.append("Unmanifested file in capture: " + unexpected)
    elif (root / "manifest.json").is_file() and not (
        root / ".ai-os" / "manifests" / "scaffold.json"
    ).is_file():
        errors.append("Root capture manifest has an unsupported schema.")

    scaffold_path = root / ".ai-os" / "manifests" / "scaffold.json"
    scaffold_manifest = _load_manifest(scaffold_path, root)
    if isinstance(scaffold_manifest, Mapping) and scaffold_manifest.get("schema") == "cowork-ai-os.scaffold.v1":
        declared_protected = set()
        files = scaffold_manifest.get("files")
        if isinstance(files, list):
            for entry in files:
                relative = _safe_manifest_relative(entry.get("path") if isinstance(entry, Mapping) else None)
                if relative is not None:
                    declared_protected.add(relative.as_posix())
        protected_prefixes = (
            "Inbox/Cowork-Import/",
            "Projects/Cowork-Import/",
            ".ai-os/private/Cowork-Import/",
        )
        for unexpected in sorted(
            relative
            for relative in actual_relatives
            if relative.startswith(protected_prefixes) and relative not in declared_protected
        ):
            errors.append("Unmanifested file in imported capture: " + unexpected)

    review_entries, unreviewed_candidates = _review_counts(root)
    if capture_warning_count:
        warnings.append(
            "Capture manifest records {} warning(s); inspect the local manifest.".format(
                capture_warning_count
            )
        )
    if redacted_file_count:
        warnings.append(
            "{} imported file(s) record secret-pattern redactions.".format(redacted_file_count)
        )
    if binary_review_file_count:
        warnings.append(
            "{} imported binary file(s) require human review.".format(binary_review_file_count)
        )

    for path in regular_files:
        try:
            current = path.lstat()
        except OSError:
            errors.append("File changed during verification: " + path.relative_to(root).as_posix())
            continue
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or _identity_marker(current) != regular_markers[path]
        ):
            errors.append("File changed during verification: " + path.relative_to(root).as_posix())

    return {
        "schema": "cowork-ai-os.verify.v1",
        "target": str(root),
        "ok": not errors,
        "files_checked": len(regular_files),
        "manifests_checked": checked_manifests,
        "source_policy_declared_read_only": source_policy_declared,
        "capture_warning_count": capture_warning_count,
        "review_entry_count": review_entries,
        "unreviewed_candidate_count": unreviewed_candidates,
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
    }
