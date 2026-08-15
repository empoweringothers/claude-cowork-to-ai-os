#!/usr/bin/env python3
"""Verify the integrity manifest in an unpacked Cowork AI OS release."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "FILE-SHA256SUMS.json"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError("release file is linked or not regular")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_manifest() -> bytes:
    try:
        before = MANIFEST.lstat()
    except OSError as exc:
        raise ValueError("FILE-SHA256SUMS.json is missing") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > MAX_MANIFEST_BYTES
    ):
        raise ValueError("FILE-SHA256SUMS.json must be a bounded, single-link regular file")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(MANIFEST), flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > MAX_MANIFEST_BYTES
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("FILE-SHA256SUMS.json changed or is unsafe")
        chunks = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_MANIFEST_BYTES:
            raise ValueError("FILE-SHA256SUMS.json exceeds the size limit")
        after = os.fstat(descriptor)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ino != opened.st_ino
            or after.st_nlink != 1
        ):
            raise ValueError("FILE-SHA256SUMS.json changed while being read")
        return data
    finally:
        os.close(descriptor)


def _valid_expected_files(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(path, str)
        and bool(path)
        and isinstance(digest, str)
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest.casefold())
        for path, digest in value.items()
    )


def main() -> int:
    try:
        data = json.loads(_read_manifest().decode("utf-8"))
        expected = data["files"]
        if not _valid_expected_files(expected):
            raise ValueError("manifest file map is malformed")
    except (OSError, UnicodeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"Release verification failed: invalid manifest: {exc}")
        return 1

    actual = {}
    unsafe = []
    for path in ROOT.rglob("*"):
        if path == MANIFEST:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if ".git" in path.relative_to(ROOT).parts:
            unsafe.append(relative)
            continue
        try:
            info = path.lstat()
        except OSError:
            unsafe.append(relative)
            continue
        if stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink > 1):
            unsafe.append(relative)
            continue
        if stat.S_ISREG(info.st_mode):
            try:
                actual[relative] = sha256(path)
            except (OSError, ValueError):
                unsafe.append(relative)
        elif not stat.S_ISDIR(info.st_mode):
            unsafe.append(relative)
    if unsafe:
        print("Release verification failed: unsafe linked or special paths: " + ", ".join(sorted(unsafe)))
        return 1
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(
            path for path in set(actual) & set(expected) if actual[path] != expected[path]
        )
        print("Release verification failed.")
        if missing:
            print(f"Missing files: {', '.join(missing)}")
        if extra:
            print(f"Unexpected files: {', '.join(extra)}")
        if changed:
            print(f"Changed files: {', '.join(changed)}")
        return 1
    print("Release verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
