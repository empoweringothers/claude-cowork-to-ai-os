#!/usr/bin/env python3
"""Build a pinned release ZIP, hashes, and paste message from a clean tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REPOSITORY_PATH = "/empoweringothers/claude-cowork-to-ai-os"
EXCLUDED_PARTS = {".git", ".github", "__pycache__", ".pytest_cache", ".venv"}
EXCLUDED_NAMES = {"PUBLISHING-CHECKLIST.md", "FILE-SHA256SUMS.json"}
EXCLUDED_ROOT_DIRECTORIES = {"AI-OS", "captures", "exports"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise ValueError(completed.stderr.strip() or "git command failed")
    return completed.stdout.strip()


def run_git_bytes(*args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise ValueError(
            completed.stderr.decode("utf-8", errors="replace").strip()
            or "git command failed"
        )
    return completed.stdout


def release_identity() -> tuple[str, str]:
    plugin = json.loads(
        (ROOT / "plugins/cowork-ai-os/.claude-plugin/plugin.json").read_text(
            encoding="utf-8"
        )
    )
    release = json.loads((ROOT / "RELEASE.json").read_text(encoding="utf-8"))
    version = str(plugin["version"])
    tag = f"v{version}"
    if release.get("package_version") != version or release.get("release_tag") != tag:
        raise ValueError("plugin and RELEASE.json versions must match")
    return version, tag


def validate_release_url(value: str, expected_tag: str) -> None:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path
        != EXPECTED_REPOSITORY_PATH + "/releases/tag/" + expected_tag
    ):
        raise ValueError(
            "release URL must be https://github.com"
            + EXPECTED_REPOSITORY_PATH
            + f"/releases/tag/{expected_tag}"
        )


def validate_git_state(commit: str, tag: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ValueError("commit must be a full 40-character SHA")
    if run_git("rev-parse", "HEAD").lower() != commit.lower():
        raise ValueError("commit does not equal HEAD")
    if run_git("rev-parse", f"refs/tags/{tag}^{{commit}}").lower() != commit.lower():
        raise ValueError(f"tag {tag} does not point to HEAD")
    if run_git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("repository must be clean before release build")


def include(relative: Path) -> bool:
    if relative.name in EXCLUDED_NAMES or relative.suffix == ".pyc":
        return False
    if relative.parts and relative.parts[0] in EXCLUDED_ROOT_DIRECTORIES:
        return False
    if len(relative.parts) == 1 and (
        relative.name.startswith("inventory")
        and relative.suffix.casefold() in {".json", ".md", ".html"}
    ):
        return False
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    return True


def copy_tree(destination: Path, release_url: str, commit: str) -> None:
    entries = run_git_bytes("ls-tree", "-rz", "--full-tree", commit).split(b"\x00")
    for raw_entry in entries:
        if not raw_entry:
            continue
        try:
            header, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ", 2)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("unable to parse the pinned Git tree") from exc
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("release tree contains a symlink, submodule, or special entry")
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("release tree contains an unsafe path")
        if not include(relative):
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(run_git_bytes("cat-file", "blob", object_id))
        target.chmod(0o755 if mode == "100755" else 0o644)

    release_path = destination / "RELEASE.json"
    release = json.loads(release_path.read_text(encoding="utf-8"))
    release["release_url"] = release_url
    release["git_commit"] = commit.lower()
    release_path.write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")


def write_manifest(destination: Path, version: str, commit: str) -> None:
    files = {
        path.relative_to(destination).as_posix(): sha256(path)
        for path in sorted(destination.rglob("*"))
        if path.is_file() and path.name != "FILE-SHA256SUMS.json"
    }
    manifest = {
        "schema_version": 1,
        "package_version": version,
        "git_commit": commit.lower(),
        "algorithm": "sha256",
        "files": files,
    }
    (destination / "FILE-SHA256SUMS.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def zip_tree(source: Path, target: BinaryIO) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(
                    path,
                    f"claude-cowork-to-ai-os/{path.relative_to(source).as_posix()}",
                )


def _unique_temporary(path: Path) -> tuple[int, Path]:
    """Create an unpredictable, exclusive temporary file beside ``path``."""

    descriptor, name = tempfile.mkstemp(
        prefix="." + path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    return descriptor, Path(name)


def _publish_fresh(temporary: Path, path: Path) -> None:
    """Atomically publish ``temporary`` without replacing an existing path."""

    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise ValueError("release output files must not already exist") from exc
    temporary.unlink()


def atomic_text(path: Path, value: str) -> None:
    descriptor, temporary = _unique_temporary(path)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        _publish_fresh(temporary, path)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def atomic_zip_tree(source: Path, path: Path) -> None:
    descriptor, temporary = _unique_temporary(path)
    try:
        with os.fdopen(descriptor, "w+b") as stream:
            zip_tree(source, stream)
            stream.flush()
            os.fsync(stream.fileno())
        _publish_fresh(temporary, path)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-url", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    version, tag = release_identity()
    validate_release_url(args.release_url, tag)
    validate_git_state(args.commit, tag)

    output = args.out.expanduser().resolve()
    if output == ROOT or ROOT in output.parents or output in ROOT.parents:
        raise ValueError("release output must be outside the repository tree")
    output.mkdir(parents=True, exist_ok=True)

    zip_path = output / f"claude-cowork-to-ai-os-v{version}.zip"
    checksum_path = zip_path.with_suffix(".zip.sha256")
    message_path = output / "COWORK-AI-OS-SETUP-MESSAGE.txt"
    for release_artifact in (zip_path, checksum_path, message_path):
        if release_artifact.exists() or release_artifact.is_symlink():
            raise ValueError("release output files must not already exist")
    with tempfile.TemporaryDirectory(prefix="cowork-ai-os-release-") as temp:
        stage = Path(temp) / "claude-cowork-to-ai-os"
        stage.mkdir()
        copy_tree(stage, args.release_url, args.commit)
        write_manifest(stage, version, args.commit)
        atomic_zip_tree(stage, zip_path)

    digest = sha256(zip_path)
    atomic_text(checksum_path, f"{digest}  {zip_path.name}\n")
    release_zip_url = (
        "https://github.com"
        + EXPECTED_REPOSITORY_PATH
        + f"/releases/download/{tag}/{zip_path.name}"
    )
    message = (ROOT / "PASTE-INTO-CLAUDE-CODE.txt").read_text(encoding="utf-8")
    message = message.replace("{{GITHUB_RELEASE_URL}}", args.release_url)
    message = message.replace("{{RELEASE_TAG}}", tag)
    message = message.replace("{{GIT_COMMIT_SHA}}", args.commit.lower())
    message = message.replace("{{RELEASE_ZIP_URL}}", release_zip_url)
    message = message.replace("{{RELEASE_ZIP_SHA256}}", digest)
    if re.search(r"\{\{[A-Z0-9_]+\}\}", message):
        raise ValueError("generated setup message still contains a release placeholder")
    atomic_text(message_path, message)
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
