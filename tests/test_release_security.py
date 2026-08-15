from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import build_release
import verify_release


class ReleaseBuildSecurityTests(unittest.TestCase):
    def test_atomic_text_ignores_predictable_symlink_temp(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            destination = root / "checksum.sha256"
            external = root / "external.txt"
            external.write_text("EXTERNAL-CANARY", encoding="utf-8")
            predictable = destination.with_suffix(destination.suffix + ".new")
            try:
                predictable.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")

            build_release.atomic_text(destination, "trusted output\n")

            self.assertEqual(external.read_text(encoding="utf-8"), "EXTERNAL-CANARY")
            self.assertTrue(predictable.is_symlink())
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_text(encoding="utf-8"), "trusted output\n")

    def test_atomic_zip_ignores_predictable_symlink_temp(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            (source / "payload.txt").write_text("synthetic payload", encoding="utf-8")
            destination = root / "release.zip"
            external = root / "external.txt"
            external.write_text("EXTERNAL-CANARY", encoding="utf-8")
            predictable = destination.with_suffix(destination.suffix + ".new")
            try:
                predictable.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")

            build_release.atomic_zip_tree(source, destination)

            self.assertEqual(external.read_text(encoding="utf-8"), "EXTERNAL-CANARY")
            self.assertTrue(predictable.is_symlink())
            self.assertFalse(destination.is_symlink())
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(
                    archive.read("claude-cowork-to-ai-os/payload.txt"),
                    b"synthetic payload",
                )


class ReleaseVerificationSecurityTests(unittest.TestCase):
    def _write_valid_release(self, root: Path) -> Path:
        payload = root / "payload.txt"
        payload.write_bytes(b"synthetic payload")
        manifest = root / "FILE-SHA256SUMS.json"
        manifest.write_text(
            json.dumps(
                {
                    "files": {
                        "payload.txt": hashlib.sha256(b"synthetic payload").hexdigest()
                    }
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def _verify(self, root: Path, manifest: Path) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(verify_release, "ROOT", root))
            stack.enter_context(mock.patch.object(verify_release, "MANIFEST", manifest))
            stack.enter_context(contextlib.redirect_stdout(output))
            result = verify_release.main()
        return result, output.getvalue()

    def test_manifest_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "release"
            root.mkdir()
            manifest = self._write_valid_release(root)
            contents = manifest.read_bytes()
            manifest.unlink()
            external = root.parent / "external-manifest.json"
            external.write_bytes(contents)
            try:
                manifest.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")

            result, output = self._verify(root, manifest)

            self.assertEqual(result, 1)
            self.assertIn("invalid manifest", output)

    def test_manifest_hardlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "release"
            root.mkdir()
            manifest = self._write_valid_release(root)
            external = root.parent / "external-manifest.json"
            try:
                os.link(manifest, external)
            except (OSError, NotImplementedError):
                self.skipTest("hard links unavailable")

            result, output = self._verify(root, manifest)

            self.assertEqual(result, 1)
            self.assertIn("single-link regular file", output)

    def test_dot_git_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "release"
            root.mkdir()
            manifest = self._write_valid_release(root)
            (root / ".git").write_text("gitdir: synthetic", encoding="utf-8")

            result, output = self._verify(root, manifest)

            self.assertEqual(result, 1)
            self.assertIn(".git", output)

    def test_dot_git_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "release"
            root.mkdir()
            manifest = self._write_valid_release(root)
            git_directory = root / ".git"
            git_directory.mkdir()
            (git_directory / "config").write_text("synthetic", encoding="utf-8")

            result, output = self._verify(root, manifest)

            self.assertEqual(result, 1)
            self.assertIn(".git", output)

    def test_dot_git_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "release"
            root.mkdir()
            manifest = self._write_valid_release(root)
            external = root.parent / "external-directory"
            external.mkdir()
            try:
                (root / ".git").symlink_to(external, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")

            result, output = self._verify(root, manifest)

            self.assertEqual(result, 1)
            self.assertIn(".git", output)


if __name__ == "__main__":
    unittest.main()
