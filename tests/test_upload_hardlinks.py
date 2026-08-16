from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Tuple
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

import cowork_ai_os.capture as capture_module
import cowork_ai_os.safety as safety_module
from cowork_ai_os.capture import CaptureLimits, capture_sessions
from cowork_ai_os.cli import main
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.safety import SafetyError, assert_source_root, read_regular_bytes
from cowork_ai_os.verify import verify_tree


class UploadHardlinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "cowork-source"
        self.workspace = self.source / "account-a" / "workspace-a"
        self.session = self.workspace / "session-alpha"
        self.session.mkdir(parents=True)
        self.transcript = self.session / "transcript.jsonl"
        self.transcript.write_text(
            json.dumps({"role": "user", "content": "Synthetic message."}) + "\n",
            encoding="utf-8",
        )
        (self.workspace / "local_session-alpha.json").write_text(
            json.dumps(
                {
                    "id": "session-alpha",
                    "title": "Synthetic session",
                    "projectName": "Synthetic Project",
                    "spaceId": "space-1",
                    "transcriptPath": "session-alpha/transcript.jsonl",
                }
            ),
            encoding="utf-8",
        )
        (self.workspace / "spaces.json").write_text(
            json.dumps(
                {
                    "spaces": [
                        {
                            "id": "space-1",
                            "name": "Synthetic Project",
                            "instructions": "Use synthetic material only.",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.record = discover_sessions(self.source).sessions[0]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def hardlinked_upload(self, name: str = "source.png") -> Tuple[Path, Path]:
        if not safety_module.HAS_SECURE_DIR_FD:
            self.skipTest("secure no-follow directory descriptors unavailable")
        external = self.base / ("external-" + name)
        external.write_bytes(b"\x89PNG\r\n\x1a\n\x00SYNTHETIC")
        uploads = self.session / "uploads"
        uploads.mkdir(exist_ok=True)
        upload = uploads / name
        try:
            os.link(external, upload)
        except (OSError, NotImplementedError):
            self.skipTest("hardlinks unavailable")
        return external, upload

    def preview(
        self,
        output: Path,
        *,
        include: bool,
        limits: Optional[CaptureLimits] = None,
    ) -> dict:
        return capture_sessions(
            self.source,
            [self.record.safe_id],
            output,
            apply=False,
            limits=limits,
            include_hardlinked_uploads=include,
        )

    def apply(
        self,
        output: Path,
        preview: dict,
        *,
        include: bool,
        limits: Optional[CaptureLimits] = None,
    ) -> dict:
        return capture_sessions(
            self.source,
            [self.record.safe_id],
            output,
            apply=True,
            limits=limits,
            approved_plan=preview["approval_token"],
            include_hardlinked_uploads=include,
        )

    def test_default_skips_hardlinked_upload_and_strict_reader_rejects_it(self) -> None:
        external, upload = self.hardlinked_upload()
        output = self.base / "capture-default"

        preview = self.preview(output, include=False)
        self.assertEqual(preview["hardlinked_upload_file_count"], 0)
        self.assertTrue(any("hard-linked uploads" in item for item in preview["warnings"]))
        with self.assertRaises(SafetyError):
            read_regular_bytes(upload, self.source, 1024)

        self.apply(output, preview, include=False)
        exported = b"".join(
            path.read_bytes() for path in output.rglob("*") if path.is_file()
        )
        self.assertNotIn(external.read_bytes(), exported)

    def test_opt_in_preview_is_body_free_and_capture_is_a_fresh_file(self) -> None:
        external, upload = self.hardlinked_upload()
        output = self.base / "capture-opt-in"
        original_read = capture_module.read_regular_bytes

        def reject_upload_body(path: Path, *args, **kwargs):
            if path == upload:
                raise AssertionError("preview opened an upload body")
            return original_read(path, *args, **kwargs)

        with mock.patch.object(
            capture_module, "read_regular_bytes", side_effect=reject_upload_body
        ):
            preview = self.preview(output, include=True)

        self.assertEqual(preview["hardlinked_upload_file_count"], 1)
        self.assertTrue(any(item.startswith("WARNING:") for item in preview["warnings"]))
        self.assertNotIn(str(external), json.dumps(preview))
        result = self.apply(output, preview, include=True)
        self.assertEqual(result["hardlinked_upload_file_count"], 1)

        captured = output / "sessions" / self.record.safe_id / "uploads" / "item-0001.png"
        self.assertEqual(captured.read_bytes(), external.read_bytes())
        self.assertEqual(captured.stat().st_nlink, 1)
        self.assertNotEqual(
            (captured.stat().st_dev, captured.stat().st_ino),
            (upload.stat().st_dev, upload.stat().st_ino),
        )
        self.assertTrue(verify_tree(output)["ok"])
        private = json.loads(
            (output / ".private" / "provenance.json").read_text(encoding="utf-8")
        )
        artifact = private["sessions"][0]["artifacts"][0]
        self.assertEqual(artifact["source_link_count"], 2)
        self.assertTrue(artifact["copied_by_value"])
        self.assertNotIn(str(external), json.dumps(private))

    def test_preview_is_stale_when_link_count_changes(self) -> None:
        external, _ = self.hardlinked_upload()
        output = self.base / "capture-link-change"
        preview = self.preview(output, include=True)
        third_name = self.base / "third-name.png"
        os.link(external, third_name)

        with self.assertRaises(SafetyError):
            self.apply(output, preview, include=True)
        self.assertFalse(output.exists())

    def test_preview_is_stale_when_hardlink_content_identity_changes(self) -> None:
        external, _ = self.hardlinked_upload()
        output = self.base / "capture-content-change"
        preview = self.preview(output, include=True)
        external.write_bytes(b"\x89PNG\r\n\x1a\n\x00DIFFERENT")

        with self.assertRaises(SafetyError):
            self.apply(output, preview, include=True)
        self.assertFalse(output.exists())

    def test_opt_in_still_rejects_hardlinked_outputs_memory_and_symlinks(self) -> None:
        if not safety_module.HAS_SECURE_DIR_FD:
            self.skipTest("secure no-follow directory descriptors unavailable")
        external = self.base / "outside.png"
        external.write_bytes(b"\x89PNG\r\n\x1a\n\x00BLOCKED")
        for kind in ("outputs", "memory"):
            root = self.session / kind
            root.mkdir()
            try:
                os.link(external, root / (kind + ".png"))
            except (OSError, NotImplementedError):
                self.skipTest("hardlinks unavailable")
        project_memory = self.workspace / "spaces" / "space-1" / "memory"
        project_memory.mkdir(parents=True)
        os.link(external, project_memory / "project.png")
        uploads = self.session / "uploads"
        uploads.mkdir()
        try:
            (uploads / "escape.png").symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")

        output = self.base / "capture-refusals"
        preview = self.preview(output, include=True)
        self.assertEqual(preview["hardlinked_upload_file_count"], 0)
        self.assertTrue(any("hard-linked outputs" in item for item in preview["warnings"]))
        self.assertTrue(any("hard-linked memory" in item for item in preview["warnings"]))
        self.assertTrue(any("hard-linked project memory" in item for item in preview["warnings"]))
        self.assertTrue(any("symlink in uploads" in item for item in preview["warnings"]))
        self.apply(output, preview, include=True)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        kinds = {
            item["provenance"]["kind"]
            for item in manifest["files"]
            if isinstance(item.get("provenance"), dict)
        }
        self.assertFalse(any("upload" in kind or "output" in kind or "memory" in kind for kind in kinds))

    def test_opt_in_deduplicates_inode_and_skips_oversized_upload(self) -> None:
        external, _ = self.hardlinked_upload("one.png")
        os.link(external, self.session / "uploads" / "two.png")
        output = self.base / "capture-dedup"
        preview = self.preview(output, include=True)
        self.assertEqual(preview["hardlinked_upload_file_count"], 1)

        tiny_limits = CaptureLimits(max_file_bytes=4)
        oversized_output = self.base / "capture-oversized"
        oversized = self.preview(oversized_output, include=True, limits=tiny_limits)
        self.assertEqual(oversized["hardlinked_upload_file_count"], 0)
        self.assertTrue(any("oversized uploads" in item for item in oversized["warnings"]))

    def test_cli_flag_is_bound_to_the_approval_token(self) -> None:
        self.hardlinked_upload()
        output = self.base / "capture-cli"
        base_args = [
            "capture",
            "--source",
            str(self.source),
            "--session",
            self.record.safe_id,
            "--output",
            str(output),
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(base_args + ["--include-hardlinked-uploads"])
        self.assertEqual(code, 0)
        preview = json.loads(stdout.getvalue())
        self.assertTrue(preview["include_hardlinked_uploads"])

        with contextlib.redirect_stderr(io.StringIO()):
            code = main(
                base_args
                + ["--apply", "--approve-plan", preview["approval_token"]]
            )
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

        with contextlib.redirect_stdout(io.StringIO()):
            code = main(
                base_args
                + [
                    "--include-hardlinked-uploads",
                    "--apply",
                    "--approve-plan",
                    preview["approval_token"],
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(output.exists())


class SourceSafetyRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def synthetic_stat(*, ctime_ns: int, ino: int = 22) -> SimpleNamespace:
        return SimpleNamespace(
            st_mode=0o100600,
            st_dev=11,
            st_ino=ino,
            st_size=9,
            st_mtime_ns=44,
            st_ctime_ns=ctime_ns,
            st_nlink=1,
        )

    def read_with_mocked_stats(
        self,
        *,
        path_stats: list[SimpleNamespace],
        handle_stats: list[SimpleNamespace],
        platform_name: str,
    ) -> bytes:
        target = self.base / "synthetic.txt"
        root = self.base / "source"
        with mock.patch.object(safety_module.os, "name", platform_name), mock.patch.object(
            safety_module, "HAS_SECURE_DIR_FD", platform_name != "nt"
        ), mock.patch.object(
            safety_module, "ensure_contained_regular", side_effect=path_stats
        ), mock.patch.object(
            safety_module, "_open_windows_contained_readonly", return_value=123
        ), mock.patch.object(
            safety_module, "_open_contained_readonly", return_value=123
        ), mock.patch.object(safety_module.os, "open", return_value=123), mock.patch.object(
            safety_module.os, "fstat", side_effect=handle_stats
        ), mock.patch.object(
            safety_module.os, "read", side_effect=[b"synthetic", b""]
        ), mock.patch.object(safety_module.os, "close"):
            return read_regular_bytes(target, root, 1024)

    def test_windows_reader_accepts_path_handle_ctime_semantics_difference(self) -> None:
        path_stat = self.synthetic_stat(ctime_ns=55)
        handle_stat = self.synthetic_stat(ctime_ns=66)

        data = self.read_with_mocked_stats(
            path_stats=[path_stat, path_stat],
            handle_stats=[handle_stat, handle_stat],
            platform_name="nt",
        )

        self.assertEqual(data, b"synthetic")

    def test_windows_reader_rejects_handle_ctime_change_during_read(self) -> None:
        path_stat = self.synthetic_stat(ctime_ns=55)
        opened_stat = self.synthetic_stat(ctime_ns=66)
        changed_stat = self.synthetic_stat(ctime_ns=67)

        with self.assertRaisesRegex(SafetyError, "changed while it was being read"):
            self.read_with_mocked_stats(
                path_stats=[path_stat],
                handle_stats=[opened_stat, changed_stat],
                platform_name="nt",
            )

    def test_posix_reader_still_rejects_path_handle_ctime_difference(self) -> None:
        path_stat = self.synthetic_stat(ctime_ns=55)
        handle_stat = self.synthetic_stat(ctime_ns=66)

        with self.assertRaisesRegex(SafetyError, "changed during capture"):
            self.read_with_mocked_stats(
                path_stats=[path_stat],
                handle_stats=[handle_stat],
                platform_name="posix",
            )

    def test_source_root_rejects_intermediate_symlink_to_protected_tree(self) -> None:
        protected = self.base / "Credentials"
        nested = protected / "synthetic-source"
        nested.mkdir(parents=True)
        alias = self.base / "safe-alias"
        try:
            alias.symlink_to(protected, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")

        with self.assertRaisesRegex(SafetyError, "must not contain symlinks"):
            assert_source_root(alias / nested.name)

    def test_source_root_rechecks_forbidden_parts_after_resolution(self) -> None:
        safe = self.base / "synthetic-source"
        safe.mkdir()
        protected = self.base / "Credentials" / "synthetic-source"

        with mock.patch.object(Path, "resolve", return_value=protected):
            with self.assertRaisesRegex(SafetyError, "protected browser"):
                assert_source_root(safe)

    def test_source_root_accepts_normal_directory(self) -> None:
        safe = self.base / "synthetic-source"
        safe.mkdir()

        self.assertEqual(assert_source_root(safe), safe.resolve())

    def test_normal_read_rejects_parent_symlink_swap_before_secure_open(self) -> None:
        if not safety_module.HAS_SECURE_DIR_FD:
            self.skipTest("secure no-follow directory descriptors unavailable")
        root = self.base / "synthetic-source"
        parent = root / "parent"
        parent.mkdir(parents=True)
        target = parent / "payload.txt"
        target.write_bytes(b"approved synthetic bytes")
        external_parent = self.base / "external"
        external_parent.mkdir()
        (external_parent / target.name).write_bytes(b"outside synthetic bytes")
        moved_parent = root / "parent-original"
        original_open = safety_module._open_contained_readonly
        swapped = False

        def swap_then_open(path: Path, source_root: Path) -> int:
            nonlocal swapped
            parent.rename(moved_parent)
            parent.symlink_to(external_parent, target_is_directory=True)
            swapped = True
            return original_open(path, source_root)

        with mock.patch.object(
            safety_module, "_open_contained_readonly", side_effect=swap_then_open
        ):
            with self.assertRaises(SafetyError):
                read_regular_bytes(target, root, 1024)

        self.assertTrue(swapped)


if __name__ == "__main__":
    unittest.main()
