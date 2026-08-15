from __future__ import annotations

import json
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

import cowork_ai_os.safety as safety
import cowork_ai_os.verify as verify_module
from cowork_ai_os.capture import capture_sessions
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.doctor import doctor_report
from cowork_ai_os.safety import SafetyError
from cowork_ai_os.verify import verify_tree


class SecurityRegressionRoundThreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        self.workspace = self.source / "account" / "workspace"
        self.session = self.workspace / "session-alpha"
        self.session.mkdir(parents=True)
        (self.session / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "synthetic message"}) + "\n",
            encoding="utf-8",
        )
        (self.workspace / "local_session-alpha.json").write_text(
            json.dumps(
                {
                    "id": "session-alpha",
                    "spaceId": "space-alpha",
                    "transcriptPath": "session-alpha/transcript.jsonl",
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def preview(self, output: Path) -> tuple[str, str]:
        session_id = discover_sessions(self.source).sessions[0].safe_id
        plan = capture_sessions(
            self.source, [session_id], output, apply=False
        )
        return session_id, plan["approval_token"]

    def test_spaces_file_appearing_after_preview_invalidates_apply(self) -> None:
        output = self.base / "capture"
        session_id, token = self.preview(output)
        (self.workspace / "spaces.json").write_text(
            json.dumps(
                {
                    "spaces": [
                        {
                            "id": "space-alpha",
                            "instructions": "NEW_SPACE_BODY_MUST_NOT_IMPORT",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SafetyError):
            capture_sessions(
                self.source,
                [session_id],
                output,
                apply=True,
                approved_plan=token,
            )
        self.assertFalse(output.exists())

    def test_doctor_rejects_protected_explicit_root_without_opening_it(self) -> None:
        protected = self.base / "IndexedDB"
        protected.mkdir()
        metadata = protected / "local_synthetic.json"
        metadata.write_text(json.dumps({"id": "synthetic"}), encoding="utf-8")
        opened = []

        def should_not_open(*args, **kwargs):
            opened.append((args, kwargs))
            raise AssertionError("protected root was opened")

        with mock.patch(
            "cowork_ai_os.doctor.recognized_session_metadata_file",
            side_effect=should_not_open,
        ):
            row = doctor_report([protected], agent_safe=True)["roots"][0]
        self.assertFalse(row["usable"])
        self.assertTrue(row["protected"])
        self.assertEqual(opened, [])

    def test_capture_manifest_without_private_provenance_fails_verify(self) -> None:
        capture = self.base / "capture"
        capture.mkdir(mode=0o700)
        payload = capture / "README.md"
        payload.write_text("synthetic\n", encoding="utf-8")
        manifest = {
            "schema": "cowork-ai-os.capture.v1",
            "source_policy": "read-only",
            "files": [
                {
                    "path": "README.md",
                    "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
                }
            ],
        }
        (capture / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        if os.name != "nt":
            os.chmod(payload, 0o600)
            os.chmod(capture / "manifest.json", 0o600)

        result = verify_tree(capture)

        self.assertFalse(result["ok"])
        self.assertTrue(
            any("private provenance" in item for item in result["errors"])
        )

    def test_windows_identity_marker_normalizes_only_deprecated_ctime(self) -> None:
        common = {
            "st_mode": 0o100600,
            "st_dev": 11,
            "st_ino": 22,
            "st_nlink": 1,
            "st_size": 33,
            "st_mtime_ns": 44,
        }
        path_stat = SimpleNamespace(**common, st_ctime_ns=55)
        handle_stat = SimpleNamespace(**common, st_ctime_ns=66)

        with mock.patch.object(verify_module.os, "name", "nt"):
            self.assertEqual(
                verify_module._identity_marker(path_stat),
                verify_module._identity_marker(handle_stat),
            )
            changed_inode = SimpleNamespace(
                **{**common, "st_ino": 23}, st_ctime_ns=66
            )
            self.assertNotEqual(
                verify_module._identity_marker(path_stat),
                verify_module._identity_marker(changed_inode),
            )

        with mock.patch.object(verify_module.os, "name", "posix"):
            self.assertNotEqual(
                verify_module._identity_marker(path_stat),
                verify_module._identity_marker(handle_stat),
            )

    @unittest.skipIf(os.name == "nt", "hard-link timing test is POSIX-specific")
    def test_verify_rejects_file_swapped_to_hardlink_after_inventory(self) -> None:
        capture = self.base / "capture"
        session_id, token = self.preview(capture)
        capture_sessions(
            self.source,
            [session_id],
            capture,
            apply=True,
            approved_plan=token,
        )
        target = capture / "README.md"
        external = self.base / "external.txt"
        original_scan = verify_module._stream_secret_scan
        swapped = False

        def swap_then_scan(path, expected, max_bytes=verify_module.MAX_SECRET_SCAN_BYTES):
            nonlocal swapped
            if path == target and not swapped:
                external.write_bytes(target.read_bytes())
                target.unlink()
                os.link(external, target)
                swapped = True
            return original_scan(path, expected, max_bytes)

        with mock.patch.object(
            verify_module, "_stream_secret_scan", side_effect=swap_then_scan
        ):
            result = verify_tree(capture)

        self.assertTrue(swapped)
        self.assertFalse(result["ok"])
        self.assertEqual(target.stat().st_nlink, 2)

    @unittest.skipIf(os.name == "nt", "directory-handle test is POSIX-specific")
    def test_parent_symlink_swap_cannot_redirect_capture_into_source(self) -> None:
        approved_parent = self.base / "approved-parent"
        approved_parent.mkdir()
        moved_parent = self.base / "approved-parent-original"
        output = approved_parent / "capture"
        session_id, token = self.preview(output)
        original_mkdir = safety.os.mkdir
        swapped = False

        def swap_parent_before_create(path, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == "capture" and dir_fd is not None and not swapped:
                approved_parent.rename(moved_parent)
                approved_parent.symlink_to(self.source, target_is_directory=True)
                swapped = True
            return original_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(safety.os, "mkdir", side_effect=swap_parent_before_create):
            with self.assertRaises(SafetyError):
                capture_sessions(
                    self.source,
                    [session_id],
                    output,
                    apply=True,
                    approved_plan=token,
                )

        self.assertTrue(swapped)
        self.assertFalse((self.source / "capture").exists())


if __name__ == "__main__":
    unittest.main()
