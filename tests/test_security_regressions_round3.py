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

import cowork_ai_os.capture as capture_module
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

    def test_safe_spaces_change_marker_failure_fails_preview_closed(self) -> None:
        spaces = self.workspace / "spaces.json"
        spaces.write_text(
            json.dumps(
                {
                    "spaces": [
                        {
                            "id": "space-alpha",
                            "instructions": "SYNTHETIC_SPACE_INSTRUCTIONS",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        session_id = discover_sessions(self.source).sessions[0].safe_id
        output = self.base / "capture"
        real_change_marker = capture_module.source_file_change_marker

        def fail_registry_marker(path, root, **kwargs):
            if Path(path).name == "spaces.json":
                raise SafetyError("synthetic change metadata failure")
            return real_change_marker(path, root, **kwargs)

        with mock.patch.object(
            capture_module,
            "source_file_change_marker",
            side_effect=fail_registry_marker,
        ):
            with self.assertRaisesRegex(SafetyError, "change metadata failure"):
                capture_sessions(
                    self.source, [session_id], output, apply=False
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

    def test_windows_stream_scan_keeps_handle_ctime_race_check(self) -> None:
        target = self.base / "scan-target.txt"
        target.write_text("synthetic safe text", encoding="utf-8")
        real_fstat = verify_module.os.fstat
        fstat_calls = 0

        def changing_handle_stat(descriptor):
            nonlocal fstat_calls
            fstat_calls += 1
            info = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_nlink=info.st_nlink,
                st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns + (1 if fstat_calls > 1 else 0),
            )

        with mock.patch.object(verify_module.os, "name", "nt"):
            expected = verify_module._identity_marker(target.lstat())
            with mock.patch.object(
                verify_module.os, "fstat", side_effect=changing_handle_stat
            ):
                with self.assertRaises(SafetyError):
                    verify_module._stream_secret_scan(target, expected)

        self.assertEqual(fstat_calls, 2)

    def test_windows_change_marker_uses_handle_change_time(self) -> None:
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

        with mock.patch.object(safety.os, "name", "nt"), mock.patch.object(
            safety, "ensure_contained_regular", side_effect=[path_stat, path_stat]
        ), mock.patch.object(
            safety, "_open_windows_contained_readonly", return_value=123
        ) as open_contained, mock.patch.object(
            safety.os, "fstat", side_effect=[handle_stat, handle_stat]
        ), mock.patch.object(
            safety,
            "_windows_file_change_time_100ns",
            side_effect=[700, 700],
        ), mock.patch.object(safety.os, "close"):
            marker = safety.source_file_change_marker(
                self.base / "synthetic.txt", self.source
            )

        self.assertEqual(marker, ("windows-change-time-100ns", 700))
        open_contained.assert_called_once_with(
            self.base / "synthetic.txt", self.source, metadata_only=True
        )

    def test_windows_change_marker_rejects_change_during_query(self) -> None:
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

        with mock.patch.object(safety.os, "name", "nt"), mock.patch.object(
            safety, "ensure_contained_regular", side_effect=[path_stat, path_stat]
        ), mock.patch.object(
            safety, "_open_windows_contained_readonly", return_value=123
        ), mock.patch.object(
            safety.os, "fstat", side_effect=[handle_stat, handle_stat]
        ), mock.patch.object(
            safety,
            "_windows_file_change_time_100ns",
            side_effect=[700, 701],
        ), mock.patch.object(safety.os, "close"):
            with self.assertRaisesRegex(SafetyError, "metadata inspection"):
                safety.source_file_change_marker(
                    self.base / "synthetic.txt", self.source
                )

    def test_fallback_writes_and_hashes_in_binary_mode(self) -> None:
        binary_flag = 0x8000
        noinherit_flag = 0x0080
        write_open = mock.Mock(return_value=123)

        with mock.patch.object(safety, "HAS_SECURE_DIR_FD", False), mock.patch.object(
            safety, "secure_mkdir"
        ), mock.patch.object(safety.os, "O_BINARY", binary_flag, create=True), mock.patch.object(
            safety.os, "O_NOINHERIT", noinherit_flag, create=True
        ), mock.patch.object(safety.os, "open", write_open), mock.patch.object(
            safety.os, "write", side_effect=lambda descriptor, data: len(data)
        ), mock.patch.object(safety.os, "close"), mock.patch.object(
            safety.os, "chmod"
        ):
            safety.secure_write(self.base / "binary-output.json", b"a\nb\n")

        write_flags = write_open.call_args.args[1]
        self.assertTrue(write_flags & binary_flag)
        self.assertTrue(write_flags & noinherit_flag)

        info = SimpleNamespace(
            st_mode=0o100600,
            st_nlink=1,
            st_size=4,
            st_mtime_ns=44,
            st_ino=22,
        )
        hash_open = mock.Mock(return_value=124)
        with mock.patch.object(safety.os, "O_BINARY", binary_flag, create=True), mock.patch.object(
            safety.os, "O_NOINHERIT", noinherit_flag, create=True
        ), mock.patch.object(safety.os, "open", hash_open), mock.patch.object(
            safety.os, "fstat", side_effect=[info, info]
        ), mock.patch.object(safety.os, "read", side_effect=[b"a\nb\n", b""]), mock.patch.object(
            safety.os, "close"
        ):
            safety.sha256_file(self.base / "binary-output.json")

        hash_flags = hash_open.call_args.args[1]
        self.assertTrue(hash_flags & binary_flag)
        self.assertTrue(hash_flags & noinherit_flag)

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
