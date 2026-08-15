from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))
sys.path.insert(0, str(REPO / "scripts"))

from cowork_ai_os.capture import CaptureLimits, capture_sessions
from cowork_ai_os.cli import _html_inventory, _markdown_inventory, main
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.doctor import default_cowork_roots, doctor_report
from cowork_ai_os.safety import SafetyError, safe_component
from cowork_ai_os.scaffold import REQUIRED_DIRECTORIES, scaffold_ai_os
from cowork_ai_os.verify import verify_tree
from build_release import include as release_include
from build_release import validate_release_url


class SyntheticCoworkCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "cowork-source"
        self.workspace = self.source / "account-a" / "workspace-a"
        self.workspace.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def add_session(
        self,
        raw_id: str = "session-alpha",
        title: str = "Synthetic planning chat",
        project: str = "Explicit Project",
        transcript_lines=None,
        transcript_name: str = "transcript.jsonl",
        space_id: str = "space-1",
    ):
        session_dir = self.workspace / raw_id
        session_dir.mkdir()
        transcript = session_dir / transcript_name
        lines = transcript_lines or [
            {"role": "user", "content": "Please summarize the synthetic plan."},
            {"role": "assistant", "content": [{"type": "text", "text": "Synthetic summary."}]},
        ]
        transcript.write_text(
            "\n".join(item if isinstance(item, str) else json.dumps(item) for item in lines) + "\n",
            encoding="utf-8",
        )
        metadata = {
            "id": raw_id,
            "title": title,
            "projectName": project,
            "spaceId": space_id,
            "spaceName": "Synthetic Space",
            "createdAt": "2026-01-02T03:04:05Z",
            "updatedAt": "2026-01-03T03:04:05Z",
            "messageCount": 2,
            "selectedFolders": ["/private/example/Chosen Folder"],
            "transcriptPath": "{}/{}".format(raw_id, transcript_name),
        }
        metadata_path = self.workspace / ("local_" + raw_id + ".json")
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        spaces = {
            "spaces": [
                {
                    "id": "space-1",
                    "name": "Space from spaces.json",
                    "instructions": "Use synthetic references only; token=sk-test-canary-1234567890",
                },
                {"id": "space-other", "name": "Unselected", "instructions": "DO NOT IMPORT THIS BODY"},
            ]
        }
        (self.workspace / "spaces.json").write_text(json.dumps(spaces), encoding="utf-8")
        return metadata_path, transcript, session_dir

    def inventory(self):
        return discover_sessions(self.source)

    def capture(self, output_name: str = "capture"):
        inventory = self.inventory()
        output = self.base / output_name
        preview = capture_sessions(
            self.source, [inventory.sessions[0].safe_id], output, apply=False
        )
        result = capture_sessions(
            self.source,
            [inventory.sessions[0].safe_id],
            output,
            apply=True,
            approved_plan=preview["approval_token"],
        )
        return output, result, inventory.sessions[0]

    def snapshot_source(self):
        result = {}
        for path in sorted(self.source.rglob("*")):
            if path.is_file() and not path.is_symlink():
                result[path.relative_to(self.source).as_posix()] = (
                    path.stat().st_mtime_ns,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
        return result


class InventoryTests(SyntheticCoworkCase):
    def test_inventory_is_agent_safe_and_does_not_open_spaces_or_bodies(self):
        self.add_session()
        import cowork_ai_os.discovery as discovery

        opened = []
        original = discovery.read_regular_bytes

        def tracking(path, root, max_bytes):
            opened.append(Path(path).name)
            return original(path, root, max_bytes)

        with mock.patch.object(discovery, "read_regular_bytes", side_effect=tracking):
            inventory = self.inventory()
        self.assertEqual(opened, ["local_session-alpha.json"])
        safe = inventory.agent_safe_dict()
        self.assertTrue(safe["agent_safe"])
        self.assertIsNone(safe["sessions"][0]["space"]["has_instructions"])
        rendered = json.dumps(safe)
        self.assertNotIn("Use synthetic", rendered)
        self.assertNotIn(str(self.source), rendered)
        self.assertEqual(safe["sessions"][0]["selected_folders"], ["Chosen Folder"])

    def test_inventory_markdown_neutralizes_untrusted_metadata(self):
        malicious = '<script>alert(1)</script> ![x](javascript:alert(1)) [link](file:///x)'
        self.add_session(title=malicious, project=malicious)
        report = _markdown_inventory(self.inventory())
        self.assertNotIn("<script>", report)
        self.assertNotIn("![x](", report)
        self.assertNotIn("[link](", report)
        self.assertIn("Untrusted metadata title", report)
        self.assertIn("instruction fields were not consulted or emitted", report)
        self.assertIn("Standalone transcript, spaces registry, memory, upload, and output files were not opened", report)

    def test_inventory_html_is_standalone_escaped_and_offline(self):
        self.add_session(title="<script>bad()</script>")
        report = _html_inventory(self.inventory())
        self.assertTrue(report.startswith("<!doctype html>"))
        self.assertIn("Content-Security-Policy", report)
        self.assertNotIn("<script>bad", report)
        self.assertNotIn("src=\"http", report)

    def test_native_transcript_beats_audit_fallback(self):
        _, _, session_dir = self.add_session()
        (session_dir / "audit.jsonl").write_text('{"role":"user","content":"audit"}\n', encoding="utf-8")
        record = self.inventory().sessions[0]
        self.assertEqual(record.transcript_kind, "native")
        self.assertEqual(record.transcript_path.name, "transcript.jsonl")

    def test_realistic_cli_session_id_nested_jsonl_is_discovered(self):
        raw_id = "task-native-001"
        cli_id = "cli-session-001"
        session_dir = self.workspace / ("local_" + raw_id)
        transcript_dir = session_dir / ".claude" / "projects" / "-synthetic-project"
        transcript_dir.mkdir(parents=True)
        transcript = transcript_dir / (cli_id + ".jsonl")
        transcript.write_text(
            json.dumps({"role": "user", "content": "nested native transcript"}) + "\n",
            encoding="utf-8",
        )
        metadata = {
            "id": raw_id,
            "cliSessionId": cli_id,
            "title": "Nested native",
        }
        (self.workspace / ("local_" + raw_id + ".json")).write_text(
            json.dumps(metadata), encoding="utf-8"
        )

        record = self.inventory().sessions[0]
        self.assertEqual(record.transcript_kind, "native")
        self.assertEqual(record.transcript_path.resolve(), transcript.resolve())

    def test_unassociated_transcript_hint_cannot_redirect_to_another_session(self):
        other = self.workspace / "other-session"
        other.mkdir()
        (other / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "must not be selected"}) + "\n",
            encoding="utf-8",
        )
        metadata = {
            "id": "selected-session",
            "title": "Selected",
            "transcriptPath": "other-session/transcript.jsonl",
        }
        (self.workspace / "local_selected-session.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )

        record = self.inventory().sessions[0]
        self.assertIsNone(record.transcript_path)

    def test_nested_subagent_transcript_is_never_selected(self):
        _, parent, session_dir = self.add_session()
        subagent = session_dir / "subagents" / "agent-a"
        subagent.mkdir(parents=True)
        (subagent / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "SUBAGENT_BODY_MUST_NOT_EXPORT"}) + "\n",
            encoding="utf-8",
        )

        record = self.inventory().sessions[0]
        self.assertEqual(record.transcript_path.resolve(), parent.resolve())
        output, _, _ = self.capture()
        exported = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in output.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("SUBAGENT_BODY_MUST_NOT_EXPORT", exported)

    def test_equal_priority_transcript_candidates_fail_closed(self):
        _, _, session_dir = self.add_session()
        (session_dir / "conversation.jsonl").write_text(
            json.dumps({"role": "user", "content": "ambiguous second transcript"}) + "\n",
            encoding="utf-8",
        )
        inventory = self.inventory()
        self.assertIsNone(inventory.sessions[0].transcript_path)
        self.assertTrue(any("ambiguous transcript" in item for item in inventory.warnings))

    def test_malformed_metadata_is_reported_without_crashing(self):
        raw_name = "local_RAW-SESSION-ID-CANARY.json"
        (self.workspace / raw_name).write_text("{not-json", encoding="utf-8")
        inventory = self.inventory()
        self.assertEqual(inventory.sessions, [])
        self.assertTrue(any("malformed metadata" in item for item in inventory.warnings))
        self.assertNotIn("RAW-SESSION-ID-CANARY", json.dumps(inventory.agent_safe_dict()))


class CaptureTests(SyntheticCoworkCase):
    def test_dry_run_has_zero_writes_and_does_not_read_transcript_or_spaces(self):
        self.add_session()
        before = self.snapshot_source()
        inventory = self.inventory()
        output = self.base / "dry-output"
        import cowork_ai_os.capture as capture_module

        original = capture_module.read_regular_bytes
        opened = []

        def tracking(path, root, max_bytes):
            opened.append(Path(path).name)
            return original(path, root, max_bytes)

        with mock.patch.object(capture_module, "read_regular_bytes", side_effect=tracking):
            result = capture_sessions(self.source, [inventory.sessions[0].safe_id[:8]], output, apply=False)
        self.assertEqual(result["mode"], "dry-run")
        self.assertFalse(output.exists())
        self.assertEqual(opened, [])
        self.assertEqual(before, self.snapshot_source())

    def test_apply_requires_matching_preview_token(self):
        self.add_session()
        session_id = self.inventory().sessions[0].safe_id
        output = self.base / "approval-required"
        with self.assertRaises(SafetyError):
            capture_sessions(self.source, [session_id], output, apply=True)
        self.assertFalse(output.exists())
        preview = capture_sessions(self.source, [session_id], output, apply=False)
        with self.assertRaises(SafetyError):
            capture_sessions(
                self.source,
                [session_id],
                output,
                apply=True,
                approved_plan="0" * 64,
            )
        self.assertFalse(output.exists())
        self.assertRegex(preview["approval_token"], r"^[0-9a-f]{64}$")

    def test_apply_sanitizes_chat_instructions_and_text_artifacts(self):
        canary = "sk-test-canary-1234567890"
        lines = [
            {"role": "user", "content": "secret " + canary + " <script>x</script> ![x](file:///x)", "systemPrompt": "RAW_SYSTEM_PROMPT"},
            {"role": "assistant", "content": [{"type": "tool_use", "input": {"password": "TOOL_SECRET"}}, {"type": "text", "text": "safe response"}]},
            {"role": "tool", "content": "RAW_TOOL_RESULT"},
        ]
        _, _, session_dir = self.add_session(transcript_lines=lines)
        (session_dir / "memory").mkdir()
        (session_dir / "memory" / "note.md").write_text("password=" + canary, encoding="utf-8")
        (session_dir / "outputs").mkdir()
        (session_dir / "outputs" / "report.txt").write_text("api_key=" + canary, encoding="utf-8")
        before = self.snapshot_source()
        output, result, record = self.capture()
        all_text = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore") for path in output.rglob("*") if path.is_file()
        )
        self.assertNotIn(canary, all_text)
        self.assertNotIn("RAW_SYSTEM_PROMPT", all_text)
        self.assertNotIn("TOOL_SECRET", all_text)
        self.assertNotIn("RAW_TOOL_RESULT", all_text)
        self.assertNotIn("<script>", (output / "sessions" / record.safe_id / "chat.md").read_text())
        self.assertNotIn("![x](", (output / "sessions" / record.safe_id / "chat.md").read_text())
        self.assertIn("REDACTED:SECRET", all_text)
        self.assertIn("Space Instructions", all_text)
        self.assertIn("Message 0001", all_text)
        self.assertEqual(before, self.snapshot_source())
        self.assertTrue(verify_tree(output)["ok"])

    def test_malformed_jsonl_is_skipped_but_valid_messages_survive(self):
        self.add_session(transcript_lines=["not json", {"role": "user", "content": "valid synthetic text"}])
        output, result, record = self.capture()
        chat = (output / "sessions" / record.safe_id / "chat.md").read_text()
        self.assertIn("valid synthetic text", chat)
        self.assertTrue(any("malformed transcript" in warning for warning in result["warnings"]))

    def test_symlink_escape_and_special_files_are_skipped(self):
        _, _, session_dir = self.add_session()
        uploads = session_dir / "uploads"
        uploads.mkdir()
        outside = self.base / "outside.txt"
        outside.write_text("OUTSIDE_CANARY", encoding="utf-8")
        try:
            (uploads / "escape.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        try:
            os.link(outside, uploads / "hardlink.txt")
        except (OSError, NotImplementedError):
            pass
        if hasattr(os, "mkfifo"):
            os.mkfifo(uploads / "special.txt")
        output, result, _ = self.capture()
        exported = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
        self.assertNotIn(b"OUTSIDE_CANARY", exported)
        self.assertTrue(
            any(
                "symlink" in warning or "special file" in warning or "hard-linked" in warning
                for warning in result["warnings"]
            )
        )

    def test_credential_bearing_names_fail_closed(self):
        _, _, session_dir = self.add_session()
        outputs = session_dir / "outputs"
        outputs.mkdir()
        names = [
            ".env",
            ".env.production",
            ".npmrc",
            ".pypirc",
            ".netrc",
            "_netrc",
            ".mcp.json",
            "id_rsa",
            "cert.pem",
            "store.p12",
            "vault.kdbx",
            ".credentials.json",
            "buddy-tokens.json",
            "buddy_tokens.json",
            "oauth.json",
            "auth.json",
        ]
        for name in names:
            (outputs / name).write_text("CREDENTIAL_FILE_CANARY", encoding="utf-8")
        output, _, _ = self.capture()
        exported = b"\n".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
        self.assertNotIn(b"CREDENTIAL_FILE_CANARY", exported)

    def test_quoted_json_secret_values_are_redacted(self):
        _, _, session_dir = self.add_session()
        outputs = session_dir / "outputs"
        outputs.mkdir()
        value = "synthetic-oauth-value-123456"
        (outputs / "settings.json").write_text(
            json.dumps({"access_token": value, "safe": "kept"}), encoding="utf-8"
        )
        output, _, _ = self.capture()
        rendered = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in output.rglob("*")
            if path.is_file()
        )
        self.assertNotIn(value, rendered)
        self.assertIn("REDACTED:SECRET", rendered)

    def test_path_overlap_and_existing_destinations_are_rejected(self):
        self.add_session()
        session_id = self.inventory().sessions[0].safe_id
        with self.assertRaises(SafetyError):
            capture_sessions(self.source, [session_id], self.source / "export", apply=False)
        existing = self.base / "existing"
        existing.mkdir()
        with self.assertRaises(SafetyError):
            capture_sessions(self.source, [session_id], existing, apply=True)

    def test_output_permissions_are_owner_only(self):
        self.add_session()
        output, _, _ = self.capture()
        if os.name == "nt":
            self.skipTest("POSIX mode bits unavailable")
        for path in [output] + list(output.rglob("*")):
            mode = stat.S_IMODE(path.lstat().st_mode)
            self.assertEqual(mode, 0o700 if path.is_dir() else 0o600, str(path))

    def test_binary_manifest_marks_limited_scan_and_human_review(self):
        _, _, session_dir = self.add_session()
        uploads = session_dir / "uploads"
        uploads.mkdir()
        (uploads / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00synthetic")
        output, result, _ = self.capture()
        manifest = json.loads((output / "manifest.json").read_text())
        binary = next(
            entry
            for entry in manifest["files"]
            if entry["provenance"]["kind"] == "allowlisted-binary-upload"
        )
        self.assertEqual(binary["provenance"]["binary_scan"], "limited")
        self.assertTrue(binary["provenance"]["requires_human_review"])
        self.assertTrue(any("human review" in item for item in manifest["warnings"]))

    def test_mismatched_file_contents_fail_closed_or_receive_markdown_extension(self):
        _, _, session_dir = self.add_session()
        uploads = session_dir / "uploads"
        uploads.mkdir()
        (uploads / "actually-text.png").write_text("plain synthetic text", encoding="utf-8")
        (uploads / "actually-binary.txt").write_bytes(b"\x00\xff\x00synthetic")
        output, result, _ = self.capture()
        public_manifest = (output / "manifest.json").read_text()
        private_manifest = (output / ".private" / "provenance.json").read_text()
        self.assertNotIn("actually-text.png", public_manifest)
        self.assertNotIn("actually-binary.txt", public_manifest)
        self.assertIn("actually-text.png", private_manifest)
        self.assertNotIn("actually-binary.txt", private_manifest)
        self.assertTrue(any("did not match its allowed text type" in item for item in result["warnings"]))

    def test_private_manifest_uses_only_source_relative_paths(self):
        self.add_session()
        output, _, _ = self.capture()
        private_path = output / ".private" / "provenance.json"
        private = private_path.read_text()
        shareable = (output / "manifest.json").read_text()
        self.assertNotIn(str(self.source), private)
        self.assertNotIn(str(self.source), shareable)
        self.assertIn("account-a/workspace-a/local_session-alpha.json", private)
        self.assertNotIn("Synthetic planning chat", shareable)
        self.assertNotIn("Explicit Project", shareable)
        self.assertNotIn("source_sha256", shareable)
        self.assertIn("Synthetic planning chat", private)
        self.assertIn("Explicit Project", private)

    def test_artifact_limits_apply_globally_across_selected_sessions(self):
        _, _, first_dir = self.add_session(raw_id="session-first")
        _, _, second_dir = self.add_session(raw_id="session-second")
        for directory, value in ((first_dir, "first"), (second_dir, "second")):
            (directory / "outputs").mkdir()
            (directory / "outputs" / (value + ".txt")).write_text(value, encoding="utf-8")
        inventory = self.inventory()
        output = self.base / "global-limit"
        preview = capture_sessions(
            self.source,
            [record.safe_id for record in inventory.sessions],
            output,
            apply=False,
            limits=CaptureLimits(max_files=1),
        )
        result = capture_sessions(
            self.source,
            [record.safe_id for record in inventory.sessions],
            output,
            apply=True,
            limits=CaptureLimits(max_files=1),
            approved_plan=preview["approval_token"],
        )
        manifest = json.loads((output / "manifest.json").read_text())
        artifacts = [
            entry
            for entry in manifest["files"]
            if entry["provenance"]["kind"].startswith("sanitized-output")
        ]
        self.assertEqual(len(artifacts), 1)
        self.assertTrue(any("Global artifact file-count limit" in item for item in result["warnings"]))


class VerifyAndScaffoldTests(SyntheticCoworkCase):
    def test_unmanifested_capture_file_is_rejected_and_not_scaffolded(self):
        self.add_session()
        capture, _, record = self.capture()
        injected = capture / "sessions" / record.safe_id / "CLAUDE.md"
        injected.write_text("UNMANIFESTED_PROMPT_INJECTION", encoding="utf-8")
        if os.name != "nt":
            os.chmod(injected, 0o600)
        verification = verify_tree(capture)
        self.assertFalse(verification["ok"])
        self.assertTrue(any("Unmanifested file" in item for item in verification["errors"]))
        with self.assertRaises(SafetyError):
            scaffold_ai_os(capture, self.base / "blocked-ai-os", profile="personal", apply=True)

    def test_verify_detects_hash_tamper_secret_symlink_and_permissions(self):
        self.add_session()
        output, _, record = self.capture()
        chat = output / "sessions" / record.safe_id / "chat.md"
        chat.write_text(chat.read_text() + "\napi_key=sk-test-canary-1234567890\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(chat, 0o644)
        try:
            (output / "escape").symlink_to(self.base / "outside")
        except (OSError, NotImplementedError):
            pass
        result = verify_tree(output)
        self.assertFalse(result["ok"])
        joined = "\n".join(result["errors"])
        self.assertIn("Hash mismatch", joined)
        self.assertIn("Likely secret", joined)
        if os.name != "nt":
            self.assertIn("permissions", joined)

    def test_scaffold_dry_run_and_apply_route_private_and_make_project_index(self):
        _, _, session_dir = self.add_session()
        for folder, filename in (
            ("memory", "memory-note.md"),
            ("uploads", "brief.txt"),
            ("outputs", "result.txt"),
        ):
            (session_dir / folder).mkdir()
            (session_dir / folder / filename).write_text(
                "synthetic " + folder, encoding="utf-8"
            )
        capture, _, _ = self.capture()
        dry_output = self.base / "ai-os-dry"
        dry = scaffold_ai_os(capture, dry_output, profile="personal", apply=False)
        self.assertEqual(dry["mode"], "dry-run")
        self.assertFalse(dry_output.exists())
        with self.assertRaises(SafetyError):
            scaffold_ai_os(capture, dry_output, profile="personal", apply=True)
        self.assertFalse(dry_output.exists())

        output = self.base / "ai-os"
        approved_preview = scaffold_ai_os(
            capture, output, profile="personal", apply=False
        )
        scaffold_ai_os(
            capture,
            output,
            profile="personal",
            apply=True,
            approved_plan=approved_preview["approval_token"],
        )
        for relative in REQUIRED_DIRECTORIES:
            self.assertTrue(output.joinpath(*relative.split("/")).is_dir())
        self.assertTrue((output / "Inbox" / "Cowork-Import" / "manifest.json").is_file())
        self.assertFalse((output / "Inbox" / "Cowork-Import" / ".private").exists())
        self.assertTrue((output / ".ai-os" / "private" / "Cowork-Import" / "provenance.json").is_file())
        self.assertIn("Inbox/Cowork-Import/", (output / ".gitignore").read_text())
        self.assertIn("Projects/Cowork-Import/", (output / ".gitignore").read_text())
        self.assertIn("Type: `personal`", (output / "PRIVACY.md").read_text())
        self.assertNotIn("{{PROFILE}}", (output / "PRIVACY.md").read_text())
        indexes = list(
            (output / "Projects" / "Cowork-Import").glob(
                "index-????????????????/README.md"
            )
        )
        self.assertEqual(len(indexes), 1)
        index_text = indexes[0].read_text()
        self.assertIn("does not establish current state", index_text)
        readable_index = index_text.replace("\\", "")
        for expected in (
            "Conversation",
            "Space instructions",
            "memory-note.md",
            "brief.txt",
            "result.txt",
        ):
            self.assertIn(expected, readable_index)
        self.assertTrue(verify_tree(output)["ok"])

        review = output / "Inbox" / "REVIEW.md"
        review.write_text(
            review.read_text()
            + "\n## Candidate 1\n\n- Status: `review`\n- Candidate statement: Synthetic.\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            os.chmod(review, 0o600)
        reviewed_verification = verify_tree(output)
        self.assertTrue(reviewed_verification["ok"])
        self.assertEqual(reviewed_verification["review_entry_count"], 1)
        self.assertEqual(reviewed_verification["unreviewed_candidate_count"], 1)


class CliSafetyTests(SyntheticCoworkCase):
    def test_doctor_defaults_only_use_supported_session_root_names(self):
        for system in ("Darwin", "Windows", "Linux"):
            roots = default_cowork_roots(
                home=Path("/synthetic-home"),
                platform_name=system,
                environ={"APPDATA": "C:\\Synthetic\\Roaming", "LOCALAPPDATA": "C:\\Synthetic\\Local"},
            )
            self.assertTrue(roots)
            self.assertTrue(all(path.name == "local-agent-mode-sessions" for path in roots))

    def test_doctor_agent_safe_hides_full_paths(self):
        sensitive = self.base / "very-private" / "cowork-root"
        sensitive.mkdir(parents=True)
        report = doctor_report([sensitive], agent_safe=True)
        rendered = json.dumps(report)
        self.assertNotIn(str(sensitive), rendered)
        self.assertEqual(report["roots"][0]["basename"], "cowork-root")
        self.assertNotIn("path", report["roots"][0])

    def test_doctor_rejects_an_empty_or_unrecognized_directory(self):
        empty = self.base / "empty-root"
        empty.mkdir()
        report = doctor_report([empty], agent_safe=True)
        self.assertFalse(report["roots"][0]["usable"])
        self.assertEqual(report["roots"][0]["layout"], "no-session-metadata")

        (empty / "local_synthetic.json").write_text("{}", encoding="utf-8")
        report = doctor_report([empty], agent_safe=True)
        self.assertFalse(report["roots"][0]["usable"])
        self.assertEqual(report["roots"][0]["layout"], "no-session-metadata")

    def test_report_outputs_cannot_overlap_inspected_roots(self):
        self.add_session()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["inventory", "--source", str(self.source), "--output", str(self.source / "report.json")])
        self.assertEqual(code, 2)
        self.assertFalse((self.source / "report.json").exists())

        capture, _, _ = self.capture()
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["verify", str(capture), "--output", str(capture / "verify.json")])
        self.assertEqual(code, 2)
        self.assertFalse((capture / "verify.json").exists())

        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["doctor", "--source", str(self.source), "--output", str(self.source / "doctor.md")])
        self.assertEqual(code, 2)
        self.assertFalse((self.source / "doctor.md").exists())

    def test_protected_browser_store_source_is_rejected(self):
        protected = self.base / "IndexedDB"
        protected.mkdir()
        with self.assertRaises(SafetyError):
            discover_sessions(protected)

    def test_windows_reserved_device_names_are_neutralized(self):
        self.assertEqual(safe_component("CON.txt"), "_CON.txt")
        self.assertEqual(safe_component("lpt9.log"), "_lpt9.log")


class ReleaseSafetyTests(unittest.TestCase):
    def test_release_url_is_publisher_and_tag_pinned(self):
        validate_release_url(
            "https://github.com/empoweringothers/claude-cowork-to-ai-os/releases/tag/v0.1.0",
            "v0.1.0",
        )
        rejected = (
            "https://github.com/attacker/lookalike/releases/tag/v0.1.0",
            "https://" + "user" + "@" + "github.com/empoweringothers/claude-cowork-to-ai-os/releases/tag/v0.1.0",
            "https://github.com/empoweringothers/claude-cowork-to-ai-os/releases/tag/v0.1.0?x=1",
            "https://github.com/empoweringothers/claude-cowork-to-ai-os/releases/tag/v0.1.0#fragment",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_release_url(url, "v0.1.0")

    def test_release_filter_excludes_generated_private_roots(self):
        self.assertFalse(release_include(Path("captures/private/secret.txt")))
        self.assertFalse(release_include(Path("AI-OS/.ai-os/private/provenance.json")))
        self.assertFalse(release_include(Path("exports/capture.zip")))
        self.assertTrue(
            release_include(Path("plugins/cowork-ai-os/templates/ai-os/.gitignore"))
        )


if __name__ == "__main__":
    unittest.main()
