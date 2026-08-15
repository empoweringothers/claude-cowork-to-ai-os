from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

from cowork_ai_os.capture import capture_sessions
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.safety import SafetyError
from cowork_ai_os.scaffold import scaffold_ai_os


class CaptureScaffoldRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def add_session(
        self,
        account: str,
        workspace: str,
        raw_id: str,
        project: str = "Same display title",
        message: str = "SYNTHETIC_ALPHA",
        with_workspace_spaces: bool = True,
    ) -> Path:
        root = self.source / account / workspace
        session = root / raw_id
        session.mkdir(parents=True)
        transcript = session / "transcript.jsonl"
        transcript.write_text(
            json.dumps({"role": "user", "content": message}) + "\n",
            encoding="utf-8",
        )
        (root / ("local_" + raw_id + ".json")).write_text(
            json.dumps(
                {
                    "id": raw_id,
                    "title": "Synthetic session",
                    "projectName": project,
                    "spaceId": "space-" + raw_id,
                    "transcriptPath": raw_id + "/transcript.jsonl",
                }
            ),
            encoding="utf-8",
        )
        if with_workspace_spaces:
            (root / "spaces.json").write_text(
                json.dumps(
                    {
                        "spaces": [
                            {
                                "id": "space-" + raw_id,
                                "name": project,
                                "instructions": "Workspace-local synthetic instructions",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
        return session

    def apply_capture(self, output: Path, selectors=None) -> Path:
        records = discover_sessions(self.source).sessions
        chosen = selectors or [record.safe_id for record in records]
        preview = capture_sessions(self.source, chosen, output, apply=False)
        capture_sessions(
            self.source,
            chosen,
            output,
            apply=True,
            approved_plan=preview["approval_token"],
        )
        return output

    def test_same_size_transcript_change_invalidates_preview(self) -> None:
        session = self.add_session("account-a", "workspace-a", "session-a")
        record = discover_sessions(self.source).sessions[0]
        output = self.base / "capture"
        preview = capture_sessions(
            self.source, [record.safe_id], output, apply=False
        )
        transcript = session / "transcript.jsonl"
        before = transcript.read_text(encoding="utf-8")
        transcript.write_text(
            before.replace("SYNTHETIC_ALPHA", "SYNTHETIC_BRAVO"), encoding="utf-8"
        )
        self.assertEqual(len(before), len(transcript.read_text(encoding="utf-8")))
        with self.assertRaises(SafetyError):
            capture_sessions(
                self.source,
                [record.safe_id],
                output,
                apply=True,
                approved_plan=preview["approval_token"],
            )
        self.assertFalse(output.exists())

    def test_account_level_spaces_file_is_never_used(self) -> None:
        self.add_session(
            "account-a", "workspace-a", "session-a", with_workspace_spaces=False
        )
        account_spaces = self.source / "account-a" / "spaces.json"
        account_spaces.write_text(
            json.dumps(
                {
                    "spaces": [
                        {
                            "id": "space-session-a",
                            "name": "Wrong sibling scope",
                            "instructions": "UPWARD_SPACE_SCOPE_CANARY",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        output = self.apply_capture(self.base / "capture")
        exported = b"\n".join(
            path.read_bytes() for path in output.rglob("*") if path.is_file()
        )
        self.assertNotIn(b"UPWARD_SPACE_SCOPE_CANARY", exported)

    def test_duplicate_workspace_space_ids_skip_both_instruction_bodies(self) -> None:
        self.add_session("account-a", "workspace-a", "session-a")
        spaces_path = self.source / "account-a" / "workspace-a" / "spaces.json"
        spaces_path.write_text(
            json.dumps(
                {
                    "spaces": [
                        {
                            "id": "space-session-a",
                            "instructions": "DUPLICATE_SPACE_FIRST_CANARY",
                        },
                        {
                            "id": "space-session-a",
                            "instructions": "DUPLICATE_SPACE_SECOND_CANARY",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        output = self.apply_capture(self.base / "capture")
        exported = b"\n".join(
            path.read_bytes() for path in output.rglob("*") if path.is_file()
        )
        self.assertNotIn(b"DUPLICATE_SPACE_FIRST_CANARY", exported)
        self.assertNotIn(b"DUPLICATE_SPACE_SECOND_CANARY", exported)
        self.assertFalse(list(output.rglob("space-instructions.md")))

    def test_unknown_extension_utf8_artifact_is_sanitized(self) -> None:
        session = self.add_session("account-a", "workspace-a", "session-a")
        uploads = session / "uploads"
        uploads.mkdir()
        (uploads / "note.custom").write_text(
            "CUSTOM_TEXT_ARTIFACT_CANARY", encoding="utf-8"
        )
        output = self.apply_capture(self.base / "capture")
        imported = [
            path
            for path in output.rglob("*.imported.md")
            if "uploads" in path.parts
        ]
        self.assertEqual(len(imported), 1)
        self.assertIn(
            "CUSTOM\\_TEXT\\_ARTIFACT\\_CANARY", imported[0].read_text()
        )

    def test_scaffold_rejects_destination_inside_original_source(self) -> None:
        self.add_session("account-a", "workspace-a", "session-a")
        capture = self.apply_capture(self.base / "capture")
        with self.assertRaises(SafetyError):
            scaffold_ai_os(
                capture,
                self.source / "AI-OS",
                profile="personal",
                apply=False,
            )
        self.assertFalse((self.source / "AI-OS").exists())

    def test_same_label_different_workspaces_get_separate_indexes(self) -> None:
        self.add_session("account-a", "workspace-a", "session-a")
        self.add_session("account-b", "workspace-b", "session-b")
        capture = self.apply_capture(self.base / "capture")
        output = self.base / "AI-OS"
        preview = scaffold_ai_os(
            capture, output, profile="personal", apply=False
        )
        scaffold_ai_os(
            capture,
            output,
            profile="personal",
            apply=True,
            approved_plan=preview["approval_token"],
        )
        indexes = list(
            (output / "Projects" / "Cowork-Import").glob(
                "index-????????????????/README.md"
            )
        )
        self.assertEqual(len(indexes), 2)

    def test_known_short_hash_collision_cannot_overwrite_project_index(self) -> None:
        for raw_id in ("session-28183", "session-30342"):
            self.add_session("account", "workspace", raw_id)
            metadata_path = (
                self.source
                / "account"
                / "workspace"
                / ("local_" + raw_id + ".json")
            )
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata.pop("spaceId", None)
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        capture = self.apply_capture(self.base / "capture")
        output = self.base / "AI-OS"
        preview = scaffold_ai_os(capture, output, profile="personal", apply=False)
        scaffold_ai_os(
            capture,
            output,
            profile="personal",
            apply=True,
            approved_plan=preview["approval_token"],
        )
        indexes = list(
            (output / "Projects" / "Cowork-Import").glob("index-*/README.md")
        )
        self.assertEqual(len(indexes), 2)
        indexed = "\n".join(path.read_text(encoding="utf-8") for path in indexes)
        for session_id in json.loads(
            (capture / "manifest.json").read_text(encoding="utf-8")
        )["session_ids"]:
            self.assertIn(session_id, indexed)


if __name__ == "__main__":
    unittest.main()
