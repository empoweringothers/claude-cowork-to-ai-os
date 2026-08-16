from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

from cowork_ai_os.discovery import discover_sessions


class DiscoveryScopeRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "cowork-source"
        self.workspace = self.source / "account-a" / "workspace-a"
        self.workspace.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_metadata(self, filename: str, data: dict) -> Path:
        path = self.workspace / filename
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def only_record(self):
        inventory = discover_sessions(self.source)
        self.assertEqual(len(inventory.sessions), 1, inventory.warnings)
        return inventory.sessions[0]

    def test_fuzzy_substring_directory_does_not_supply_transcript(self) -> None:
        self.write_metadata(
            "local_session-primary.json",
            {"id": "session-primary", "title": "Selected session"},
        )
        decoy = self.workspace / "archive-session-primary-copy"
        decoy.mkdir()
        (decoy / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "wrong session"}) + "\n",
            encoding="utf-8",
        )

        record = self.only_record()

        self.assertIsNone(record.transcript_path)
        self.assertEqual(record.transcript_bytes, 0)

    def test_subagent_hint_cannot_create_transcript_or_artifact_roots(self) -> None:
        relative = Path("host-session/subagents/agent-leak")
        self.write_metadata(
            "local_agent-leak.json",
            {
                "id": "agent-leak",
                "title": "Parent metadata",
                "transcriptPath": (relative / "transcript.jsonl").as_posix(),
            },
        )
        subagent = self.workspace / relative
        (subagent / "uploads").mkdir(parents=True)
        (subagent / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "subagent-only"}) + "\n",
            encoding="utf-8",
        )
        (subagent / "uploads" / "subagent-only.txt").write_text(
            "must not be counted", encoding="utf-8"
        )

        record = self.only_record()

        self.assertIsNone(record.transcript_path)
        self.assertEqual(record.artifact_roots["uploads"], [])
        self.assertEqual(record.artifact_stats["uploads"]["files"], 0)

    def test_nested_selected_token_under_other_session_is_not_an_association(self) -> None:
        relative = Path("other-session/selected-session")
        self.write_metadata(
            "local_selected-session.json",
            {
                "id": "selected-session",
                "title": "Selected metadata",
                "transcriptPath": (relative / "transcript.jsonl").as_posix(),
            },
        )
        decoy = self.workspace / relative
        (decoy / "uploads").mkdir(parents=True)
        (decoy / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "UNSELECTEDBODYCANARY"})
            + "\n",
            encoding="utf-8",
        )
        (decoy / "uploads" / "unselected.txt").write_text(
            "UNSELECTEDUPLOADCANARY", encoding="utf-8"
        )

        record = self.only_record()

        self.assertIsNone(record.transcript_path)
        self.assertEqual(record.artifact_roots["uploads"], [])
        self.assertEqual(record.artifact_stats["uploads"]["files"], 0)

    def test_cli_session_id_cannot_name_a_sibling_session_root(self) -> None:
        self.write_metadata(
            "local_selected-session.json",
            {
                "id": "selected-session",
                "cliSessionId": "other-session",
                "title": "Selected metadata",
                "transcriptPath": "other-session/transcript.jsonl",
            },
        )
        sibling = self.workspace / "other-session"
        (sibling / "uploads").mkdir(parents=True)
        (sibling / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "SIBLINGBODYCANARY"})
            + "\n",
            encoding="utf-8",
        )
        (sibling / "uploads" / "sibling.txt").write_text(
            "SIBLINGUPLOADCANARY", encoding="utf-8"
        )

        record = self.only_record()

        self.assertIsNone(record.transcript_path)
        self.assertEqual(record.artifact_roots["uploads"], [])

    def test_workspace_artifacts_are_not_attached_to_a_session(self) -> None:
        self.write_metadata(
            "local_session-one.json",
            {"id": "session-one", "title": "Session one"},
        )
        session = self.workspace / "session-one"
        (session / "uploads").mkdir(parents=True)
        (session / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "selected"}) + "\n",
            encoding="utf-8",
        )
        (session / "uploads" / "selected.txt").write_text(
            "selected upload", encoding="utf-8"
        )
        (self.workspace / "uploads").mkdir()
        (self.workspace / "uploads" / "workspace-only.txt").write_text(
            "must not be counted", encoding="utf-8"
        )

        record = self.only_record()

        self.assertEqual(
            record.transcript_path.resolve(), (session / "transcript.jsonl").resolve()
        )
        self.assertEqual(
            [path.resolve() for path in record.artifact_roots["uploads"]],
            [(session / "uploads").resolve()],
        )
        self.assertEqual(record.artifact_stats["uploads"]["files"], 1)

    def test_exact_direct_session_directory_still_resolves(self) -> None:
        self.write_metadata(
            "local_session-exact.json",
            {"id": "session-exact", "title": "Exact session"},
        )
        session = self.workspace / "session-exact"
        session.mkdir()
        transcript = session / "transcript.jsonl"
        transcript.write_text(
            json.dumps({"role": "user", "content": "exact"}) + "\n",
            encoding="utf-8",
        )

        record = self.only_record()

        self.assertEqual(record.transcript_path.resolve(), transcript.resolve())
        self.assertEqual(record.transcript_kind, "native")

    def test_realistic_nested_cli_session_id_still_resolves(self) -> None:
        raw_id = "task-native-001"
        cli_id = "cli-session-001"
        self.write_metadata(
            "local_task-native-001.json",
            {
                "id": raw_id,
                "cliSessionId": cli_id,
                "title": "Nested native",
            },
        )
        session = self.workspace / "local_task-native-001"
        transcript_dir = session / ".claude" / "projects" / "-synthetic-project"
        transcript_dir.mkdir(parents=True)
        transcript = transcript_dir / (cli_id + ".jsonl")
        transcript.write_text(
            json.dumps({"role": "user", "content": "nested native"}) + "\n",
            encoding="utf-8",
        )

        record = self.only_record()

        self.assertEqual(record.transcript_path.resolve(), transcript.resolve())
        self.assertEqual(record.transcript_kind, "native")


if __name__ == "__main__":
    unittest.main()
