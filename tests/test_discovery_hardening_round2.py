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
from cowork_ai_os.doctor import doctor_report


class DiscoveryHardeningRoundTwoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source"
        self.workspace = self.source / "account-a" / "workspace-a"
        self.workspace.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_metadata(self, filename: str, value: object) -> Path:
        path = self.workspace / filename
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    @staticmethod
    def write_transcript(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"role": "user", "content": text}) + "\n",
            encoding="utf-8",
        )

    def only_record(self):
        result = discover_sessions(self.source)
        self.assertEqual(len(result.sessions), 1, result.warnings)
        return result.sessions[0]

    def test_absolute_hint_cannot_cross_into_sibling_workspace(self) -> None:
        sibling = self.source / "account-b" / "workspace-b" / "session-shared"
        transcript = sibling / "transcript.jsonl"
        self.write_transcript(transcript, "CROSS_WORKSPACE_CANARY")
        self.write_metadata(
            "local_session-shared.json",
            {
                "id": "session-shared",
                "transcriptPath": str(transcript.resolve()),
            },
        )

        record = self.only_record()

        self.assertIsNone(record.transcript_path)
        self.assertEqual(record.artifact_roots["uploads"], [])

    def test_canonical_alias_hint_is_safe_and_does_not_crash(self) -> None:
        session = self.workspace / "session-canonical"
        transcript = session / "transcript.jsonl"
        self.write_transcript(transcript, "CANONICAL_PATH_CANARY")
        alias = self.base / "source-alias"
        try:
            alias.symlink_to(self.source, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks unavailable")
        aliased_transcript = (
            alias
            / "account-a"
            / "workspace-a"
            / "session-canonical"
            / "transcript.jsonl"
        )
        self.write_metadata(
            "local_session-canonical.json",
            {"id": "session-canonical", "transcriptPath": str(aliased_transcript)},
        )

        record = self.only_record()

        self.assertEqual(record.transcript_path, transcript.resolve())
        self.assertEqual(record.transcript_path, record.transcript_path.resolve())

    def test_protected_direct_session_directory_is_rejected(self) -> None:
        transcript = self.workspace / "auth" / "transcript.jsonl"
        self.write_transcript(transcript, "PROTECTED_AUTH_CANARY")
        self.write_metadata("local_auth.json", {"id": "auth"})

        record = self.only_record()

        self.assertIsNone(record.transcript_path)
        self.assertTrue(
            all(not roots for roots in record.artifact_roots.values()),
            record.artifact_roots,
        )

    def test_only_winning_transcript_root_supplies_artifacts(self) -> None:
        native = self.workspace / "session-winner"
        audit = self.workspace / "audit-copy" / "session-winner"
        self.write_transcript(native / "transcript.jsonl", "WINNING_NATIVE")
        self.write_transcript(audit / "audit.jsonl", "LOSING_AUDIT")
        (native / "uploads").mkdir()
        (audit / "uploads").mkdir()
        (native / "uploads" / "winning.txt").write_text(
            "WINNING_ARTIFACT", encoding="utf-8"
        )
        (audit / "uploads" / "losing.txt").write_text(
            "LOSING_ARTIFACT_CANARY", encoding="utf-8"
        )
        self.write_metadata(
            "local_session-winner.json",
            {
                "id": "session-winner",
                "transcriptPath": str((native / "transcript.jsonl").resolve()),
                "auditPath": str((audit / "audit.jsonl").resolve()),
            },
        )

        record = self.only_record()

        self.assertEqual(record.transcript_path, (native / "transcript.jsonl").resolve())
        self.assertEqual(record.transcript_kind, "native")
        self.assertEqual(
            [path.resolve() for path in record.artifact_roots["uploads"]],
            [(native / "uploads").resolve()],
        )
        self.assertEqual(record.artifact_stats["uploads"]["files"], 1)

    def test_ambiguous_transcripts_supply_no_artifact_roots(self) -> None:
        candidates = []
        for branch in ("copy-one", "copy-two"):
            session = self.workspace / "session-ambiguous" / branch
            transcript = session / "transcript.jsonl"
            self.write_transcript(transcript, branch)
            (session / "uploads").mkdir()
            (session / "uploads" / (branch + ".txt")).write_text(
                branch, encoding="utf-8"
            )
            candidates.append(transcript)
        self.write_metadata(
            "local_session-ambiguous.json",
            {
                "id": "session-ambiguous",
                "transcriptPath": str(candidates[0].resolve()),
                "auditPath": str(candidates[1].resolve()),
            },
        )

        inventory = discover_sessions(self.source)
        self.assertEqual(len(inventory.sessions), 1, inventory.warnings)
        record = inventory.sessions[0]

        self.assertIsNone(record.transcript_path)
        self.assertTrue(any("ambiguous transcript" in item for item in inventory.warnings))
        self.assertTrue(
            all(not roots for roots in record.artifact_roots.values()),
            record.artifact_roots,
        )
        self.assertTrue(
            all(stats["files"] == 0 for stats in record.artifact_stats.values()),
            record.artifact_stats,
        )

    def test_empty_and_descriptive_only_metadata_are_unrecognized(self) -> None:
        self.write_metadata("local_empty.json", {})
        self.write_metadata("local_description.json", {"title": "Not enough schema"})

        inventory = discover_sessions(self.source)
        doctor = doctor_report([self.source], agent_safe=True)["roots"][0]

        self.assertEqual(inventory.sessions, [])
        self.assertTrue(any("unrecognized metadata" in item for item in inventory.warnings))
        self.assertFalse(doctor["usable"])
        self.assertEqual(doctor["layout"], "no-session-metadata")

    def test_identity_and_association_shapes_remain_recognized(self) -> None:
        identity_root = self.base / "identity-source"
        identity_root.mkdir()
        (identity_root / "local_identity.json").write_text(
            json.dumps({"id": "session-identity"}), encoding="utf-8"
        )
        identity_inventory = discover_sessions(identity_root)

        self.assertEqual(len(identity_inventory.sessions), 1)
        self.assertTrue(
            doctor_report([identity_root], agent_safe=True)["roots"][0]["usable"]
        )

        association_root = self.base / "association-source"
        association_root.mkdir()
        transcript = association_root / "session-associated" / "transcript.jsonl"
        self.write_transcript(transcript, "ASSOCIATED")
        (association_root / "local_session-associated.json").write_text(
            json.dumps(
                {"transcriptPath": "session-associated/transcript.jsonl"}
            ),
            encoding="utf-8",
        )
        association_inventory = discover_sessions(association_root)

        self.assertEqual(len(association_inventory.sessions), 1)
        self.assertEqual(
            association_inventory.sessions[0].transcript_path, transcript.resolve()
        )
        self.assertTrue(
            doctor_report([association_root], agent_safe=True)["roots"][0]["usable"]
        )

    def test_nested_cli_session_id_transcript_remains_supported(self) -> None:
        raw_id = "task-native-round-two"
        cli_id = "cli-session-round-two"
        session = self.workspace / ("local_" + raw_id)
        transcript = (
            session
            / ".claude"
            / "projects"
            / "-synthetic-project"
            / (cli_id + ".jsonl")
        )
        self.write_transcript(transcript, "NESTED_NATIVE_CANARY")
        (session / "uploads").mkdir()
        (session / "uploads" / "nested.txt").write_text(
            "NESTED_ARTIFACT", encoding="utf-8"
        )
        self.write_metadata(
            "local_" + raw_id + ".json",
            {"id": raw_id, "cliSessionId": cli_id, "title": "Nested native"},
        )

        record = self.only_record()

        self.assertEqual(record.transcript_path, transcript.resolve())
        self.assertEqual(record.transcript_kind, "native")
        self.assertEqual(
            [path.resolve() for path in record.artifact_roots["uploads"]],
            [(session / "uploads").resolve()],
        )


if __name__ == "__main__":
    unittest.main()
