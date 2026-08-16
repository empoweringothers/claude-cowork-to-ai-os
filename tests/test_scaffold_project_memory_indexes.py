from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

from cowork_ai_os.capture import capture_sessions
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.safety import SafetyError, sha256_bytes
from cowork_ai_os.scaffold import scaffold_ai_os
from cowork_ai_os.verify import verify_tree


class ScaffoldProjectMemoryIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_session(
        self,
        workspace: Path,
        raw_id: str,
        space_id: str,
        *,
        project_name: Optional[str] = None,
    ) -> None:
        session = workspace / raw_id
        session.mkdir(parents=True, exist_ok=True)
        (session / "transcript.jsonl").write_text(
            json.dumps(
                {"role": "user", "content": "Synthetic selected session body"}
            )
            + "\n",
            encoding="utf-8",
        )
        metadata = {
            "id": raw_id,
            "title": "Synthetic selected session",
            "spaceId": space_id,
            "transcriptPath": raw_id + "/transcript.jsonl",
        }
        if project_name is not None:
            metadata["projectName"] = project_name
        (workspace / ("local_" + raw_id + ".json")).write_text(
            json.dumps(metadata), encoding="utf-8"
        )

    @staticmethod
    def write_spaces(workspace: Path, entries: list[dict]) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "spaces.json").write_text(
            json.dumps({"spaces": entries}), encoding="utf-8"
        )

    def test_shared_memory_is_linked_once_per_related_identity_group(self) -> None:
        shared_workspace = self.source / "account-a" / "workspace-a"
        unrelated_workspace = self.source / "account-b" / "workspace-b"
        self.write_spaces(
            shared_workspace,
            [{"id": "space-shared", "name": "Same display label"}],
        )
        self.write_spaces(
            unrelated_workspace,
            [{"id": "space-unrelated", "name": "Same display label"}],
        )

        # Two sessions deliberately share the project-kind identity group.
        self.add_session(
            shared_workspace,
            "session-project-first",
            "space-shared",
            project_name="Same display label",
        )
        self.add_session(
            shared_workspace,
            "session-project-second",
            "space-shared",
            project_name="Same display label",
        )
        # This session resolves the same exact project-memory directory, but
        # its explicit metadata produces a distinct space-kind index group.
        self.add_session(shared_workspace, "session-space", "space-shared")
        # An unrelated workspace deliberately reuses the display label.
        self.add_session(
            unrelated_workspace,
            "session-unrelated",
            "space-unrelated",
            project_name="Same display label",
        )

        memory_root = shared_workspace / "spaces" / "space-shared" / "memory"
        memory_root.mkdir(parents=True)
        (memory_root / "shared-context.md").write_text(
            "SYNTHETIC_SHARED_PROJECT_MEMORY", encoding="utf-8"
        )

        records = discover_sessions(self.source).sessions
        safe_by_raw = {record.raw_identifier: record.safe_id for record in records}
        capture = self.base / "capture"
        selectors = [record.safe_id for record in records]
        capture_preview = capture_sessions(
            self.source, selectors, capture, apply=False
        )
        capture_sessions(
            self.source,
            selectors,
            capture,
            apply=True,
            approved_plan=capture_preview["approval_token"],
        )

        capture_manifest = json.loads(
            (capture / "manifest.json").read_text(encoding="utf-8")
        )
        memory_entries = [
            entry
            for entry in capture_manifest["files"]
            if entry["provenance"].get("kind") == "sanitized-project-memory"
        ]
        self.assertEqual(len(memory_entries), 1)
        memory_path = memory_entries[0]["path"]
        expected_related = {
            safe_by_raw["session-project-first"],
            safe_by_raw["session-project-second"],
            safe_by_raw["session-space"],
        }
        self.assertEqual(
            set(memory_entries[0]["provenance"]["related_session_ids"]),
            expected_related,
        )

        output = self.base / "AI-OS"
        scaffold_preview = scaffold_ai_os(
            capture, output, profile="personal", apply=False
        )
        scaffold_ai_os(
            capture,
            output,
            profile="personal",
            apply=True,
            approved_plan=scaffold_preview["approval_token"],
        )

        index_paths = sorted(
            (output / "Projects" / "Cowork-Import").glob("index-*/README.md")
        )
        self.assertEqual(len(index_paths), 3)
        index_text = {
            path: path.read_text(encoding="utf-8") for path in index_paths
        }

        def index_for(raw_id: str) -> Path:
            safe_id = safe_by_raw[raw_id]
            matches = [
                path for path, text in index_text.items() if "`{}`".format(safe_id) in text
            ]
            self.assertEqual(len(matches), 1)
            return matches[0]

        project_index = index_for("session-project-first")
        self.assertEqual(project_index, index_for("session-project-second"))
        space_index = index_for("session-space")
        unrelated_index = index_for("session-unrelated")
        self.assertNotEqual(project_index, space_index)

        project_ids = {
            safe_by_raw["session-project-first"],
            safe_by_raw["session-project-second"],
        }
        space_ids = {safe_by_raw["session-space"]}
        unrelated_ids = {safe_by_raw["session-unrelated"]}
        for expected_ids, excluded_ids, path in (
            (project_ids, space_ids | unrelated_ids, project_index),
            (space_ids, project_ids | unrelated_ids, space_index),
            (unrelated_ids, project_ids | space_ids, unrelated_index),
        ):
            for safe_id in expected_ids:
                self.assertIn("`{}`".format(safe_id), index_text[path])
            for safe_id in excluded_ids:
                self.assertNotIn("`{}`".format(safe_id), index_text[path])

        for related_index in (project_index, space_index):
            self.assertEqual(index_text[related_index].count(memory_path), 1)
            self.assertEqual(
                index_text[related_index].count("## Shared project memory"), 1
            )
        self.assertNotIn(memory_path, index_text[unrelated_index])
        self.assertEqual(
            sum(text.count(memory_path) for text in index_text.values()), 2
        )
        for text in index_text.values():
            for raw_id in safe_by_raw:
                self.assertNotIn(raw_id, text)

        markdown_paths = index_paths + [
            output / "Projects" / "Cowork-Import" / "INDEX.md"
        ]
        for markdown_path in markdown_paths:
            markdown = markdown_path.read_text(encoding="utf-8")
            targets = re.findall(r"\]\(([^)]+)\)", markdown)
            self.assertTrue(targets, markdown_path)
            for target in targets:
                self.assertTrue(
                    (markdown_path.parent / target).resolve().is_file(),
                    "broken Markdown link in {}: {}".format(markdown_path, target),
                )

        verification = verify_tree(output)
        self.assertTrue(verification["ok"], verification)
        scaffold_manifest = json.loads(
            (output / ".ai-os" / "manifests" / "scaffold.json").read_text(
                encoding="utf-8"
            )
        )
        integrity = {entry["path"]: entry for entry in scaffold_manifest["files"]}
        for path in index_paths:
            relative = path.relative_to(output).as_posix()
            self.assertIn(relative, integrity)
            self.assertEqual(
                integrity[relative]["sha256"], sha256_bytes(path.read_bytes())
            )

    def test_public_related_session_tamper_is_rejected_by_private_provenance(self) -> None:
        shared_workspace = self.source / "synthetic-account" / "workspace"
        self.write_spaces(
            shared_workspace,
            [{"id": "space-project", "name": "Fictional project"}],
        )
        self.add_session(
            shared_workspace,
            "session-owner",
            "space-project",
            project_name="Fictional project",
        )
        self.add_session(
            shared_workspace,
            "session-related",
            "space-project",
            project_name="Fictional project",
        )

        memory_root = shared_workspace / "spaces" / "space-project" / "memory"
        memory_root.mkdir(parents=True)
        (memory_root / "fictional-context.md").write_text(
            "SYNTHETIC_PROJECT_MEMORY_ONLY", encoding="utf-8"
        )

        records = discover_sessions(self.source).sessions
        safe_by_raw = {record.raw_identifier: record.safe_id for record in records}
        capture = self.base / "capture-tampered-public"
        selectors = [record.safe_id for record in records]
        preview = capture_sessions(self.source, selectors, capture, apply=False)
        capture_sessions(
            self.source,
            selectors,
            capture,
            apply=True,
            approved_plan=preview["approval_token"],
        )

        private_path = capture / ".private" / "provenance.json"
        private_hash = sha256_bytes(private_path.read_bytes())
        manifest_path = capture / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        memory_entry = next(
            entry
            for entry in manifest["files"]
            if entry["provenance"].get("kind") == "sanitized-project-memory"
        )
        original_related = memory_entry["provenance"]["related_session_ids"]
        self.assertIn(safe_by_raw["session-related"], original_related)
        memory_entry["provenance"]["related_session_ids"] = [
            safe_by_raw["session-owner"]
        ]
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(private_hash, sha256_bytes(private_path.read_bytes()))
        self.assertTrue(verify_tree(capture)["ok"])

        def assert_public_tamper_rejected(output_name: str) -> None:
            output = self.base / output_name
            self.assertEqual(private_hash, sha256_bytes(private_path.read_bytes()))
            self.assertTrue(verify_tree(capture)["ok"])
            with self.assertRaisesRegex(
                SafetyError, "public project-memory provenance disagrees"
            ):
                scaffold_ai_os(capture, output, profile="personal", apply=False)
            self.assertFalse(output.exists())

        assert_public_tamper_rejected("AI-OS-from-related-id-tamper")

        # Hiding the public relationship must not silently omit the private
        # project-space artifact from the indexes.
        memory_entry["provenance"]["related_session_ids"] = original_related
        memory_entry["provenance"]["kind"] = "sanitized-memory"
        memory_entry["provenance"].pop("scope")
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert_public_tamper_rejected("AI-OS-from-hidden-public-relationship")

        # Fabricating another public project-memory relationship likewise has
        # no exact private artifact counterpart and must fail closed.
        memory_entry["provenance"]["kind"] = "sanitized-project-memory"
        memory_entry["provenance"]["scope"] = "project-space"
        readme_entry = next(
            entry for entry in manifest["files"] if entry["path"] == "README.md"
        )
        readme_entry["provenance"] = {
            "kind": "sanitized-project-memory",
            "session_id": safe_by_raw["session-owner"],
            "scope": "project-space",
            "related_session_ids": original_related,
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert_public_tamper_rejected("AI-OS-from-extra-public-relationship")


if __name__ == "__main__":
    unittest.main()
