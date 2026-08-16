from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

import cowork_ai_os.capture as capture_module
import cowork_ai_os.discovery as discovery_module
from cowork_ai_os.capture import capture_sessions
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.safety import SafetyError


class SpaceProjectMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        self.workspace = self.source / "account-a" / "workspace-a"
        self.workspace.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_session(
        self,
        raw_id: str,
        space_id: str,
        *,
        workspace: Optional[Path] = None,
    ) -> None:
        workspace = workspace or self.workspace
        session = workspace / raw_id
        session.mkdir(parents=True, exist_ok=True)
        (session / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "Synthetic session body"})
            + "\n",
            encoding="utf-8",
        )
        (workspace / ("local_" + raw_id + ".json")).write_text(
            json.dumps(
                {
                    "id": raw_id,
                    "title": "Synthetic selected session",
                    "spaceId": space_id,
                    "transcriptPath": raw_id + "/transcript.jsonl",
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def write_spaces(workspace: Path, entries: list[dict]) -> None:
        (workspace / "spaces.json").write_text(
            json.dumps({"spaces": entries}), encoding="utf-8"
        )

    @staticmethod
    def write_project_memory(
        workspace: Path, space_id: str, filename: str, body: str
    ) -> Path:
        memory = workspace / "spaces" / space_id / "memory"
        memory.mkdir(parents=True, exist_ok=True)
        target = memory / filename
        target.write_text(body, encoding="utf-8")
        return target

    def selected_ids(self, *raw_ids: str) -> list[str]:
        wanted = set(raw_ids)
        records = discover_sessions(self.source).sessions
        selected = [
            record.safe_id for record in records if record.raw_identifier in wanted
        ]
        self.assertEqual(len(selected), len(wanted))
        return selected

    def apply_capture(self, output: Path, *raw_ids: str) -> tuple[dict, dict]:
        selectors = self.selected_ids(*raw_ids)
        preview = capture_sessions(self.source, selectors, output, apply=False)
        result = capture_sessions(
            self.source,
            selectors,
            output,
            apply=True,
            approved_plan=preview["approval_token"],
        )
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        return result, manifest

    @staticmethod
    def exported_text(output: Path) -> str:
        return "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in output.rglob("*")
            if path.is_file()
        )

    def test_exact_space_instructions_and_project_memory_are_selected(self) -> None:
        self.add_session("session-selected", "space-selected")
        self.write_spaces(
            self.workspace,
            [
                {
                    "id": "space-selected",
                    "name": "Selected project",
                    "instructions": "SELECTEDPROJECTINSTRUCTIONS",
                },
                {
                    "id": "space-stale",
                    "name": "Stale project",
                    "instructions": "STALEPROJECTINSTRUCTIONS",
                },
            ],
        )
        self.write_project_memory(
            self.workspace,
            "space-selected",
            "selected.md",
            "SELECTEDPROJECTMEMORY",
        )
        self.write_project_memory(
            self.workspace, "space-stale", "stale.md", "STALEPROJECTMEMORY"
        )
        for relative, body in (
            (Path("agent/memory/agent.md"), "AGENTMEMORY"),
            (Path("memory/workspace.md"), "WORKSPACEMEMORY"),
        ):
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")

        output = self.base / "capture"
        _, manifest = self.apply_capture(output, "session-selected")
        exported = self.exported_text(output)

        self.assertIn("SELECTEDPROJECTINSTRUCTIONS", exported)
        self.assertIn("SELECTEDPROJECTMEMORY", exported)
        for excluded in (
            "STALEPROJECTINSTRUCTIONS",
            "STALEPROJECTMEMORY",
            "AGENTMEMORY",
            "WORKSPACEMEMORY",
        ):
            self.assertNotIn(excluded, exported)
        project_memory = [
            item
            for item in manifest["files"]
            if item["provenance"]["kind"] == "sanitized-project-memory"
        ]
        self.assertEqual(len(project_memory), 1)
        self.assertEqual(project_memory[0]["provenance"]["scope"], "project-space")

    def test_same_space_id_in_sibling_workspace_is_not_used(self) -> None:
        self.add_session("session-selected", "space-shared")
        self.write_spaces(
            self.workspace,
            [
                {
                    "id": "space-shared",
                    "instructions": "SELECTEDWORKSPACEINSTRUCTIONS",
                }
            ],
        )
        self.write_project_memory(
            self.workspace, "space-shared", "selected.md", "SELECTEDWORKSPACEMEMORY"
        )

        sibling = self.source / "account-b" / "workspace-b"
        sibling.mkdir(parents=True)
        self.write_spaces(
            sibling,
            [
                {
                    "id": "space-shared",
                    "instructions": "SIBLINGWORKSPACEINSTRUCTIONS",
                }
            ],
        )
        self.write_project_memory(
            sibling, "space-shared", "sibling.md", "SIBLINGWORKSPACEMEMORY"
        )

        output = self.base / "capture"
        self.apply_capture(output, "session-selected")
        exported = self.exported_text(output)

        self.assertIn("SELECTEDWORKSPACEINSTRUCTIONS", exported)
        self.assertIn("SELECTEDWORKSPACEMEMORY", exported)
        self.assertNotIn("SIBLINGWORKSPACEINSTRUCTIONS", exported)
        self.assertNotIn("SIBLINGWORKSPACEMEMORY", exported)

    def test_two_selected_sessions_share_one_project_memory_export(self) -> None:
        for raw_id in ("session-first", "session-second"):
            self.add_session(raw_id, "space-shared")
        self.write_spaces(
            self.workspace,
            [{"id": "space-shared", "name": "Shared project"}],
        )
        self.write_project_memory(
            self.workspace, "space-shared", "shared.md", "SHAREDPROJECTMEMORY"
        )

        output = self.base / "capture"
        _, manifest = self.apply_capture(
            output, "session-first", "session-second"
        )
        project_memory = [
            item
            for item in manifest["files"]
            if item["provenance"]["kind"] == "sanitized-project-memory"
        ]

        self.assertEqual(len(project_memory), 1)
        self.assertEqual(
            sorted(project_memory[0]["provenance"]["related_session_ids"]),
            sorted(manifest["session_ids"]),
        )
        imported_bodies = "\n".join(
            path.read_text(encoding="utf-8")
            for path in output.rglob("*.imported.md")
        )
        self.assertEqual(imported_bodies.count("SHAREDPROJECTMEMORY"), 1)

    def test_project_memory_rejects_links_hardlinks_and_protected_paths(self) -> None:
        self.add_session("session-selected", "space-selected")
        self.add_session("session-linked-root", "space-linked-root")
        self.write_spaces(
            self.workspace,
            [
                {"id": "space-selected"},
                {"id": "space-linked-root"},
            ],
        )
        memory_file = self.write_project_memory(
            self.workspace, "space-selected", "good.md", "GOODPROJECTMEMORY"
        )
        memory = memory_file.parent
        protected = memory / "auth"
        protected.mkdir()
        (protected / "secret.md").write_text(
            "PROTECTEDPROJECTMEMORY", encoding="utf-8"
        )
        (memory / ".env").write_text("PROTECTEDENVPROJECTMEMORY", encoding="utf-8")

        outside_file = self.base / "outside-file.md"
        outside_file.write_text("LINKEDPROJECTMEMORY", encoding="utf-8")
        outside_directory = self.base / "outside-directory"
        outside_directory.mkdir()
        (outside_directory / "root.md").write_text(
            "LINKEDROOTPROJECTMEMORY", encoding="utf-8"
        )
        links_supported = True
        try:
            (memory / "linked.md").symlink_to(outside_file)
            linked_parent = self.workspace / "spaces" / "space-linked-root"
            linked_parent.mkdir(parents=True)
            (linked_parent / "memory").symlink_to(
                outside_directory, target_is_directory=True
            )
        except (OSError, NotImplementedError):
            links_supported = False

        hardlinks_supported = True
        try:
            os.link(outside_file, memory / "hardlinked.md")
        except (OSError, NotImplementedError):
            hardlinks_supported = False

        output = self.base / "capture"
        result, _ = self.apply_capture(
            output, "session-selected", "session-linked-root"
        )
        exported = self.exported_text(output)

        self.assertIn("GOODPROJECTMEMORY", exported)
        self.assertNotIn("PROTECTEDPROJECTMEMORY", exported)
        self.assertNotIn("PROTECTEDENVPROJECTMEMORY", exported)
        self.assertNotIn("LINKEDPROJECTMEMORY", exported)
        self.assertNotIn("LINKEDROOTPROJECTMEMORY", exported)
        warning_text = "\n".join(result["warnings"]).casefold()
        self.assertIn("protected", warning_text)
        if links_supported:
            self.assertIn("symlink", warning_text)
        if hardlinks_supported:
            self.assertIn("hard-linked", warning_text)

    def test_inventory_and_capture_preview_do_not_open_project_bodies(self) -> None:
        self.add_session("session-selected", "space-selected")
        self.write_spaces(
            self.workspace,
            [
                {
                    "id": "space-selected",
                    "name": "REGISTRYNAMECANARY",
                    "instructions": "REGISTRYINSTRUCTIONBODYCANARY",
                }
            ],
        )
        self.write_project_memory(
            self.workspace,
            "space-selected",
            "memory.md",
            "PROJECTMEMORYBODYCANARY",
        )
        discovery_reads: list[str] = []
        original_discovery_read = discovery_module.read_regular_bytes

        def track_discovery(path: Path, root: Path, max_bytes: int) -> bytes:
            name = Path(path).name
            discovery_reads.append(name)
            if name == "spaces.json":
                raise AssertionError("inventory opened the spaces registry")
            return original_discovery_read(path, root, max_bytes)

        with mock.patch.object(
            discovery_module, "read_regular_bytes", side_effect=track_discovery
        ):
            inventory = discover_sessions(self.source)
            safe = inventory.agent_safe_dict()
            self.assertIsNone(safe["sessions"][0]["space"]["name"])
            output = self.base / "preview-output"
            with mock.patch.object(
                capture_module,
                "read_regular_bytes",
                side_effect=AssertionError("capture preview opened a content body"),
            ):
                preview = capture_sessions(
                    self.source,
                    [inventory.sessions[0].safe_id],
                    output,
                    apply=False,
                )

        self.assertEqual(set(discovery_reads), {"local_session-selected.json"})
        self.assertEqual(preview["project_memory_file_count"], 1)
        self.assertFalse(output.exists())
        rendered = json.dumps(safe) + json.dumps(preview)
        self.assertNotIn("REGISTRYNAMECANARY", rendered)
        self.assertNotIn("REGISTRYINSTRUCTIONBODYCANARY", rendered)
        self.assertNotIn("PROJECTMEMORYBODYCANARY", rendered)

    def test_approval_token_binds_project_memory_file_metadata(self) -> None:
        self.add_session("session-selected", "space-selected")
        self.write_spaces(self.workspace, [{"id": "space-selected"}])
        memory = self.write_project_memory(
            self.workspace,
            "space-selected",
            "memory.md",
            "PROJECTMEMORYALPHA",
        )
        selector = self.selected_ids("session-selected")
        output = self.base / "capture"
        first = capture_sessions(self.source, selector, output, apply=False)

        before = memory.stat()
        memory.write_text("PROJECTMEMORYBRAVO", encoding="utf-8")
        os.utime(
            memory,
            ns=(before.st_atime_ns, max(before.st_mtime_ns + 1, memory.stat().st_mtime_ns)),
        )
        second = capture_sessions(self.source, selector, output, apply=False)

        self.assertNotEqual(first["approval_token"], second["approval_token"])
        with self.assertRaises(SafetyError):
            capture_sessions(
                self.source,
                selector,
                output,
                apply=True,
                approved_plan=first["approval_token"],
            )
        self.assertFalse(output.exists())

    def test_nested_or_path_like_space_identity_cannot_select_memory(self) -> None:
        session = self.workspace / "session-nested"
        session.mkdir()
        (session / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "Synthetic"}) + "\n",
            encoding="utf-8",
        )
        (self.workspace / "local_session-nested.json").write_text(
            json.dumps(
                {
                    "id": "session-nested",
                    "transcriptPath": "session-nested/transcript.jsonl",
                    "space": {"id": "space-decoy"},
                }
            ),
            encoding="utf-8",
        )
        self.write_project_memory(
            self.workspace, "space-decoy", "decoy.md", "NESTEDSPACEIDMEMORY"
        )
        self.add_session("session-pathlike", "../space-decoy")

        output = self.base / "capture"
        self.apply_capture(output, "session-nested", "session-pathlike")

        self.assertNotIn("NESTEDSPACEIDMEMORY", self.exported_text(output))


if __name__ == "__main__":
    unittest.main()
