from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "plugins" / "cowork-ai-os" / "lib"
sys.path.insert(0, str(LIB))

import cowork_ai_os.capture as capture_module
from cowork_ai_os.capture import capture_sessions
from cowork_ai_os.discovery import discover_sessions
from cowork_ai_os.safety import SafetyError


class InstructionCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        self.workspace = self.source / "account-fictional" / "workspace-fictional"
        self.workspace.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def add_session(
        self,
        raw_id: str,
        *,
        identifier_key: str = "spaceId",
        identifier_value: str = "space-fictional",
        inline_instructions: str = "",
    ) -> Path:
        session = self.workspace / raw_id
        session.mkdir()
        (session / "transcript.jsonl").write_text(
            json.dumps({"role": "user", "content": "Fictional chat body"}) + "\n",
            encoding="utf-8",
        )
        metadata = {
            "id": raw_id,
            "title": "Fictional selected session",
            "transcriptPath": raw_id + "/transcript.jsonl",
        }
        if identifier_key:
            metadata[identifier_key] = identifier_value
        if inline_instructions:
            metadata["spaceInstructions"] = inline_instructions
        metadata_path = self.workspace / ("local_" + raw_id + ".json")
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        return metadata_path

    def write_spaces(self, entries: list[dict]) -> Path:
        path = self.workspace / "spaces.json"
        path.write_text(json.dumps({"spaces": entries}), encoding="utf-8")
        return path

    def write_memory(self, identifier: str, body: str) -> Path:
        memory = self.workspace / "spaces" / identifier / "memory"
        memory.mkdir(parents=True, exist_ok=True)
        path = memory / "fictional.md"
        path.write_text(body, encoding="utf-8")
        return path

    def selector(self, raw_id: str) -> str:
        for record in discover_sessions(self.source).sessions:
            if record.raw_identifier == raw_id:
                return record.safe_id
        self.fail("fictional session was not discovered")

    def apply_capture(self, raw_ids: list[str], output_name: str = "capture") -> tuple[Path, dict]:
        output = self.base / output_name
        selectors = [self.selector(raw_id) for raw_id in raw_ids]
        preview = capture_sessions(self.source, selectors, output, apply=False)
        result = capture_sessions(
            self.source,
            selectors,
            output,
            apply=True,
            approved_plan=preview["approval_token"],
        )
        return output, result

    @staticmethod
    def exported_text(output: Path) -> str:
        return "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in output.rglob("*")
            if path.is_file()
        )

    def test_unique_workspace_registry_instruction_wins_over_inline(self) -> None:
        self.add_session(
            "session-registry",
            identifier_value="space-registry",
            inline_instructions="INLINEFALLBACKCANARY",
        )
        self.write_spaces(
            [
                {
                    "id": "space-registry",
                    "name": "Fictional Registry Project",
                    "instructions": "UNIQUEINSTRUCTIONCANARY",
                }
            ]
        )
        self.write_memory("space-registry", "CANONICALMEMORYCANARY")

        output, _ = self.apply_capture(["session-registry"])
        exported = self.exported_text(output)

        self.assertIn("UNIQUEINSTRUCTIONCANARY", exported)
        self.assertIn("CANONICALMEMORYCANARY", exported)
        self.assertIn("Fictional Registry Project", exported)
        self.assertNotIn("INLINEFALLBACKCANARY", exported)

    def test_inline_instruction_is_used_when_registry_has_no_match(self) -> None:
        self.add_session(
            "session-inline",
            identifier_value="space-inline",
            inline_instructions="INLINEONLYCANARY",
        )
        self.write_spaces(
            [
                {
                    "id": "space-unrelated",
                    "instructions": "UNRELATEDREGISTRYCANARY",
                }
            ]
        )

        output, _ = self.apply_capture(["session-inline"])
        exported = self.exported_text(output)

        self.assertIn("INLINEONLYCANARY", exported)
        self.assertNotIn("UNRELATEDREGISTRYCANARY", exported)

    def test_legacy_alternate_ids_associate_content_but_not_memory_paths(self) -> None:
        cases = (
            ("session-snake", "space_id", "legacy-snake", "SNAKEIDINSTRUCTION"),
            ("session-project", "projectId", "legacy-project", "PROJECTIDINSTRUCTION"),
        )
        for raw_id, key, value, _ in cases:
            self.add_session(raw_id, identifier_key=key, identifier_value=value)
            self.write_memory(value, "LEGACYMEMORYMUSTNOTIMPORT" + value)
        self.write_spaces(
            [
                {
                    "id": value,
                    "name": "Fictional " + value,
                    "instructions": instruction,
                }
                for _, _, value, instruction in cases
            ]
        )

        records = {
            item.raw_identifier: item for item in discover_sessions(self.source).sessions
        }
        for raw_id, _, value, _ in cases:
            self.assertEqual(records[raw_id].space_identifier, "")
            self.assertEqual(records[raw_id].space_association_identifier, value)

        output, _ = self.apply_capture([item[0] for item in cases])
        exported = self.exported_text(output)

        self.assertIn("SNAKEIDINSTRUCTION", exported)
        self.assertIn("PROJECTIDINSTRUCTION", exported)
        self.assertNotIn("LEGACYMEMORYMUSTNOTIMPORT", exported)

    def test_canonical_id_is_the_only_registry_authority(self) -> None:
        metadata_path = self.add_session(
            "session-aliases",
            identifier_value="canonical-space",
            inline_instructions="ALIASESINLINECANARY",
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata.update(
            {
                "space_id": "root-snake-alias",
                "projectId": "root-project-alias",
                "space": {"id": "object-space-alias"},
                "session": {
                    "project": {"project_id": "nested-project-alias"}
                },
            }
        )
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        self.write_spaces(
            [
                {
                    "id": "canonical-space",
                    "instructions": "CANONICALINSTRUCTIONCANARY",
                },
                {
                    "id": "nested-project-alias",
                    "instructions": "ALIASINSTRUCTIONMUSTNOTIMPORT",
                }
            ]
        )
        self.write_memory("canonical-space", "CANONICALALIASMEMORYCANARY")
        self.write_memory("root-snake-alias", "ALIASMEMORYMUSTNOTIMPORT")

        record = discover_sessions(self.source).sessions[0]
        self.assertEqual(record.space_identifier, "canonical-space")
        self.assertEqual(
            record.space_association_identifiers,
            (
                "canonical-space",
                "root-snake-alias",
                "root-project-alias",
                "object-space-alias",
                "nested-project-alias",
            ),
        )

        output, _ = self.apply_capture(["session-aliases"])
        exported = self.exported_text(output)
        self.assertIn("CANONICALINSTRUCTIONCANARY", exported)
        self.assertIn("CANONICALALIASMEMORYCANARY", exported)
        self.assertNotIn("ALIASESINLINECANARY", exported)
        self.assertNotIn("ALIASINSTRUCTIONMUSTNOTIMPORT", exported)
        self.assertNotIn("ALIASMEMORYMUSTNOTIMPORT", exported)

    def test_conflicting_noncanonical_aliases_fail_closed(self) -> None:
        metadata_path = self.add_session(
            "session-cross-alias",
            identifier_key="",
            inline_instructions="CROSSALIASINLINECANARY",
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["space_id"] = "space-cross-alias"
        metadata["projectId"] = "project-cross-alias"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        self.write_spaces(
            [
                {
                    "id": "space-cross-alias",
                    "instructions": "CROSSALIASFIRSTCANARY",
                },
                {
                    "id": "project-cross-alias",
                    "instructions": "CROSSALIASSECONDCANARY",
                },
            ]
        )

        output, result = self.apply_capture(["session-cross-alias"])
        exported = self.exported_text(output)
        for excluded in (
            "CROSSALIASINLINECANARY",
            "CROSSALIASFIRSTCANARY",
            "CROSSALIASSECONDCANARY",
        ):
            self.assertNotIn(excluded, exported)
        self.assertIn("conflicting", "\n".join(result["warnings"]).casefold())

    def test_nested_inline_instruction_containers_are_supported(self) -> None:
        cases = (
            ("session", None, "NESTEDSESSIONCANARY"),
            ("metadata", "space", "NESTEDMETADATASPACECANARY"),
            ("conversation", "project", "NESTEDCONVERSATIONPROJECTCANARY"),
        )
        for index, (container_name, object_name, instruction) in enumerate(cases):
            with self.subTest(container=container_name, object=object_name):
                raw_id = "session-nested-{}".format(index)
                metadata_path = self.add_session(
                    raw_id,
                    identifier_key="",
                    inline_instructions="",
                )
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                instruction_container: dict = {
                    (
                        "spaceInstructions"
                        if object_name is None
                        else "instructions"
                    ): instruction
                }
                if object_name is not None:
                    instruction_container["id"] = "nested-identity-{}".format(index)
                metadata[container_name] = (
                    {object_name: instruction_container}
                    if object_name is not None
                    else instruction_container
                )
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

                output, _ = self.apply_capture(
                    [raw_id], output_name="nested-capture-{}".format(index)
                )
                self.assertIn(instruction, self.exported_text(output))

    def test_untyped_generic_session_instructions_are_not_exported(self) -> None:
        metadata_path = self.add_session(
            "session-untyped-instructions",
            identifier_key="",
            inline_instructions="",
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["session"] = {"instructions": "RAWGENERICINSTRUCTIONCANARY"}
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        output, _ = self.apply_capture(["session-untyped-instructions"])
        exported = self.exported_text(output)

        self.assertNotIn("RAWGENERICINSTRUCTIONCANARY", exported)
        self.assertFalse(list(output.rglob("space-instructions.md")))

    def test_conflicting_typed_inline_project_is_not_exported(self) -> None:
        metadata_path = self.add_session(
            "session-conflicting-inline",
            identifier_value="canonical-selected",
            inline_instructions="",
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["project"] = {
            "id": "other-unselected",
            "instructions": "OTHERINLINEPROJECTCANARY",
        }
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        output, _ = self.apply_capture(["session-conflicting-inline"])
        exported = self.exported_text(output)

        self.assertNotIn("OTHERINLINEPROJECTCANARY", exported)
        self.assertFalse(list(output.rglob("space-instructions.md")))

    def test_root_inline_instruction_has_deterministic_precedence(self) -> None:
        metadata_path = self.add_session(
            "session-root-precedence",
            identifier_key="",
            inline_instructions="ROOTPRECEDENCECANARY",
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["space"] = {"instructions": "ROOTSPACELOWERPRECEDENCECANARY"}
        metadata["session"] = {
            "instructions": "NESTEDSESSIONLOWERPRECEDENCECANARY"
        }
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        output, _ = self.apply_capture(["session-root-precedence"])
        exported = self.exported_text(output)
        self.assertIn("ROOTPRECEDENCECANARY", exported)
        self.assertNotIn("ROOTSPACELOWERPRECEDENCECANARY", exported)
        self.assertNotIn("NESTEDSESSIONLOWERPRECEDENCECANARY", exported)

    def test_duplicate_registry_id_fails_closed_without_inline_fallback(self) -> None:
        self.add_session(
            "session-duplicate",
            identifier_value="space-duplicate",
            inline_instructions="AMBIGUOUSINLINECANARY",
        )
        self.write_spaces(
            [
                {"id": "space-duplicate", "instructions": "DUPLICATEFIRSTCANARY"},
                {"id": "space-duplicate", "instructions": "DUPLICATESECONDCANARY"},
            ]
        )

        output, result = self.apply_capture(["session-duplicate"])
        exported = self.exported_text(output)

        for excluded in (
            "AMBIGUOUSINLINECANARY",
            "DUPLICATEFIRSTCANARY",
            "DUPLICATESECONDCANARY",
        ):
            self.assertNotIn(excluded, exported)
        self.assertFalse(list(output.rglob("space-instructions.md")))
        self.assertIn("duplicate", "\n".join(result["warnings"]).casefold())

    def test_path_like_id_can_associate_instructions_but_cannot_select_memory(self) -> None:
        unsafe_identifier = "../fictional-escape"
        self.add_session(
            "session-unsafe",
            identifier_value=unsafe_identifier,
            inline_instructions="UNSAFEINLINECANARY",
        )
        self.write_spaces(
            [
                {
                    "id": unsafe_identifier,
                    "instructions": "UNSAFEREGISTRYCANARY",
                }
            ]
        )
        escaped_memory = self.workspace / "fictional-escape" / "memory"
        escaped_memory.mkdir(parents=True)
        (escaped_memory / "fictional.md").write_text(
            "UNSAFEMEMORYMUSTNOTIMPORT", encoding="utf-8"
        )

        record = discover_sessions(self.source).sessions[0]
        self.assertEqual(record.space_identifier, "")
        self.assertEqual(record.space_association_identifier, unsafe_identifier)

        output, _ = self.apply_capture(["session-unsafe"])
        exported = self.exported_text(output)

        self.assertIn("UNSAFEREGISTRYCANARY", exported)
        self.assertNotIn("UNSAFEINLINECANARY", exported)
        self.assertNotIn("UNSAFEMEMORYMUSTNOTIMPORT", exported)

    def test_present_malformed_registry_blocks_inline_fallback(self) -> None:
        self.add_session(
            "session-malformed-registry",
            identifier_value="space-malformed-registry",
            inline_instructions="MALFORMEDINLINECANARY",
        )
        (self.workspace / "spaces.json").write_text("{malformed", encoding="utf-8")

        output, result = self.apply_capture(["session-malformed-registry"])
        self.assertNotIn("MALFORMEDINLINECANARY", self.exported_text(output))
        self.assertIn("malformed", "\n".join(result["warnings"]).casefold())

    def test_present_malformed_registry_blocks_inline_without_association(self) -> None:
        self.add_session(
            "session-malformed-no-association",
            identifier_key="",
            inline_instructions="NOASSOCIATIONINLINECANARY",
        )
        (self.workspace / "spaces.json").write_text("{malformed", encoding="utf-8")

        output, result = self.apply_capture(["session-malformed-no-association"])
        self.assertNotIn("NOASSOCIATIONINLINECANARY", self.exported_text(output))
        self.assertIn("malformed", "\n".join(result["warnings"]).casefold())

    def test_present_symlink_registry_blocks_inline_fallback(self) -> None:
        self.add_session(
            "session-linked-registry",
            identifier_value="space-linked-registry",
            inline_instructions="LINKEDINLINECANARY",
        )
        target = self.workspace / "fictional-registry-target.json"
        target.write_text(json.dumps({"spaces": []}), encoding="utf-8")
        (self.workspace / "spaces.json").symlink_to(target.name)

        output, result = self.apply_capture(["session-linked-registry"])
        self.assertNotIn("LINKEDINLINECANARY", self.exported_text(output))
        self.assertIn("linked", "\n".join(result["warnings"]).casefold())

    def test_present_nonregular_registry_blocks_inline_fallback(self) -> None:
        self.add_session(
            "session-directory-registry",
            identifier_value="space-directory-registry",
            inline_instructions="DIRECTORYINLINECANARY",
        )
        (self.workspace / "spaces.json").mkdir()

        output, result = self.apply_capture(["session-directory-registry"])
        self.assertNotIn("DIRECTORYINLINECANARY", self.exported_text(output))
        self.assertIn("non-regular", "\n".join(result["warnings"]).casefold())

    def test_present_unsafe_hardlinked_registry_blocks_inline_fallback(self) -> None:
        self.add_session(
            "session-hardlinked-registry",
            identifier_value="space-hardlinked-registry",
            inline_instructions="HARDLINKEDINLINECANARY",
        )
        target = self.workspace / "fictional-hardlinked-registry.json"
        target.write_text(json.dumps({"spaces": []}), encoding="utf-8")
        os.link(target, self.workspace / "spaces.json")

        output, result = self.apply_capture(["session-hardlinked-registry"])
        self.assertNotIn("HARDLINKEDINLINECANARY", self.exported_text(output))
        self.assertIn("unsafe", "\n".join(result["warnings"]).casefold())

    def test_preview_does_not_consult_or_emit_instruction_bodies(self) -> None:
        self.add_session(
            "session-preview",
            identifier_value="space-preview",
            inline_instructions="PREVIEWINLINEBODYCANARY",
        )
        self.write_spaces(
            [
                {
                    "id": "space-preview",
                    "name": "PREVIEWREGISTRYNAMECANARY",
                    "instructions": "PREVIEWREGISTRYBODYCANARY",
                }
            ]
        )
        self.write_memory("space-preview", "PREVIEWMEMORYBODYCANARY")
        selector = self.selector("session-preview")

        with mock.patch.object(
            capture_module,
            "_selected_space_details",
            side_effect=AssertionError("preview consulted instruction content"),
        ), mock.patch.object(
            capture_module,
            "read_regular_bytes",
            side_effect=AssertionError("preview opened a selected content body"),
        ):
            preview = capture_sessions(
                self.source,
                [selector],
                self.base / "preview-output",
                apply=False,
            )

        rendered = json.dumps(preview)
        for canary in (
            "PREVIEWINLINEBODYCANARY",
            "PREVIEWREGISTRYNAMECANARY",
            "PREVIEWREGISTRYBODYCANARY",
            "PREVIEWMEMORYBODYCANARY",
        ):
            self.assertNotIn(canary, rendered)
        self.assertFalse((self.base / "preview-output").exists())

    def test_stale_metadata_invalidates_instruction_approval_token(self) -> None:
        metadata_path = self.add_session(
            "session-stale-metadata",
            identifier_value="space-stale-metadata",
            inline_instructions="METADATAINSTRUCTIONALPHA",
        )
        selector = self.selector("session-stale-metadata")
        output = self.base / "stale-metadata-output"
        preview = capture_sessions(self.source, [selector], output, apply=False)
        original_stat = metadata_path.stat()

        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["spaceInstructions"] = "METADATAINSTRUCTIONBRAVO"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        os.utime(
            metadata_path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        changed_stat = metadata_path.stat()
        self.assertEqual(changed_stat.st_size, original_stat.st_size)
        self.assertEqual(changed_stat.st_mtime_ns, original_stat.st_mtime_ns)
        refreshed = capture_sessions(self.source, [selector], output, apply=False)

        self.assertNotEqual(preview["approval_token"], refreshed["approval_token"])
        with self.assertRaises(SafetyError):
            capture_sessions(
                self.source,
                [selector],
                output,
                apply=True,
                approved_plan=preview["approval_token"],
            )
        self.assertFalse(output.exists())

    def test_stale_spaces_registry_invalidates_instruction_approval_token(self) -> None:
        self.add_session(
            "session-stale-registry",
            identifier_value="space-stale-registry",
        )
        spaces_path = self.write_spaces(
            [
                {
                    "id": "space-stale-registry",
                    "instructions": "REGISTRYINSTRUCTIONALPHA",
                }
            ]
        )
        selector = self.selector("session-stale-registry")
        output = self.base / "stale-registry-output"
        preview = capture_sessions(self.source, [selector], output, apply=False)
        original_stat = spaces_path.stat()

        spaces = json.loads(spaces_path.read_text(encoding="utf-8"))
        spaces["spaces"][0]["instructions"] = "REGISTRYINSTRUCTIONBRAVO"
        spaces_path.write_text(json.dumps(spaces), encoding="utf-8")
        os.utime(
            spaces_path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        changed_stat = spaces_path.stat()
        self.assertEqual(changed_stat.st_size, original_stat.st_size)
        self.assertEqual(changed_stat.st_mtime_ns, original_stat.st_mtime_ns)
        refreshed = capture_sessions(self.source, [selector], output, apply=False)

        self.assertNotEqual(preview["approval_token"], refreshed["approval_token"])
        with self.assertRaises(SafetyError):
            capture_sessions(
                self.source,
                [selector],
                output,
                apply=True,
                approved_plan=preview["approval_token"],
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
