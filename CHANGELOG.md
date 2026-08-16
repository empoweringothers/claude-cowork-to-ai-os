# Changelog

All notable changes will be documented here. The project follows semantic
versioning after the first stable release.

## 0.1.1 — 2026-08-15

- Recover project-scoped memory only from the selected workspace's exact
  `spaces/<spaceId>/memory/` directory and include shared project memory once
  when multiple selected sessions refer to it.
- Recover project instructions from a unique exact `spaces.json` match, with a
  fallback to inline instructions in that exact selected session when the
  registry is absent or has no matching instructions. Duplicate registry IDs
  still fail closed.
- Add a default-off `--include-hardlinked-uploads` compatibility option for
  regular files in selected session upload folders. Approved files are copied
  by value; hardlinked memory and outputs remain excluded.
- Keep projectless sessions separate instead of inferring a project from a
  display label, and continue treating linked folders as references rather
  than copy sources.
- Improve verification guidance for transient macOS provenance metadata
  changes after a large fresh local write.
- Avoid a false-positive secret finding caused only by Markdown escaping around
  a redaction marker.
- Bind transcript hints to the selected session's direct workspace root, reject
  conflicting instruction identities, and exclude untyped generic instruction
  fields.
- Harden source reads against parent-symlink races and protected-store aliases,
  while preserving Windows path/handle timestamp compatibility.
- Keep the repository validator usable inside the filtered release archive.

## 0.1.0 — 2026-08-15

- Add a dependency-free local Cowork doctor, metadata inventory, selected
  capture, AI OS scaffold, and verification workflow.
- Add a Claude Code plugin skill and pinned-release paste-in setup pattern.
- Add privacy, threat-model, supported-source, manual UI fallback, account
  visibility, contributor, security, and release documentation.
- Add synthetic safety tests and cross-platform CI.
