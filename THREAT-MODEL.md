# Threat Model

## Protected assets

- Personal and organizational conversations
- Uploaded and generated files
- Project instructions and memory
- Local paths, account identifiers, and email addresses
- Credentials and authentication state outside the supported source boundary

## Main threats

1. Capturing every session when the user intended to move one project.
2. Mixing personal and work material in one destination.
3. Following a symlink or mis-scoping a hardlink outside the selected session.
4. Copying credentials or secrets embedded in text or files.
5. Treating prompt injection inside an imported transcript as live
   instructions.
6. Writing into or corrupting Claude Desktop's undocumented storage.
7. Leaking raw paths or content through logs, manifests, HTML, exceptions, or
   Git.
8. A future Cowork format change causing the parser to select the wrong file.
9. Treating a project display label, nested identifier, or same ID in a sibling
   workspace as authority to read project memory.
10. Merging unrelated sessions because their project labels happen to match.

## Controls

- Metadata-only inventory precedes every content read.
- Capture requires explicit session selection, `--apply`, and the matching
  approval token from a current dry-run preview.
- Approval binds the identity of selected source files, exact link counts,
  selected project-memory metadata, the hardlinked-upload opt-in, and the
  presence or absence of optional metadata such as `spaces.json`; a change
  invalidates the plan.
- Output must be outside all source roots and must not already contain data.
- Destination directories and files use no-follow directory handles where the
  platform supports them, so a parent symlink swap cannot redirect a write.
- Source files are bound to the opened handle: POSIX uses no-follow directory
  descriptors, Windows verifies the final handle path remains beneath the
  selected root, and platforms without either mechanism fail closed.
- The source adapter opens only supported metadata, transcript, memory,
  upload, and output paths.
- Project memory requires a valid top-level `spaceId` from an explicitly
  selected session and resolves only to
  `workspace/spaces/<exact-spaceId>/memory/` in that same workspace.
- Shared project memory is deduplicated by filesystem identity. Sessions with
  no usable project/space identifier remain separate instead of being grouped
  by display label.
- Project instructions prefer one unique exact match in that workspace's
  `spaces.json`. Missing or instruction-less matches may fall back to inline
  instructions from the exact selected session; duplicate matches fail closed.
  A canonical top-level `spaceId` is the only registry identity when present;
  conflicting legacy aliases and untyped generic instruction fields fail
  closed.
- Symlinks, non-regular files, and hardlinks are skipped by default.
- The hardlinked-upload opt-in is limited to regular files inside explicitly
  selected session upload roots on platforms with secure no-follow descriptor
  traversal. It copies by value into a new inode; it does not permit hardlinked
  memory, project memory, or outputs.
- File count and size limits bound traversal.
- Authentication/browser-store names are denied even when nested in a selected
  directory.
- Raw system prompts, raw transcript JSONL, tool inputs, tool results, and
  external linked folders are excluded by default. Linked folder basenames are
  orientation metadata, not permission to traverse or clone those trees.
- Imported text is wrapped and labeled as untrusted source material.
- Common secret patterns are replaced before content reaches normal output.
- A private provenance manifest is kept separate from the shareable manifest.
- Verification recomputes hashes, checks permissions and symlinks, and scans
  output again.
- No command writes into the Cowork source tree.

## Non-goals

This project does not defeat encryption, recover deleted cloud data, bypass
account controls, copy browser sessions, scrape the Claude UI, impersonate a
user, or guarantee perfect secret/PII detection.
