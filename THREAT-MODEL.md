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
3. Following a symlink outside the selected session.
4. Copying credentials or secrets embedded in text or files.
5. Treating prompt injection inside an imported transcript as live
   instructions.
6. Writing into or corrupting Claude Desktop's undocumented storage.
7. Leaking raw paths or content through logs, manifests, HTML, exceptions, or
   Git.
8. A future Cowork format change causing the parser to select the wrong file.

## Controls

- Metadata-only inventory precedes every content read.
- Capture requires explicit session selection, `--apply`, and the matching
  approval token from a current dry-run preview.
- Approval binds both the identity of selected source files and the absence of
  optional metadata such as `spaces.json`; a newly appearing file invalidates
  the plan.
- Output must be outside all source roots and must not already contain data.
- Destination directories and files use no-follow directory handles where the
  platform supports them, so a parent symlink swap cannot redirect a write.
- The source adapter opens only supported metadata, transcript, memory,
  upload, and output paths.
- Symlinks, hard-linked files, and non-regular files are skipped.
- File count and size limits bound traversal.
- Authentication/browser-store names are denied even when nested in a selected
  directory.
- Raw system prompts, raw transcript JSONL, tool inputs, tool results, and
  external linked folders are excluded by default.
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
