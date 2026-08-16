# Supported Sources

## Cowork local session roots

The experimental Cowork adapter looks only in these roots unless the user
provides an explicit override:

- macOS: `~/Library/Application Support/Claude/local-agent-mode-sessions/`
- Windows MSIX: `%LOCALAPPDATA%/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/local-agent-mode-sessions/`
- Windows classic roaming: `%APPDATA%/Claude/local-agent-mode-sessions/`
- Windows classic local: `%LOCALAPPDATA%/Claude/local-agent-mode-sessions/`
- Linux: `~/.config/Claude/local-agent-mode-sessions/`

Expected session layout:

```text
<root>/<account-id>/<workspace-id>/
  spaces.json
  spaces/<space-id>/
    memory/                         # project-scoped memory
  local_<session-id>.json
  local_<session-id>/
    .claude/projects/<encoded-project>/<cli-session-id>.jsonl
    audit.jsonl
    memory/                         # session-scoped memory
    uploads/                        # files supplied to the selected session
    outputs/                        # files produced by the selected session
```

Cowork's local format is undocumented. A format mismatch is a stop condition,
not permission to scan broader application storage.

`<space-id>` must come from the exact selected session's valid top-level
`spaceId`. It is resolved only beneath that session's workspace. A same-looking
ID in a sibling workspace, a nested display object, or a project label is not a
filesystem selector.

Inventory does not open `spaces.json` or any memory, upload, or output body.
Its memory count therefore describes only session-local folders located from
the recognized session layout. A capture preview can report the metadata-only
count for exact project memory after individual sessions are selected.

## Captured by default after selection

- allowlisted task metadata without account email/name
- title, timestamps, and project/space mapping
- project instructions from a unique exact workspace `spaces.json` match;
  when the registry is absent or its exact match has no instructions, inline
  instructions from that exact selected session metadata are the fallback
- user and assistant text from the selected conversation
- session memory files detected as UTF-8 text after selection
- project memory detected as UTF-8 text under the exact
  `workspace/spaces/<spaceId>/memory/` root after selection
- files detected as UTF-8 text in that session's `uploads/` and `outputs/`,
  regardless of extension and within limits
- allowlisted binary images, PDFs, Office documents, audio, and video:
  `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.pdf`, `.docx`, `.pptx`, `.xlsx`,
  `.mp3`, `.wav`, `.m4a`, `.mp4`, and `.mov`
- hashes and provenance for generated output

Tool calls and results are excluded rather than executed or reproduced. If
multiple selected sessions resolve to the same project-memory directory, each
source file is captured once and its related opaque sessions are recorded in
provenance.

A duplicate exact ID in `spaces.json` is ambiguous and causes registry
instructions to be skipped without using the inline fallback. Sessions without
a usable project/space ID remain separate; titles and display labels are never
used to guess a project or locate project memory.

When valid top-level `spaceId` metadata exists, only that canonical value may
select a registry entry. If it is absent, legacy association aliases are used
only when every available alias agrees on one exact value. Conflicts fail
closed. A generic inline `instructions` field is eligible only inside a typed
`space` or `project` object; generic session/conversation containers must use
the explicit `spaceInstructions` or `customInstructions` fields.

Default capture limits are 32 MiB per transcript, 10,000 messages, 12,582,912
Unicode characters of transcript text, 100 artifact files total, 10 MiB per
artifact, and 100 MiB of artifacts total. The preview reports the exact limits
and binds them into its approval token.

## Excluded by default

- raw task metadata and raw transcript JSONL
- `systemPrompt`
- tool inputs, tool results, shell environment, and file-history snapshots
- subagent transcripts
- external `userSelectedFolders`; their basenames may be shown as references,
  but their contents are never traversed or copied
- workspace/global memory such as `agent/memory/`, unmatched sibling project
  memory, and memory selected only by a display label
- files reached through symlinks or represented by hard links
- files over configured limits or with denied credential-bearing names
- non-text files whose extension is not in the binary allowlist above

Skipped oversized, symlinked, hardlinked, protected, special, unreadable, and
non-text/unallowlisted items produce bounded warnings without printing their
content. File-count, depth, per-file, and total-byte limits still apply to all
selected artifacts, including project memory.

## Optional hardlinked-upload compatibility

Cowork installations may represent session uploads as hardlinks. They
remain skipped by default because another pathname outside Cowork may refer to
the same source inode. A user can opt in for selected session uploads only:

```bash
cowork-ai-os capture \
  --source "<supported-root>" \
  --session "<opaque-id>" \
  --output "<fresh-capture>" \
  --include-hardlinked-uploads
```

Run that command as a dry-run first, then repeat the same flag with `--apply`
and its matching approval token. The flag, file identity, exact link count,
limits, and destination are bound to the token. Accepted files are read through
secure no-follow directory descriptors and written as fresh, single-link
by-value copies. If the platform cannot provide that secure traversal, they
remain skipped.

This option never admits hardlinked session memory, project memory, outputs,
symlinks, special files, protected paths, oversized files, or binary formats
outside the allowlist. It does not discover or copy the other names attached to
the source inode.

## Never supported

- Cookies, Local Storage, Session Storage, IndexedDB, browser profiles, or
  Keychain/DPAPI data
- buddy tokens, OAuth material, Claude credentials, API keys, or session reuse
- undocumented web, GraphQL, or private Claude APIs
- UI scraping or automated browser harvesting
- writing/importing sessions back into Claude Desktop
- destructive source cleanup

## Cloud-only gaps

The local adapter cannot recover content that Claude did not store locally.
Use Anthropic's supported account export or manual file download for those
items, then place the reviewed files into the AI OS Inbox.
