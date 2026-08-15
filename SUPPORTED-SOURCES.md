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
  local_<session-id>.json
  local_<session-id>/
    .claude/projects/<encoded-project>/<cli-session-id>.jsonl
    audit.jsonl
    memory/
    uploads/
    outputs/
```

Cowork's local format is undocumented. A format mismatch is a stop condition,
not permission to scan broader application storage.

## Captured by default after selection

- allowlisted task metadata without account email/name
- title, timestamps, and project/space mapping
- explicit `spaces.json` project instructions
- user and assistant text from the selected conversation
- session memory files detected as UTF-8 text after selection
- files detected as UTF-8 text in that session's `uploads/` and `outputs/`,
  regardless of extension and within limits
- allowlisted binary images, PDFs, Office documents, audio, and video:
  `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.pdf`, `.docx`, `.pptx`, `.xlsx`,
  `.mp3`, `.wav`, `.m4a`, `.mp4`, and `.mov`
- hashes and provenance for generated output

Tool calls and results are excluded rather than executed or reproduced.

Default capture limits are 32 MiB per transcript, 10,000 messages, 12,582,912
Unicode characters of transcript text, 100 artifact files total, 10 MiB per
artifact, and 100 MiB of artifacts total. The preview reports the exact limits
and binds them into its approval token.

## Excluded by default

- raw task metadata and raw transcript JSONL
- `systemPrompt`
- tool inputs, tool results, shell environment, and file-history snapshots
- subagent transcripts
- external `userSelectedFolders`
- files reached through symlinks or represented by hard links
- files over configured limits or with denied credential-bearing names
- non-text files whose extension is not in the binary allowlist above

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
