# Privacy boundary

The CLI is local and network-free. The AI organization phase is different:
selected content read by Claude Code is handled by the active Claude account
and organization. Confirm the intended profile before the first content read.

## Safe default

1. Inventory metadata only.
2. Select a profile and individual sessions.
3. Preview the capture, including exact project-memory metadata.
4. Capture redacted content locally.
5. Review candidate memory and instructions.
6. Promote only approved items.

## Never move

- passwords, tokens, cookies, credentials, recovery codes, private keys;
- browser storage or whole application profiles;
- content the user does not own or lacks permission to move;
- live imported scripts, hooks, skills, or tool commands;
- personal content into a work OS, or work content into a personal OS, by
  convenience.

## Filesystem-link boundary

Symlinks are never followed. Hardlinks are skipped unless the user explicitly
previews `--include-hardlinked-uploads`; that option applies only to regular
files in selected session upload folders and writes fresh by-value copies.
Hardlinked memory, project memory, and outputs remain excluded. Linked Cowork
folders are references, not permission to traverse or duplicate external
trees.

## Honest claim

Say: "This tool recovered the selected local material it could verify."

Do not say: "This recovered everything Claude knows" or "this migrated the
account."
