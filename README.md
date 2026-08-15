# Claude Cowork to AI OS

Recover the parts of your local Claude Cowork work that you choose—project
instructions, session memory, conversations, uploads, and generated files—and
place them into a private, readable AI OS for Claude Code.

This is a community project from Empowering Others. It is not an Anthropic
product and it does not migrate a Claude account.

Runtime requirement: Python 3.9 or newer. The extractor uses only Python's
standard library and does not install packages or make network calls.

## What it does

1. Finds local Cowork sessions without opening chat bodies.
2. Creates a metadata-only inventory in JSON, Markdown, and an offline HTML
   viewer.
3. Lets you choose sessions before any conversation or file content is read.
4. Captures only the selected content into a new destination.
5. Redacts common secret patterns, skips symlinks and credential-bearing files,
   and records provenance and hashes.
6. Builds a Markdown AI OS that Claude Code can navigate.

The source Cowork directories are read-only. The tool never signs in, changes
accounts, writes into Claude Desktop, or calls an undocumented web API.

## Quick start after release

The public marketplace commands will be available after the first tagged
release:

```text
/plugin marketplace add empoweringothers/claude-cowork-to-ai-os@v0.1.0
/plugin install cowork-ai-os@empowering-others-ai
/reload-plugins
/cowork-ai-os:import-cowork
```

Plugin installation requires a reload before the new skill is available. The
release's generated `COWORK-AI-OS-SETUP-MESSAGE.txt` is the verified path: it
downloads the exact release archive, checks its SHA-256 and internal manifest,
then installs from that local verified copy. After installation, run
`/reload-plugins`, then start the import command above.

The shorter marketplace command is convenient once you already trust the tag.
Do not substitute `main` or a raw commit SHA after `owner/repo@`; Claude's
GitHub marketplace refs support branches and tags.

For local development:

```bash
claude --plugin-dir ./plugins/cowork-ai-os
```

Then run `/cowork-ai-os:import-cowork` inside Claude Code.

Claude Code supports shareable plugins with skills and local executables, and
GitHub-hosted marketplaces can be pinned with `owner/repo@ref`. See Anthropic's
[plugin guide](https://code.claude.com/docs/en/plugins) and
[marketplace guide](https://code.claude.com/docs/en/plugin-marketplaces).

## Privacy boundary

The extractor itself has no network or telemetry code. However, when you ask
Claude Code to read or reorganize captured content, that selected content is
processed through the Claude account and organization currently active in
Claude Code. Review your account, employer, and data-retention rules first.

The tool will not deliberately open or copy these as source stores/artifacts:

- Cookies, browser Local/Session Storage, IndexedDB, Keychain items, Claude
  credentials, or credential-bearing files;
- the complete Claude Desktop application-data folder;
- hidden/system prompts or raw tool inputs and results by default;
- linked external folders;
- anything from a session you did not select.

A selected conversation or ordinary text file may already contain a sensitive
value. Common patterns are redacted, but human review is still required.

Do not move employer-owned, client, ministry, health, financial, or other
confidential material into a personal account without permission. Read
[`PRIVACY.md`](PRIVACY.md) and [`THREAT-MODEL.md`](THREAT-MODEL.md) before using
real data.

## What the AI OS looks like

```text
AI-OS/
  START-HERE.md
  CLAUDE.md
  HOME.md
  STATE.md
  USER.md
  OBJECTIVE.md
  MOTIVES.md
  Inbox/
  Projects/
  Knowledge/
  Memory/Sessions/
  Decisions/
  Outputs/
  System/
  .ai-os/
    manifests/
    reports/
    private/
```

The importer preserves source material and provenance. It does not silently
turn old chat statements into current facts, decisions, commitments, or
instructions. They remain in the imported Inbox beside a review worksheet
until a person deliberately promotes them.

## Current support

- macOS Claude Desktop/Cowork local sessions: MVP target
- Windows and Linux paths: supported with synthetic tests; real-world reports
  welcome
- native Cowork/Claude Code JSONL transcripts: supported when present
- Cowork `audit.jsonl`: conservative fallback
- `spaces.json` project names and explicit project instructions: supported
- session `memory/`, `uploads/`, and `outputs/`: selected capture
- cloud-only Cowork sessions or content absent from local storage: not
  recoverable by this tool

See [`SUPPORTED-SOURCES.md`](SUPPORTED-SOURCES.md) for the exact boundary.

If a session is cloud-only, missing, or no longer parseable, use the supported
Claude UI steps in [`docs/MANUAL-UI-FALLBACK.md`](docs/MANUAL-UI-FALLBACK.md).
Before moving anything between personal and organization accounts, read
[`docs/ACCOUNT-AND-ADMIN-VISIBILITY.md`](docs/ACCOUNT-AND-ADMIN-VISIBILITY.md).

## Why another project?

Existing open-source projects solve important pieces:

- [AgentsView](https://github.com/kenn-io/agentsview) provides a strong local
  Cowork session UI and search experience.
- [cowork2code](https://github.com/looptech-ai/cowork2code) demonstrates that a
  local Cowork transcript can be re-homed as a Claude Code session.
- [claude-cowork-export](https://github.com/PeriChu/claude-cowork-export)
  provides broad archival formats and a cross-account continuation seed.
- [claude-code-profiles](https://github.com/quinnjr/claude-code-profiles)
  separates Claude Code profiles.

This project focuses on a narrower public promise: **selective recovery into a
reviewable AI OS, with the safe path as the default.** See
[`ACKNOWLEDGMENTS.md`](ACKNOWLEDGMENTS.md).

## Development

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_repository.py
claude plugin validate .
claude plugin validate ./plugins/cowork-ai-os
```

All fixtures must be fictional. Never add a real Cowork transcript, account ID,
email, personal path, token, or recovered file to this repository.

## Status

`0.1.0` is a pre-release MVP. Cowork's local format is undocumented and may
change. The doctor and inventory stages fail closed when the format is not
recognized; source data remains untouched.

## License

MIT. See [`LICENSE`](LICENSE).
