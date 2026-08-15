# Manual Claude UI fallback

Use this path when the local recovery tool cannot see an important session, or
when you prefer to review every item in Claude before saving it. UI export and
local recovery complement each other; neither is a universal account importer.

## First choose the account path

If a personal Claude account and a Team or Enterprise organization use the
same email address, Anthropic provides a one-way **Bring your data** migration.
Start in the organization account, then open **Settings > Account > Close your
personal account**. Chats, chat artifacts, projects and their files and
instructions, uploads, tasks, and eligible memory can move. Cowork task/session
history, locally stored Cowork data, custom skills, app authorizations, custom
connectors, published artifacts, and Claude Code cloud sessions do not.

If the accounts use different email addresses, Claude does not provide a
personal-account-to-personal-account migration. An account data export is a
backup/source archive and cannot be imported into another personal Claude
account.

Sources: [account migration](https://support.claude.com/en/articles/9267400-move-your-personal-claude-account-to-a-team-or-enterprise-organization),
[data export](https://support.claude.com/en/articles/9450526-export-your-claude-data),
and [email changes](https://support.claude.com/en/articles/8452276-how-do-i-change-the-email-address-associated-with-my-account).
Checked 2026-08-14.

## Save one Cowork project to a local folder

In Cowork, open **Projects**, select **+**, then **Import from project**. Choose
one Claude chat project, name it, and choose where it will be saved locally.
Claude transfers that project's files and instructions into a local Cowork
project. Bulk import is not currently supported.

For a project already tied to a local folder, preserve that folder directly.
Archiving the Cowork project removes its UI metadata but does not delete the
local folder. Cowork projects are not currently available as Claude Code
projects, so the durable handoff is the reviewed local folder and its AI OS
files.

Source: [Organize your tasks with projects in Claude Cowork](https://support.claude.com/en/articles/14116274-organize-your-tasks-with-projects-in-claude-cowork).
Checked 2026-08-14.

## Ask each important session for a handoff bundle

Connect a new, private folder and paste this into the Cowork session:

```text
Create a self-contained handoff bundle for this project in the connected
folder. Include:

- HANDOFF.md: purpose, current state, exact requirements, and how to resume
- CLAUDE-CANDIDATE.md: durable project rules only, under 200 lines
- DECISIONS.md: dated decisions, rationale, status, and source in this session
- OPEN-LOOPS.md: unfinished work, blockers, and the next resolved action
- SOURCES.md: links and file provenance
- artifacts/: only the project files and outputs I explicitly ask you to keep
- MANIFEST.md: every created file, its purpose, and whether content is explicit,
  inferred, stale, conflicting, or uncertain

Do not include passwords, API keys, tokens, cookies, OAuth data, browser or
account authentication, hidden system prompts, raw tool credentials, unrelated
personal memory, or material from another project. Do not invent missing
context. Quote or cite the originating message when practical. Leave proposed
instructions and decisions marked for human review rather than activating them.
```

Review the bundle in the file system before moving it to another account. A
handoff is a readable continuation source, not a way to resume the original UI
session.

## Copy visible instructions from the UI

Open **Settings > Cowork > Global instructions** and copy only the instructions
you intentionally wrote into an Inbox file for review. Do the same for the
visible instructions in each selected Cowork project or connected folder. Keep
global rules separate from project rules; a project-specific preference should
not silently become an account-wide instruction.

The local recovery tool intentionally does not extract a raw `systemPrompt`.
That field can combine product-owned hidden instructions with user context and
is not a safe or stable source for reconstructing user-authored rules.

Source: [Get started with Claude Cowork](https://support.claude.com/en/articles/13345190-get-started-with-claude-cowork).
Checked 2026-08-14.

## Download artifacts and generated files

Open each important artifact or generated file and use the visible **Copy** or
**Download** control. Preserve the original file rather than only a prose
summary. Live artifacts may depend on connected apps and should be converted or
downloaded to a durable static deliverable before an account change.

## Export memory separately

Depending on the UI version, open **Settings > Memory** or **Settings >
Capabilities > Memory**. Claude also documents asking it to write out its
memory verbatim, then saving that text locally. Import only reviewed,
work-appropriate entries; built-in memory import is experimental and does not
replace project-scoped Cowork memory.

Source: [Import and export your memory from Claude](https://support.claude.com/en/articles/12123587-import-and-export-your-memory-from-claude).
Checked 2026-08-14.

## Record scheduled tasks, skills, plugins, and connectors

- Under **Scheduled**, record each task's name, prompt, approval mode, cadence,
  model, and folder. Recreate only the tasks you still want; there is no
  documented bulk import/export flow.
- Preserve the original source or ZIP for custom skills. Review scripts before
  placing approved skills under a private AI OS or `.claude/skills/` folder.
- Reinstall approved plugins from their trusted source. Do not copy local
  plugin caches or automatically activate recovered hooks and MCP servers.
- Record connector names and non-secret URLs only. Reauthenticate in the
  destination account; never copy tokens, cookies, or OAuth state.

Source: [Schedule recurring tasks in Claude Cowork](https://support.claude.com/en/articles/13854387-schedule-recurring-tasks-in-claude-cowork).
Checked 2026-08-14.

## Request the official account export as a backup

For Free, Pro, or Max, open **Settings > Privacy > Export data**. The emailed
download link expires after 24 hours. Keep the raw archive outside the public
repository and treat it as sensitive. It can help recover ordinary chat and
account records, but it cannot be imported into another personal account and
must not be assumed to contain missing local Cowork history.

Source: [Export your Claude data](https://support.claude.com/en/articles/9450526-export-your-claude-data).
Checked 2026-08-14.
