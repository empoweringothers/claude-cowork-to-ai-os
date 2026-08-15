# Manual UI fallback

Use this only for user-visible content that local recovery cannot verify.

1. In **Projects**, select **+ > Import from project** to save one Claude chat
   project's files and instructions to a local Cowork project. Bulk import is
   not supported.
2. In each important Cowork session, ask Claude to write a self-contained
   handoff folder containing `HANDOFF.md`, candidate project instructions,
   decisions, open loops, sources, selected artifacts, and a manifest. Require
   it to exclude credentials, auth state, hidden prompts, and unrelated data.
3. Copy visible **Settings > Cowork > Global instructions** and each selected
   project's visible instructions into separate review files. Do not attempt to
   reconstruct them from a raw `systemPrompt`.
4. Use visible Copy/Download controls for artifacts and generated files.
5. Export reviewed memory from **Settings > Memory**, or the legacy **Settings
   > Capabilities > Memory** flow.
6. Record scheduled-task name, prompt, approval mode, cadence, model, and folder
   manually. Preserve original skill/plugin source, and reconnect apps without
   copying tokens or OAuth state.
7. For Free, Pro, or Max, **Settings > Privacy > Export data** provides a
   sensitive backup/source archive. It cannot be imported into another personal
   Claude account.

Same-email personal-to-Team/Enterprise migration is a separate supported,
one-way option. It still excludes Cowork task/session history, locally stored
Cowork data, custom skills, app authentication, custom connectors, published
artifacts, and Claude Code cloud sessions.

Official sources, checked 2026-08-14:

- https://support.claude.com/en/articles/9267400-move-your-personal-claude-account-to-a-team-or-enterprise-organization
- https://support.claude.com/en/articles/14116274-organize-your-tasks-with-projects-in-claude-cowork
- https://support.claude.com/en/articles/12123587-import-and-export-your-memory-from-claude
- https://support.claude.com/en/articles/13854387-schedule-recurring-tasks-in-claude-cowork
- https://support.claude.com/en/articles/9450526-export-your-claude-data
