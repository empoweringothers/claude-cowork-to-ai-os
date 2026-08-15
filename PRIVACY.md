# Privacy

## The short version

- Source Cowork folders are read-only.
- Nothing is uploaded by this repository's extractor.
- No telemetry, analytics, update check, remote API, browser automation, or
  account token is used.
- Only sessions selected by the user may be captured.
- Captured data can still be sensitive. Keep the destination private.

## Local extraction versus AI processing

The CLI runs locally and has no networking code. Claude Code is a separate
application. If the user asks Claude Code to read a captured conversation or
file, that selected material is processed under the active Claude account and
its applicable organization settings. The plugin must disclose this before the
first content-bearing read.

## Data never requested

The project must never ask for passwords, passkeys, recovery codes, API keys,
session cookies, OAuth tokens, browser profiles, Keychain records, Claude
credential files, or payment data. Because a selected conversation or file may
already contain sensitive values, denied filenames, redaction, and final human
review remain required; pattern matching is not a guarantee.

The source adapter is limited to explicitly supported Cowork session roots. It
must not crawl the parent Claude application-data directory.

## Output handling

Generated AI OS folders are private working data, not public repository
content. Default permissions are owner-only where the operating system supports
them. `.ai-os/private/` contains local path provenance and must stay ignored by
Git. The generated root `.gitignore` also excludes `Inbox/Cowork-Import/` and
`Projects/Cowork-Import/` so a new repository does not stage recovered
conversations, filenames, or project labels by accident.

That ignore file protects the raw import and private provenance only.
`Inbox/REVIEW.md` and anything promoted into `CLAUDE.md`, `USER.md`, `STATE.md`,
`Knowledge/`, `Decisions/`, or other working files remain stageable. Use a
private repository if Git is enabled. Approval to promote an item into the AI
OS is never approval to publish or share it.

The shareable manifest uses opaque references and output hashes. The private
manifest may contain source-relative paths and human-readable session/project
labels; it is stored separately and is not shareable by default.

## Redaction limits

Pattern-based redaction can reduce accidental exposure, but it cannot prove
that content is safe. Names, confidential strategy, private conversations, and
unusual credential formats may not match a pattern. Human review remains
required before changing accounts, repositories, or sharing the output.

## Deleting output

The tool never deletes source data. A user can delete the newly created AI OS
or capture folder with ordinary file tools. This repository intentionally does
not provide a purge-source command.
