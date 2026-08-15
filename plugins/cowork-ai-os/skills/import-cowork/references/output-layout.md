# AI OS output layout

## Core files

| Path | Purpose | Promotion rule |
|---|---|---|
| `START-HERE.md` | Human reading order and recovery status | Generated, factual only |
| `CLAUDE.md` | Stable operating rules for Claude Code | Human-approved rules only |
| `HOME.md` | Map of projects, knowledge, and memory | Generated index |
| `STATE.md` | Current priorities, blockers, and open loops | Human-approved, time-stamped |
| `USER.md` | Durable user context and preferences | Human-approved, avoid sensitive excess |
| `OBJECTIVE.md` | Current result the system serves | Human-approved |
| `MOTIVES.md` | Purpose and decision values | Human-approved |
| `PRIVACY.md` | Local data boundary | Template plus user choices |

## Working directories

- `Inbox/`: unclassified material and the review queue. Nothing here is a
  current instruction merely because it came from a prior chat.
- `Projects/Cowork-Import/index-<opaque>/`: a generated, integrity-checked index
  linking selected source material still held in the Inbox. Promote reviewed
  project context into a separate human-owned project folder.
- `Knowledge/`: reusable factual reference promoted from reviewed sources.
- `Memory/Sessions/`: readable session records that are not project-specific.
- `Decisions/`: dated, reviewed decisions with rationale and source links.
- `Outputs/`: new work made from the recovered OS, not imported originals.
- `System/`: permissions, schema, doctor notes, and operating policy.

## Internal provenance

```text
.ai-os/
  manifests/       integrity manifests and hashes
  reports/         optional reviewed copies of externally written reports
  private/         source-relative paths and local mappings; owner-only
```

Never create cross-profile indexes, symlinks, or hardlinks. Personal and work
AI OS folders must be physically separate.

## Source citations

Promoted Markdown should cite an opaque source reference and a stable locator:

```text
source: Inbox/Cowork-Import/sessions/<opaque>/chat.md :: Message 0018
```

Keep full local paths only in `.ai-os/private/`.
