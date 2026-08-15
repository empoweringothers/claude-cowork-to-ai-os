# Account and admin visibility

The account active in Claude Code matters. Local extraction can be offline, but
content later read by Claude Code is processed under that account and its
organization policy. This page covers Claude's documented controls; it does not
cover employer device management, endpoint security, network monitoring, or
legal ownership rules.

## Before opening recovered content

Run `claude auth status --text` or use `/status` in Claude Code. Also check for
an inherited `ANTHROPIC_API_KEY`, which can select API authentication instead of
the subscription account you expected.

For people who use both personal and work Claude Code, keep separate state:

```bash
alias claude-personal='CLAUDE_CONFIG_DIR="$HOME/.claude-personal" claude'
alias claude-work='CLAUDE_CONFIG_DIR="$HOME/.claude-work" claude'
```

`CLAUDE_CONFIG_DIR` separates Claude Code credentials, settings, history,
plugins, and memory. It does not isolate project files or operating-system
access, so keep personal and work AI OS folders physically separate too.

Sources: [Claude Code authentication](https://code.claude.com/docs/en/authentication)
and [environment variables](https://code.claude.com/docs/en/env-vars).
Checked 2026-08-14.

## What a Team or Enterprise organization may monitor

Team and Enterprise owners can configure Cowork OpenTelemetry export. Once
configured, it can stream:

- full user prompts;
- tool and MCP calls, including parameters, result status, and timing;
- file paths Cowork reads, modifies, or touches;
- invoked skills and plugins;
- human approval or rejection decisions;
- model, token, cost, duration, and error metadata;
- user email attributes.

Anthropic says no OpenTelemetry events flow until an admin configures an OTLP
endpoint. This is prospective monitoring, so do not assume a work Cowork prompt
or a touched path is private merely because it also exists on the local
computer.

Source: [Monitor Claude Cowork activity with OpenTelemetry](https://support.claude.com/en/articles/14477985-monitor-claude-cowork-activity-with-opentelemetry).
Checked 2026-08-14.

## Enterprise Compliance API

Claude Enterprise compliance reviewers can retrieve Cowork and Claude Code
session transcripts through beta Compliance API endpoints:

- local Cowork and Claude Code sessions captured while the user is signed into
  the Enterprise organization; and
- remote Cowork sessions that run in Anthropic-managed cloud environments.

The returned local transcript can include user prompts, assistant text, tool
calls, and text tool results. It omits thinking, replaces the system prompt with
a marker, and omits binaries, tool definitions, and MCP configuration. Local
capture is tied to Compliance API enablement and does not backfill a personal
account. The Enterprise endpoints are an administrator/compliance surface, not
a member migration or import tool.

Source: [Retrieve session transcripts](https://platform.claude.com/docs/en/manage-claude/compliance-sessions).
Checked 2026-08-14.

## Personal-account use

A personal Free, Pro, or Max account is not inside an employer's Team or
Enterprise Claude administration plane. That does **not** grant permission to
move employer, client, regulated, or confidential data into it. It also does
not prevent a managed computer or network from recording activity outside
Claude.

Before capture, decide who owns the material and which account is allowed to
process it. If the answer is ambiguous, stop with metadata inventory only.
