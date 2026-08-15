# Account and admin visibility

Before a content-bearing capture, verify the account with `claude auth status
--text` or `/status`. Check whether `ANTHROPIC_API_KEY` is selecting API
authentication unexpectedly. Keep work and personal Claude Code state in
separate `CLAUDE_CONFIG_DIR` values and keep their project folders physically
separate.

Team and Enterprise owners can configure Cowork OpenTelemetry export. Once
configured, it can include full prompts, tool/MCP calls and parameters, touched
file paths, skills/plugins, approval decisions, user email, model/tokens/cost,
timing, and errors. Anthropic says no OTel events flow until an admin configures
an endpoint.

Enterprise Compliance API session endpoints are in beta. They can retrieve
local Cowork and Claude Code transcripts captured while a user is signed into
the Enterprise organization, plus remote Cowork sessions. This is an admin
compliance surface, not a migration/import mechanism.

Using a personal account does not create permission to move employer, client,
regulated, or confidential information. It also does not bypass device or
network monitoring outside Claude.

Official sources, checked 2026-08-14:

- https://code.claude.com/docs/en/authentication
- https://code.claude.com/docs/en/env-vars
- https://support.claude.com/en/articles/14477985-monitor-claude-cowork-activity-with-opentelemetry
- https://platform.claude.com/docs/en/manage-claude/compliance-sessions
