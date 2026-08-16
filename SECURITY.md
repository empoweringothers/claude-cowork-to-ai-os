# Security Policy

## Supported versions

Only the newest tagged release is supported. The current supported MVP release
is `v0.1.1`.

## Report a vulnerability or accidental exposure

Use GitHub's private vulnerability-reporting feature. Do not open a public
issue containing a transcript, local path, account identifier, email, secret,
or recovered file.

## Security design

- Source sessions are read-only.
- Destination writes require `--apply` plus the matching token from a current
  dry-run preview.
- The extractor contains no networking or telemetry code.
- Credential and browser-state paths are denied.
- Symlinks and special files are skipped.
- Source reads use handle-bound containment on POSIX and Windows so a raced
  parent link cannot redirect the opened file outside the selected root.
- Public tests use fictional fixtures only.
- Release messages record the tag and full source commit, then pin the code
  actually installed by verifying the release archive's SHA-256 and internal
  file manifest before adding it as a local marketplace.

The release archive is not a safe place for recovered data. It contains only
the intended public repository files—including the plugin, documentation,
release scripts, and synthetic tests—and never recovered data.
