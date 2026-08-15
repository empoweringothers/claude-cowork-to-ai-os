# Contributing

## First rule

Never contribute real Cowork data. That includes transcripts, metadata,
account/workspace/session IDs, names, emails, paths, uploaded/generated files,
screenshots, cookies, tokens, or hashes derived from private values.

Use fictional fixtures with reserved example domains and visibly synthetic
UUIDs.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_repository.py
claude plugin validate .
claude plugin validate ./plugins/cowork-ai-os
```

## Product boundaries

Pull requests must preserve these defaults:

- metadata-only inventory before content access;
- individual session selection;
- source read-only and destination-only writes;
- dry-run/preview before apply;
- no browser/auth stores, private APIs, or UI scraping;
- no source purge or Cowork database mutation;
- no execution of imported content;
- no telemetry or runtime network calls;
- no silent mixing of personal and work profiles.

New source adapters require synthetic fixtures, format documentation, path
containment tests, and an explicit support-level label.
