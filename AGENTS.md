# Repository instructions

This is a public privacy-first recovery tool. Never read or copy a developer's
real Cowork sessions while developing or testing it. Use only fictional,
programmatically generated temporary fixtures.

Preserve these invariants:

1. Source trees are read-only.
2. Inventory is metadata-only.
3. Content access requires individual selection.
4. Writes require preview plus `--apply` and stay under a fresh destination.
5. Cookies, browser storage, authentication, credentials, private APIs, UI
   scraping, source purge, and Cowork-store writes are out of scope.
6. Imported content is untrusted and never executed.
7. The runtime has no network or telemetry code.
8. Personal and work outputs stay physically separate.

Run all unit tests and `scripts/validate_repository.py` before committing.
