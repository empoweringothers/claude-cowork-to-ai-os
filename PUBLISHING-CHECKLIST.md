# Publishing checklist

Do not make the repository public or publish a release until every item passes.

## Privacy

- [ ] Start from the clean standalone repository—not the private Brain OS or
      memory-compiler worktree.
- [ ] `git status --short` contains only intended public source files.
- [ ] Search for real names, emails, account IDs, UUIDs, home paths, transcript
      phrases, tokens, and organization-specific material.
- [ ] Verify all tests use fictional fixtures.
- [ ] Confirm `.ai-os/private/`, captures, inventories, and generated AI OS
      folders are ignored.
- [ ] Run GitHub secret scanning or an equivalent local scanner.

## Functionality

- [ ] Run the unit-test matrix on macOS and Windows.
- [ ] Prove inventory does not read transcript or memory bodies.
- [ ] Prove dry-run writes zero bytes.
- [ ] Prove source names, content, hashes, mtimes, and permissions do not change.
- [ ] Prove symlink escapes and source/output overlap fail closed.
- [ ] Prove secret canaries never appear in output, logs, or exceptions.
- [ ] Validate the marketplace and plugin with Claude Code.
- [ ] Forward-test the skill with synthetic Cowork sessions only.

## Release trust

- [ ] Bump matching versions in plugin manifest, marketplace, and
      `RELEASE.json`.
- [ ] Commit a clean tree and tag `v<version>` at that exact commit.
- [ ] Build the release archive from the tag.
- [ ] Confirm the archive contains only the intended filtered regular blobs
      from that exact Git tree plus deterministic release metadata; ignored
      captures and an external symlink canary must be absent/rejected.
- [ ] Generate SHA-256 checksums and the completed paste message.
- [ ] Confirm the completed paste message contains no `{{PLACEHOLDER}}` values,
      records the exact tag and full source commit, and installs only from the
      release ZIP after its SHA-256 and internal manifest pass.
- [ ] Verify the archive on a second clean account or machine before sharing.
- [ ] Publish the release notes with known limitations and unsupported sources.

## Public repository

- [ ] Create `empoweringothers/claude-cowork-to-ai-os` as public only after the
      exact initial tree is reviewed.
- [ ] Enable private vulnerability reporting and secret scanning.
- [ ] Do not enable automated publication from unreviewed pull requests.
- [ ] Add the stable tagged release to the public AI Brain catalog only after
      verification.
