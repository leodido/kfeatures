---
name: kfeatures-release-flow
description: Cut a kfeatures release. Covers the staged CHANGELOG/commit/tag/push workflow with explicit-approval checkpoints, GH007 / noreply identity recovery, PR-label-driven categorized release notes, and cosign keyless verification. Use when the user says "cut a kfeatures release", "tag vX.Y.Z", "release notes are uncategorized", "regenerate release notes", "verify a kfeatures download". Triggers on "kfeatures release", "cut release", "tag vX", "labeler", "release.yml categories", "cosign verify-blob", "GH007".
---

# kfeatures release flow

For per-PR conventions read `AGENTS.md` and `CONTRIBUTING.md`. This skill covers the release cut.

## Hard rules

1. Never commit, push, tag, or merge without explicit user approval per step. A previous "yes" does not authorize the next operation. Ask again.
2. CHANGELOG `[Unreleased]` is the staging area. Every user-visible change lands there in the PR that introduces it. The release-cut PR only renames the section.
3. Tag pushes create a GitHub Release via GoReleaser (`push: tags: v*`). Confirm `gh release view vX.Y.Z` shows the right body before treating the release as done.
4. The release workflow reads the tag's tree, not HEAD. Do not push fixes to `main` after tagging and expect them in the release.

## Workflow

Read `references/release-cut.md` for the command sequence. Steps:

1. Cut commit: rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`, update compare links at bottom of `CHANGELOG.md`. Subject: `docs(changelog): cut vX.Y.Z release`. Ask before committing.
2. Push the cut commit to `main`. Ask before pushing.
3. Wait for `main` CI green before tagging.
4. Annotated tag with noreply identity (see below). Ask before tagging.
5. Push the tag. Ask before pushing.
6. Verify `gh release view vX.Y.Z` shows the categorized body, all per-platform tarballs, `checksums.txt`, and a `.sigstore.json` sibling for each.

## GH007: noreply identity

The release commit and tag must be authored with the maintainer's GitHub-noreply email (`<id>+<username>@users.noreply.github.com`), not a personal email. The devcontainer's `postCreateCommand` sets `user.email` and `user.name` accordingly; the canonical values for this repo live in `.devcontainer/devcontainer.json`. Verify before tagging:

```bash
git config user.email   # must end in @users.noreply.github.com
git config user.name
```

If the identity is wrong (e.g. running outside the devcontainer), use the inline form for each git operation:

```bash
git -c user.email=<noreply-email> -c user.name=<username> commit -m "..."
git -c user.email=<noreply-email> -c user.name=<username> tag -a vX.Y.Z -m "vX.Y.Z"
```

Symptom of a wrong identity on push: `remote: error: GH007: Your push would publish a private email address.` Recover by amending the commit or re-creating the tag with the noreply identity, then re-push.

## Categorized release notes

GitHub generates the release body from PR labels read at the tag, via `.github/release.yml`. Two files must stay in sync:

- `.github/workflows/labeler.yml`: auto-labels new PRs from their Conventional Commit prefix. The `prefixMap` and the `*(deps)` / `*(dependencies)` scope override govern what counts as `dependencies` vs `chore`.
- `.github/release.yml`: the category list (Breaking / Features / Bug Fixes / Documentation / Dependencies / Other) and the `exclude.labels` list (`no-releasenotes`, `chore`).

Add a new prefix or category in both files in the same PR.

### Re-categorizing an already-shipped release

The labeler is additive and only fires on `pull_request: [opened, edited]`. Old PRs need manual label fixes:

1. List PRs in the release range: search for `merged:>=YYYY-MM-DD base:main`.
2. For each, set the right label via `gh pr edit <n> --add-label <label> --remove-label <stale>`. The MCP `github_pull_request_*` tools work too and dodge anonymous rate limits.
3. Regenerate the body: GitHub UI > Release > Edit > "Generate release notes". It re-reads `release.yml` at the tag and the current PR labels. Do not re-tag.

## Verifying a release (cosign)

Released artifacts are signed via cosign keyless using GitHub's OIDC token. Each artifact has a sibling `<artifact>.sigstore.json` bundle. Verify with the commands in `README.md#verifying-releases`:

```bash
cosign verify-blob \
  --bundle kfeatures_<version>_<os>_<arch>.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/leodido/kfeatures/.github/workflows/release.yaml@refs/tags/v<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  kfeatures_<version>_<os>_<arch>.tar.gz
```

Requires cosign v2.0+ on the verifier side. The certificate identity pins the workflow path and the tag: a different tag's bundle fails verification against this one's identity.

## References

- `references/release-cut.md`: command sequence for steps 1-6, with the explicit-approval checkpoints called out.
