# Release cut: command sequence

Read this before cutting `vX.Y.Z`. Every numbered step is an explicit-approval checkpoint: ask before executing, even if a previous step in the same session was approved.

Assumes you are on `main`, working tree clean, and `[Unreleased]` in `CHANGELOG.md` reflects everything merged since the last tag. If not, stop and reconcile first.

## 0. Pre-flight (read-only, no approval needed)

```bash
git fetch --tags origin
git checkout main && git pull --ff-only
git status                                    # must be clean
git log --oneline $(git describe --tags --abbrev=0)..HEAD
git config user.email                         # must end in @users.noreply.github.com
gh run list --branch main --limit 5           # main CI must be green
```

If `git config user.email` is wrong, prefix every `git commit`/`git tag` below with `-c user.email=<noreply-email> -c user.name=<username>`. Canonical values for this repo: see `.devcontainer/devcontainer.json`.

## 1. Cut commit: ASK BEFORE COMMITTING

Edit `CHANGELOG.md`:

- Rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` (today's UTC date).
- At the bottom of the file, update the compare links:
  - Add a new `[Unreleased]: .../compare/vX.Y.Z...HEAD` line.
  - Update the existing `[X.Y.Z]: .../compare/v<prev>...vX.Y.Z` line (or add it).

Then:

```bash
git add CHANGELOG.md
git diff --cached                             # show user; ASK
git commit -m "docs(changelog): cut vX.Y.Z release"
```

Do not add a `Co-authored-by` trailer to release-cut commits.

## 2. Push the cut commit: ASK BEFORE PUSHING

```bash
git push origin main
```

If `main` is protected and refuses direct pushes, open a PR titled `docs(changelog): cut vX.Y.Z release` and merge it. Do not tag until the cut commit is on `main`.

## 3. Wait for `main` CI green

```bash
gh run list --branch main --limit 3
gh run watch <run-id>                         # or poll until success
```

GoReleaser reads the tag's tree, not HEAD, but a red `main` usually means a broken release too. Do not skip.

## 4. Annotated tag: ASK BEFORE TAGGING

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git tag -v vX.Y.Z                             # confirm the tagger identity
```

The tagger line must end in `@users.noreply.github.com`. If not, delete and re-create with the inline `-c user.email=...` form (see SKILL.md, GH007 section).

## 5. Push the tag: ASK BEFORE PUSHING

```bash
git push origin vX.Y.Z
```

This fires `.github/workflows/release.yaml`. Watch it:

```bash
gh run list --workflow release.yaml --limit 3
gh run watch <run-id>
```

The release workflow needs `id-token: write` for cosign keyless signing (already wired). If it fails at the `sign` step, check that `sigstore/cosign-installer` is pinned and that the workflow has the OIDC permission.

## 6. Verify the release

```bash
gh release view vX.Y.Z
gh release view vX.Y.Z --json assets --jq '.assets[].name' | sort
```

Checklist:

- Release body is categorized: Features / Bug Fixes / Documentation / Dependencies / Other sections appear (if there were PRs for each). If the body is one flat list, PR labels are missing. Fix labels (see SKILL.md, "Re-categorizing"), then UI > Edit > "Generate release notes". Do not re-tag.
- All per-platform tarballs are present (`kfeatures_X.Y.Z_<os>_<arch>.tar.gz` for each goreleaser target).
- `checksums.txt` is present.
- Each artifact has a sibling `<artifact>.sigstore.json` bundle.
- `cosign verify-blob` against one tarball succeeds (see SKILL.md, "Verifying a release").

## Recovery

- Wrong identity on the cut commit, already pushed: amend with the noreply identity and force-push the branch (or open a fix PR). Do not tag yet.
- Wrong identity on the tag, not yet pushed: `git tag -d vX.Y.Z`, re-create with the inline `-c user.email=...` form.
- Wrong identity on the tag, already pushed: `git push --delete origin vX.Y.Z`, recreate locally with noreply, push again. The release workflow will re-fire; delete the bad GitHub Release first if one was created.
- CHANGELOG entry missing or wrong, tag already pushed: add the correction under a fresh `[Unreleased]` and ship it in the next release. Do not retroactively edit a shipped tag's CHANGELOG section.
