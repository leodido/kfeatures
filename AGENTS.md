# AGENTS.md

Notes for AI coding agents working in this repository. Human contributors
should follow [CONTRIBUTING.md](CONTRIBUTING.md); the conventions below
exist because agents need them spelled out.

## Documentation split

Two top-level Markdown files have distinct audiences. Do not mix them.

- **`README.md`** is user-facing. Keep it focused on: pitch, comparison,
  installation, usage examples (runnable, copy-pasteable), CLI, what the
  library detects, stability, requirements, and license. New end-user
  capability ⇒ add a usage example here.
- **`CONTRIBUTING.md`** is contributor-facing. It owns the API model
  (`Check` vs `ProbeWith`), the feature-addition review checklist, the
  frozen `FromELF` contract, the gated-vs-probe-only classification
  snapshot, and the development workflow. New API governance rule, new
  invariant, or new internal contract ⇒ goes here, not in the README.

If a change adds a new public symbol that affects both audiences, update
both files: the runnable example in `README.md`, the governance/contract
note in `CONTRIBUTING.md`.

## Release workflow

Tags drive the `releasing` GitHub Actions workflow
(`.github/workflows/release.yaml`, triggered on `push: tags: v*`). The
maintainer cuts releases by:

1. Renaming `[Unreleased]` to `[X.Y.Z] — YYYY-MM-DD` in `CHANGELOG.md`.
2. Updating the compare links at the bottom of `CHANGELOG.md`.
3. Committing as `docs(changelog): cut vX.Y.Z release`.
4. Tagging with `git tag -a vX.Y.Z -m "vX.Y.Z"` and `git push origin vX.Y.Z`.

GoReleaser handles the rest. Do not commit, tag, or push without explicit
maintainer approval.

## Commits and PRs

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`, `build:`, `ci:`).
- One logical change per commit; rebase, do not merge.
- Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change.
- Never commit or push without explicit user approval, even when a
  previous commit/push in the same session was approved.
