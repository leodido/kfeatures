# Contributing to kfeatures

This document describes the conventions that govern the public API surface and
the review checklist used when adding a new probe, feature, or requirement.

The user-facing `README.md` is intentionally kept short. The contents below are
internal API governance — read them before proposing a new `Feature*`, a new
`Require*` constructor, or a new `WithX` option.

## API model

`kfeatures` deliberately exposes two API families with distinct purposes:

| Intent                                       | API family                  | Notes                                             |
| -------------------------------------------- | --------------------------- | ------------------------------------------------- |
| Validate required capabilities (pass/fail)   | `Check(...)`                | Returns actionable errors for missing requirements |
| Collect diagnostics/reporting data           | `Probe()`, `ProbeWith(...)` | `WithX` selects what to collect; never a requirement |

Requirement items consumed by `Check(...)`:

- `Feature` — stable boolean capability
- `FeatureGroup` — reusable preset of requirements (also returned by `FromELF`)
- `RequireProgramType(...)`, `RequireMapType(...)`, `RequireProgramHelper(...)` — parameterized workload requirements
- `RequireMount(path, magic)` — parameterized filesystem-mount gate; magic comes from `golang.org/x/sys/unix` (e.g. `unix.BPF_FS_MAGIC`)
- `FromELF(path)` — producer of requirement items in the same model (program/map types + helper-per-program requirements)

`FromELF` is parser-only and available cross-platform; runtime probing/checking
remains Linux-specific.

## Feature-addition review checklist

When proposing a new probe or gate, walk through this checklist on the PR:

1. Is the signal a deterministic run/block requirement with actionable remediation text?
2. If no, keep it probe-only behind `ProbeWith(WithX...)`.
3. If yes and boolean, model it as `Feature` and wire `Result(...)`, `Diagnose(...)`, CLI mapping, and tests.
4. If yes and parameterized, model it as a requirement item type consumed by `Check(...)` (avoid enum explosion).
5. Do not add new top-level gate entrypoints (`CheckX`, `CheckGroup`, etc.): keep one gate API (`Check(...)`).
6. Do not use `WithX` as requirements: `WithX` remains probe-scope selection only.

### Current classification snapshot

- **Gated via `Check(...)`**: `Feature*` readiness checks plus parameterized program/map/helper/mount requirements.
- **Probe-only via `ProbeWith(WithX...)`**: contextual/descriptive signals without a stable universal policy (for example `DebugFS`, `SecurityFS`, `InInitPIDNS`, raw mitigation strings, raw active LSM list, kernel version).

## `FromELF` contract

The `FromELF` API is frozen against the following contract:

1. Public signature is `FromELF(path string) (FeatureGroup, error)`.
2. Extraction output must be deterministic: deduplicated and stably ordered.
3. Extraction scope includes program types, map types, and helper-per-program requirements derived from direct helper calls.
4. Unknown/unsupported ELF kinds are fail-closed (return an error, never silently ignore).

Changes to any of these points require explicit discussion in the PR and a CHANGELOG entry under a new minor version.

## Development workflow

```bash
make test       # unit tests
make lint       # go vet + golangci-lint
make build      # build the CLI
```

Integration tests (real `unix.Statfs` / `unix.Mount`) are gated behind a build
tag and a dedicated CI job:

```bash
go test -tags integration ./...
```

The Linux-only bats suite under `test/` exercises the CLI binary end-to-end and
is also run by the integration job.

## Commit and PR conventions

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `build:`, `ci:`).
- One logical change per commit; rebase, do not merge.
- Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change.
- New public symbols require Go doc comments and at least one test.
