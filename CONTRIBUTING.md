# Contributing to kfeatures

This document describes the conventions that govern the public API surface and
the review checklist used when adding a new probe, feature, or requirement.

The user-facing `README.md` is intentionally kept short. The contents below are
internal API governance: read them before proposing a new `Feature*`, a new
`Require*` constructor, or a new `WithX` option.

## API model

`kfeatures` deliberately exposes two API families with distinct purposes:

| Intent                                       | API family                  | Notes                                             |
| -------------------------------------------- | --------------------------- | ------------------------------------------------- |
| Validate required capabilities (pass/fail)   | `Check(...)`                | Returns actionable errors for missing requirements |
| Collect diagnostics/reporting data           | `Probe()`, `ProbeWith(...)` | `WithX` selects what to collect; never a requirement |

Requirement items consumed by `Check(...)`:

- `Feature`: stable boolean capability
- `FeatureGroup`: reusable preset of requirements (also returned by `FromELF`)
- `RequireProgramType(...)`, `RequireMapType(...)`, `RequireProgramHelper(...)`: parameterized workload requirements
- `RequireMount(path, magic)`: parameterized filesystem-mount gate; magic comes from `golang.org/x/sys/unix` (e.g. `unix.BPF_FS_MAGIC`)
- `RequireMinKernel(major, minor)`: parameterized minimum-kernel-version gate; composes with the helper/prog-type/map-type kernel-version snapshot maintained under `internal/kernelversions`
- `FromELF(path)`: producer of requirement items in the same model (program/map types + helper-per-program requirements)
- `ProbeELF(path)` / `ProbeELFWith(path, opts...)`: full ELF snapshot (`*ELFProbes`) with optional CO-RE classification; `Requirements()` projects to a `FeatureGroup`

`FromELF`, `ProbeELF`, and `ProbeELFWith` are parser-only and available cross-platform; runtime probing/checking remains Linux-specific.

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

`ProbeELF` is the strict superset: it returns a richer `*ELFProbes` snapshot (warnings, memory-access summaries, CO-RE classification when opted in) and lets callers project to the same `FeatureGroup` shape via `Requirements()`. New extraction surface (additional warning rules, additional CO-RE classifications) belongs on `ProbeELF`; `FromELF` stays frozen against the four contract points above.

## Kernel-version snapshot (`internal/kernelversions`)

The helper / program-type / map-type minimum-kernel-version tables are generated, not hand-edited. The generator (`internal/kernelversions/cmd/kvgen`) parses BCC's `docs/kernel-versions.md` and Linux UAPI `include/uapi/linux/bpf.h` at pinned commits, cross-validates that every `BPF_FUNC_*` / `BPF_PROG_TYPE_*` / `BPF_MAP_TYPE_*` enum value in UAPI has a corresponding row in the BCC table, and emits `source.json` plus `tables.go`.

Workflow:

- **Routine refresh**: `.github/workflows/refresh-kernel-versions.yml` runs weekly, resolves upstream HEAD for both repos, rewrites the `defaultBCCCommit` / `defaultKernelCommit` constants in `cmd/kvgen/main.go`, regenerates the snapshot, and opens a PR labelled `dependencies` if the output drifted.
- **Manual refresh**: `go generate ./internal/kernelversions/...` from a clean checkout.
- **Cross-validation failure**: when UAPI ships a new symbol before BCC documents it (or vice versa), the generator returns an error. Decide between waiting for BCC to catch up and adding the symbol to the audited allow-list in `internal/kernelversions/cmd/kvgen/known_gaps.go` with a one-line rationale; never silence the validator wholesale.

Do not commit hand-edited changes to `source.json` or `tables.go`. The auto-refresh PR is the only sanctioned path.

## CLI conventions

The `cmd/kfeatures` binary is built on [structcli](https://github.com/leodido/structcli) (>= v0.17.0). The patterns below are invariants: PRs that break them need explicit discussion in the description.

### Construction (`Bind` + `Setup` + `ExecuteOrExit`)

- Each subcommand declares its flags as a struct annotated with `flag:"…"` tags and registers it via `structcli.Bind(cmd, opts)`. No manual `Define`/`Unmarshal`/`PreRunE` plumbing.
- Top-level orchestration lives in a single `structcli.Setup(root, ...)` call. Every optional capability is opted in via a `With*` option:
  - `WithJSONSchema(jsonschema.Options{})`: `--jsonschema` discovery surface.
  - `WithFlagErrors()`: typed `FlagError` values so cobra/pflag misuse classifies into semantic exit codes instead of falling back to `Error=1`.
  - `WithMCP(structclimcp.Options{...})`: `--mcp` server mode.
- Execution goes through `structcli.ExecuteOrExit(root)`. Do **not** add a manual `if _, err := root.Execute(); err != nil { os.Exit(1) }` bridge: it bypasses the structured-error pipeline.

### Stream routing (MCP-safe)

All command output **must** go through `cmd.OutOrStdout()` and `cmd.ErrOrStderr()`. Never bare `os.Stdout`/`os.Stderr` and never the implicit-stdout `fmt.Print*` family. The MCP wrapper swaps the root command's `Out`/`Err` for per-call buffers so each `tools/call` response captures the command's output; bare `os.Stdout` writes leak directly to the host stdio and break JSON-RPC framing.

Non-MCP behaviour is bit-for-bit identical because cobra's `OutOrStdout()` resolves to `os.Stdout` when no `SetOut` was called.

### `os.Exit` discipline (MCP session survival)

`os.Exit` from inside a `RunE` terminates the MCP server process and kills subsequent `tools/call` requests on the same stdio connection. When a code path needs `os.Exit(N)` for CLI ergonomics, gate it on the MCP-detection helper:

```go
if inMCPMode(c) {
    return err  // typed return; MCP layer wraps it as isError=true content
}
os.Exit(1)
```

The helper detects MCP mode by checking whether `c.OutOrStdout()` is the bare `os.Stdout` (CLI) or a swapped buffer (MCP). Use it for any future business-outcome path that wants a non-zero exit code, not just the existing `FeatureError` and "kernel config not available" cases.

### Error contracts

Two distinct contracts coexist in the CLI:

1. **Invocation errors** (cobra/pflag misuse, unknown subcommand, validation failure) flow through `structcli.HandleError`, which writes a single JSON line to stderr and exits with a code from `structcli/exitcode` (input `10`–`19`, config/env `20`–`29`, runtime `1`–`9`). The shape is documented by structcli's `StructuredError`. Do not hand-format these. Let `WithFlagErrors` + `ExecuteOrExit` do their job.
2. **Business outcomes** (`*kfeatures.FeatureError` from `check`, missing kernel config from `config`) keep their hand-rolled contract on the CLI side: `--json` prints `{ok,feature,reason}` on stdout, the human path prints `FAIL: feature - reason` on stderr, both exit 1. Under MCP this carve-out is collapsed (the structcli envelope wins): the typed error is returned and the MCP layer marks the response `isError=true`.

When adding a new subcommand that can fail with a domain-specific verdict, decide which bucket it belongs to *before* writing the handler. Do not invent a third shape.

### MCP tool exposure

`WithMCP` exposes every runnable leaf command by default. Two reasons to exclude a tool:

- **Build metadata or shell integration** (e.g. `version`, `completion-*`): these belong in MCP's `serverInfo` response or are not agent-relevant. Add them to `Options.Exclude` by full tool name.
- **Side-effecting commands without idempotent semantics**: leave a comment in the exclude list explaining why; agents should not invoke commands that mutate host state without the operator approving the call.

When introducing a new subcommand, default to exposing it. Only exclude after thinking through the agent UX.

## Development workflow

```bash
make test         # unit tests
make lint         # go vet + golangci-lint
make build        # build the CLI
make cover        # produce coverage.out
make cover-check  # enforce per-file coverage threshold
```

### Coverage gate

`make cover-check` runs the test suite with `-coverprofile=coverage.out` and then runs `internal/tools/covercheck` against that profile, failing if any gated source file falls below `COVER_THRESHOLD` (default `90`). The list of gated files lives in the `COVER_FILES` makefile variable.

The checker honours a single-line `// coverage:ignore` marker placed in the doc comment of a function declaration (or of a `var foo = func(...)` declaration). The marker excludes every statement attributed to that function from both the numerator and the denominator. Use it sparingly and only for code that is genuinely impossible to cover from the unit-test environment (network-bound `main` entrypoints, disk-bound wrappers like `ProbeELFWith` whose branches are exercised through programmatic fixtures against the inner helper). Every marker should carry a one-line justification immediately above it.

When you add a new feature file, append it to `COVER_FILES` in the makefile and bring it up to threshold in the same PR. Internal tools (`internal/tools/covercheck`, `internal/kernelversions/cmd/kvgen`) are intentionally excluded from the gate: their happy paths are exercised by the scheduled refresh workflow against live network data.

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
