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

This file (`AGENTS.md`) is the agent-actionable distillation: it
duplicates the load-bearing rules from `CONTRIBUTING.md` in a more
direct "do this / don't do that" voice, with code snippets, because
those rules are easy to break by accident. When a CLI invariant or
governance rule changes in `CONTRIBUTING.md`, update the corresponding
section here in the same PR.

## Release workflow

Tags drive the `releasing` GitHub Actions workflow
(`.github/workflows/release.yaml`, triggered on `push: tags: v*`). The
maintainer cuts releases by:

1. Renaming `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD` in `CHANGELOG.md`.
2. Updating the compare links at the bottom of `CHANGELOG.md`.
3. Committing as `docs(changelog): cut vX.Y.Z release`.
4. Tagging with `git tag -a vX.Y.Z -m "vX.Y.Z"` and `git push origin vX.Y.Z`.

GoReleaser handles the rest. Do not commit, tag, or push without explicit
maintainer approval.

## CLI conventions (`cmd/kfeatures`)

The CLI is built on [structcli](https://github.com/leodido/structcli) (>= v0.17.0). The patterns below are load-bearing: agent edits that violate them will silently break MCP mode, the structured-error JSON envelope, or the auto-bind pipeline. The human-facing version of these rules lives in [CONTRIBUTING.md → CLI conventions](CONTRIBUTING.md#cli-conventions); the items below are the agent-actionable distillation.

Before editing `cmd/kfeatures/main.go` or adding a subcommand, read the existing file end-to-end. If you are tempted to write `os.Stdout`, `os.Exit`, or `cmd.Execute()` inside `cmd/kfeatures/`, stop and re-read the relevant section below.

### Construction: always Bind + Setup + ExecuteOrExit

Subcommands declare their flags as a struct with `flag:"..."` tags and register via `structcli.Bind(cmd, opts)`. `main()` orchestrates with one `structcli.Setup(root, ...)` call and runs the tree with `structcli.ExecuteOrExit(root)`.

Do **not**:

- Add a manual `if _, err := root.Execute(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }` bridge: it bypasses `WithFlagErrors` and turns every classified error back into a `Error=1` fallback.
- Wire a `PreRunE` to call `structcli.Unmarshal(...)` manually. `Bind` already arranges that through `ExecuteOrExit`.
- Call `structcli.SetupX` functions directly when there is a `WithX` option. Keep the `Setup` call as the single source of truth.

When adding a new subcommand:

```go
type FooOptions struct {
    Verbose bool `flag:"verbose" flagshort:"v" flagdescr:"…"`
}

func fooCmd() *cobra.Command {
    opts := &FooOptions{}
    cmd := &cobra.Command{
        Use:  "foo",
        RunE: func(c *cobra.Command, args []string) error { /* … */ },
    }
    if err := structcli.Bind(cmd, opts); err != nil {
        panic(err)
    }
    return cmd
}
```

Then `root.AddCommand(fooCmd())` **before** the `structcli.Setup(root, ...)` call so `Setup` can wrap the new subcommand.

### Stream routing: never bare `os.Stdout` / `os.Stderr` / `fmt.Print*`

Inside any `RunE`, every byte of output **must** go through `cmd.OutOrStdout()` and `cmd.ErrOrStderr()`. The MCP wrapper swaps the root's `Out`/`Err` for per-call buffers; bare `os.Stdout` writes leak past the JSON-RPC framing and corrupt the stream.

Forbidden inside `RunE`:

```go
fmt.Println("OK")                       // implicit os.Stdout
fmt.Printf("Kernel: %s\n", v)           // implicit os.Stdout
fmt.Fprintln(os.Stderr, "FAIL: …")      // bare os.Stderr
fmt.Print(sf)                           // implicit os.Stdout
json.NewEncoder(os.Stdout).Encode(v)    // bare os.Stdout
```

Required inside `RunE`:

```go
fmt.Fprintln(c.OutOrStdout(), "OK")
fmt.Fprintf(c.OutOrStdout(), "Kernel: %s\n", v)
fmt.Fprintln(c.ErrOrStderr(), "FAIL: …")
fmt.Fprint(c.OutOrStdout(), sf)
printJSON(c.OutOrStdout(), v)           // helper takes io.Writer
```

Helpers that emit output must take an `io.Writer`. Never default to `os.Stdout` inside the helper. Non-MCP behaviour is bit-for-bit identical because `OutOrStdout()` resolves to `os.Stdout` when no `SetOut` was called, so there is no reason to ever bypass this.

When you grep for `os.Stdout` in `cmd/kfeatures/`, the only legal occurrence today is inside `inMCPMode(c)`, where it is compared against `c.OutOrStdout()` to detect MCP execution.

### `os.Exit` discipline: gate on `inMCPMode(c)`

`os.Exit(N)` from inside a `RunE` terminates the MCP server process and breaks every subsequent `tools/call` on the same stdio connection. Two existing call sites need a non-zero exit code for CLI ergonomics (the `check` `FeatureError` path and the `config` "kernel config not available" path); both gate on `inMCPMode`:

```go
if inMCPMode(c) {
    return err   // typed return; MCP layer wraps as isError=true
}
os.Exit(1)
```

When you add a new code path that wants `os.Exit`, copy this pattern. Never call `os.Exit` unconditionally inside a `RunE`. Outside `RunE` (in `main()`'s setup-error path) `os.Exit` is fine: there is no MCP server to kill yet.

`inMCPMode(c)` lives in `cmd/kfeatures/main.go` and detects MCP execution by checking whether `c.OutOrStdout()` is the bare `os.Stdout` (CLI) or a swapped buffer (MCP). Do not change its implementation without also updating the comment block: both `check` and `config` rely on its semantics.

### Two error contracts (do not invent a third)

`cmd/kfeatures` deliberately ships two error shapes. Before writing a new failure path, decide which one it is:

1. **Invocation errors** (bad/missing/unknown flag, unknown subcommand, validation failure). These flow through `structcli.HandleError` automatically (because `WithFlagErrors` + `ExecuteOrExit` are wired): a single JSON line on stderr with a semantic exit code from `structcli/exitcode` (input `10`–`19`, config/env `20`–`29`, runtime `1`–`9`). Shape is `StructuredError`. **Do not hand-format these.** If your new code returns a typed `*kfeatures.SomeError`, the fallback gives it `Error=1` and embeds the message; that is acceptable. Do not write a JSON envelope yourself.
2. **Business outcomes** (`*kfeatures.FeatureError` from `check`, "kernel config not available" from `config`). These keep a hand-rolled CLI contract: `--json` writes a domain-specific JSON object on stdout (`{ok,feature,reason}` for `FeatureError`); the human path writes a domain-specific message on stderr (`FAIL: feature - reason`); both exit 1 via the `inMCPMode` carve-out. Under MCP this hand-rolled output is **collapsed**: return the typed error and let the structcli envelope win.

Do not introduce a third shape (e.g. a custom JSON-on-stderr format, or a different `--json` payload mid-stream). If your new failure does not fit either bucket, raise it in the PR description and pick one. Do not split the difference.

### MCP tool exposure

`structcli.WithMCP` exposes every runnable leaf command as an MCP tool by default. Excluding a tool requires intent:

- **Build metadata or shell integration** (`version`, `completion-bash`/`zsh`/`fish`/`powershell`) is excluded because that information lives in MCP's `serverInfo` response or has no agent value.
- **Side-effecting commands without idempotent semantics** should be excluded with a comment explaining why; agents must not be able to mutate host state through `tools/call` without operator approval.

When adding a subcommand, default to exposing it. Add it to `Options.Exclude` only after thinking through the agent UX. `Exclude` matches by exact tool name (preferred for leaves) or exact full command path; use leaf names for cobra-auto-generated subtrees like `completion <shell>` because the parent path is non-runnable and never reaches the registry.

### Bats coverage

When you change CLI behaviour, the corresponding bats file must be updated in the same commit:

- `test/cli_common.bats`: cross-platform behaviour (help, error envelopes, JSON Schema discovery).
- `test/cli_linux.bats`: Linux-only live-kernel behaviour (probe, check verdicts).
- `test/cli_nonlinux.bats`: graceful platform-error degradation on non-Linux.
- `test/cli_linux_mount.bats`: root-required mount integration tests.
- `test/cli_mcp.bats`: MCP protocol surface (cross-platform; live-kernel `tools/call` cases skip on non-Linux).

Run locally with `bats test/`. The full suite must stay green before committing.

## Commits and PRs

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`, `build:`, `ci:`).
- One logical change per commit; rebase, do not merge.
- Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change.
- Never commit or push without explicit user approval, even when a
  previous commit/push in the same session was approved.
