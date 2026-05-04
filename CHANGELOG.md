# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Releases: every artifact (per-platform tarballs and `checksums.txt`) is now signed with [cosign](https://github.com/sigstore/cosign) keyless signing backed by GitHub's OIDC token. Each artifact has a sibling `<artifact>.sigstore.json` bundle containing the signature, certificate (with the workflow identity baked in), and Rekor transparency-log inclusion proof. Verifying a download is a single `cosign verify-blob --bundle ...` invocation; see the new [Verifying releases](README.md#verifying-releases) section in the README for the exact commands. Requires cosign v2.0+ on the verifier side.
- `NOTICE` file at repo root carrying the `Copyright 2026 Leonardo Di Donato` attribution. Apache 2.0 distinguishes the license text (canonical, verbatim, in `LICENSE`) from project-level attribution (in a `NOTICE` file that downstream consumers must propagate). The previous setup folded the copyright line into `LICENSE` itself; that conflated the two and is one of the deviations that caused licensecheck to mis-classify the file (see corresponding `### Fixed` entry).

### Fixed

- `LICENSE`: replaced with the verbatim canonical Apache 2.0 text from <https://www.apache.org/licenses/LICENSE-2.0.txt>. The previous file had small body-text deviations (`to the Licensor` instead of `to Licensor`, `excluding any notices` instead of `excluding those notices`, missing leading newline, missing `APPENDIX: How to apply the Apache License to your work.` section) and substituted `[yyyy]` / `[name of copyright owner]` inline with `2026` / `Leonardo Di Donato`. Together those edits dropped the file to ~6% match against [google/licensecheck](https://github.com/google/licensecheck)'s Apache-2.0 template (well below the 75% confidence floor), so [pkg.go.dev](https://pkg.go.dev/github.com/leodido/kfeatures) classified the module as `License: UNKNOWN`, hid the documentation behind a license-policy notice, marked `Redistributable license` as failed, and refused to compute the `Imported by` graph. With the canonical text restored, licensecheck reports 100% Apache-2.0 coverage. The change takes effect on pkg.go.dev once the next tagged version is published (the `v0.5.0` snapshot is immutable).

## [0.5.0] - 2026-05-03

### Added

- CLI: `--jsonschema` persistent flag. `kfeatures --jsonschema` (or `kfeatures <subcommand> --jsonschema`) prints a JSON Schema describing the current command's flags; `kfeatures --jsonschema=tree` walks the entire subtree. Lets agents and automation tooling discover the CLI's flag/command surface without scraping `--help`. Backed by `structcli.SetupJSONSchema`.
- CLI: `--mcp` persistent flag turns `kfeatures` into a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio. Each runnable leaf command becomes an MCP tool whose input schema mirrors the cobra flag set; agents introspect via `tools/list` and invoke via `tools/call` without scraping `--help`. Backed by `structcli.WithMCP` (pure stdlib JSON-RPC, no extra heavy SDK dependency). Tools currently exposed: `probe`, `check`, `config`. `version` and `completion-*` are excluded (build metadata is in the MCP `serverInfo` response; shell completion is not an agent concern). Command handlers were re-routed through `cmd.OutOrStdout()` / `cmd.ErrOrStderr()` so MCP per-call output capture works correctly; non-MCP behaviour is bit-for-bit identical. Sessions survive business-outcome errors (`FeatureError`, missing kernel config): under MCP these return as typed errors instead of `os.Exit(1)`, so subsequent `tools/call` requests on the same connection continue to work.

### Changed

- README CLI section expanded to cover the AI-agent and CI/CD story: semantic exit codes (with a code/category table), structured-error JSON envelope, `--jsonschema` discovery (`tree` form), and `--mcp` MCP-server mode (with an example client config). A short pointer added near the top so the new capabilities are not buried.
- CONTRIBUTING gained a "CLI conventions" section codifying the invariants introduced by the structcli v0.17.0 adoption: `Bind` + `Setup` + `ExecuteOrExit` construction, stream routing through `cmd.OutOrStdout()` / `cmd.ErrOrStderr()`, `os.Exit` discipline (the `inMCPMode` carve-out), the two coexisting error contracts (invocation envelope vs business-outcome verdict), and the MCP tool-exposure policy.
- AGENTS gained an agent-actionable distillation of the same CLI conventions (with do/don't snippets) so coding agents do not silently reintroduce bare `os.Stdout` writes, `os.Exit` from `RunE`, or hand-rolled invocation-error formatting. The doc-split section calls out the new co-update obligation between `CONTRIBUTING.md` and `AGENTS.md`.
- README restructured around user-facing usage: badges, expanded usage section with `Diagnose`, `FromELF`, `FeatureGroup`, and `RequireMount` examples, stability statement, and updated comparison/detect tables.
- API model, feature-addition review checklist, `FromELF` contract, and classification snapshot moved from `README.md` to a new `CONTRIBUTING.md` (governance content kept; relocated to its proper audience).
- Bumped `structcli` from `v0.11.0` to `v0.16.1`. No behavioral change; pure dependency upgrade. New structcli capabilities (`flagkit.Output`, `SetupJSONSchema`, `exitcode`, `SetupHelpTopics`, declarative enum registration) are deferred to follow-up PRs.
- Bumped `structcli` from `v0.16.1` to `v0.17.0`. No behavioral change; pure dependency upgrade. New `Bind` / `Setup` / `ExecuteC` ergonomics and AI-native capabilities (`WithMCP`, `WithFlagErrors`, structured errors, semantic exit codes) are adopted in follow-up PRs.
- CLI: migrated to `structcli.Bind` + `structcli.Setup` + `structcli.ExecuteC`. Per-subcommand `Attach` methods, manual `Define`/`Unmarshal` calls, and `PreRunE` wiring are gone; flag definition, viper binding, env binding, and unmarshal now run through structcli's auto-bind pipeline. Behaviour-neutral: error messages and exit codes are unchanged. AI-native error handling (`ExecuteOrExit`, structured errors, semantic exit codes) lands in a follow-up PR.
- CLI: invocation errors (missing required flag, unknown flag, invalid flag value, unknown subcommand) now emit a single JSON line on stderr and exit with a semantic exit code from `structcli/exitcode` (input errors `10`–`19`, config/env `20`–`29`, runtime `1`–`9`) instead of cobra's plain string + exit `1`. Wired via `structcli.WithFlagErrors()` + `structcli.ExecuteOrExit(root)`. The shape (`{error, exit_code, message, flag, got, command, available, ...}`) is documented by structcli's `StructuredError`. Business outcomes from `kfeatures check` (`FeatureError`) keep their existing contract: `--json` prints `{ok,feature,reason}` on stdout, the human path prints `FAIL: feature - reason` on stderr, both exit `1`.
- CLI: root command now has a `RunE` that defers to `Help()`. Bare `kfeatures` still prints help and exits 0 (unchanged exit behavior); the change is required so structcli's `--jsonschema` interceptor fires on root invocations.

### Fixed

- CLI/MCP: `--json` outputs (`probe --json`, `check --json`, `config --json`) are now compact (single line, single trailing newline) when the binary runs in MCP mode. Previously every JSON payload was 2-space indented, which made sense for `kfeatures probe --json | jq` on a terminal but bloated MCP responses: the captured stdout is jammed verbatim into the JSON-RPC response's `result.content[0].text` field, so indentation arrived at clients as literal `\n` and leading-space sequences. CLI behavior is unchanged (still indented for human readers).
- CLI: `kfeatures config` now reports a missing kernel config (`/proc/config.gz`, `/boot/config-$(uname -r)`, and `/lib/modules/$(uname -r)/config` all unreadable) via the standard structcli error envelope on stderr instead of a bare `kernel config not available` line. The `message` field lists the probed paths (with the actual kernel release substituted) and points at the most common fixes (`CONFIG_IKCONFIG_PROC=y`, install the matching kernel-headers package, run as root if `/proc/config.gz` exists but is unreadable). Also fixes `--json` being silently dropped on this path: previously the early `os.Exit(1)` short-circuited the JSON branch, leaving stdout empty and stderr free-form regardless of the flag. Failure shape is now consistent with every other invocation-class error in the binary.

## [0.4.0] - 2026-04-23

### Added

- `RequireMount(path, magic)`: parameterized requirement that gates on a filesystem being mounted at `path` with a superblock magic equal to `magic`. Magic constants come from `golang.org/x/sys/unix` (e.g. `unix.BPF_FS_MAGIC`, `unix.TRACEFS_MAGIC`, `unix.CGROUP2_SUPER_MAGIC`). Useful for non-default mount paths (e.g. bpffs mounted at `/run/bpf`) or pseudo-filesystems not covered by the built-in `Feature*` gates. Backed by the same internal `checkMount` helper as `FeatureBPFFS` / `FeatureTraceFS`.
- New `integration` CI job exercises the real `unix.Statfs` / `unix.Mount` paths on `ubuntu-latest` (Go integration tests built with `-tags=integration`, plus a Linux-only bats suite that verifies CLI exit codes against the runner's actual mount state).

### Fixed

- `Check(FeatureBPFFS)` and `Check(FeatureTraceFS)` now verify the filesystem is actually mounted with the expected superblock magic (`BPF_FS_MAGIC`, `TRACEFS_MAGIC`) instead of only checking that a directory exists at the path. Previously, both gates returned success on any system where `/sys/fs/bpf` (resp. `/sys/kernel/tracing`) existed as a directory, which is the case by default on systemd-based distros even when the corresponding pseudo-filesystem is not mounted. Callers gating on these features (e.g. before pinning maps on bpffs) would silently get a false positive and fail later at `bpf_obj_pin()`. Diagnostic-only fields `SystemFeatures.DebugFS` / `.SecurityFS` keep their previous presence-only semantics.

## [0.3.1] - 2026-03-23

### Added

- `FeatureIMAMeasurementActive` and exported `ProbeIMAMeasurementActive()`: detects whether IMA has an active measurement policy by reading the runtime measurement count. A count greater than 1 (beyond the boot aggregate) means at least one rule is active; when the count is exactly 1 the probe executes `/bin/true` and re-reads to confirm. When measurement is active, file hashes are cached in the inode security blob and consumers can skip recomputation on repeated access.

## [0.3.0] - 2026-02-23

### Added

- CLI: `--require` flag value completion (shell completion now suggests valid feature names).
- CLI: case-insensitive parsing of `--require` values backed by generated `Feature` text codecs.
- Generated `Feature` enum via `go-enum` with initialism support and text marshal/unmarshal helpers; CLI parses requirements through the generated helpers.
- Build: top-level `Makefile` with the canonical lint/test/build/release targets; CI workflows now invoke them.

### Changed

- `Check()` no longer special-cases LSM injection. `FeatureBPFLSM` is a composite gate evaluated through the standard `Result` / `Diagnose` paths.
- CLI: `check` help and require UX reworked around the generated enum.
- Bumped `structcli` to `v0.11.0` (via `v0.10.0`).
- CI: pinned the goreleaser CLI version used in the release workflow.

## [0.2.0] - 2026-02-18

### Changed

- CLI now compiles on non-Linux platforms (macOS, Windows) and returns `ErrUnsupportedPlatform` instead of failing to build
- `ErrUnsupportedPlatform` sentinel moved to `types.go` for cross-platform visibility
- CLI error output no longer prints usage text on command errors (`SilenceUsage`)
- CLI error messages are cleaner: no redundant prefix wrapping

### Fixed

- `Check(FeatureBPFLSM)` now evaluates LSM program type loadability as part of the composite result, removing a special case from `Check()` loop
- `ProbeWith(WithKernelConfig())` returns `ErrNoKernelConfig` when kprobe.multi config key is unavailable instead of silently succeeding
- `version` command includes tool version, commit hash, and build date via GoReleaser ldflags

### Added

- CLI smoke test suite using BATS (bats-core) with `bats-assert`, covering Linux and macOS
- macOS CI job with `go vet` and cross-platform CLI validation
- `ErrUnsupportedPlatform` exported sentinel error for non-Linux platforms
- Build-constrained stub files (`probe_other.go`, `check_other.go`, `config_other.go`) for non-Linux compilation

## [0.1.0] - 2026-02-15

First public release.

### Added

- Kernel feature probing engine with functional options pattern (`Probe`, `ProbeWith`, `ProbeNoCache`)
- Selective probing: `WithProgramTypes()`, `WithSecuritySubsystems()`, `WithKernelConfig()`, `WithCapabilities()`, `WithJIT()`, `WithAll()`
- BPF program type detection via `cilium/ebpf`: LSM, kprobe, kprobe.multi, tracepoint, fentry
- BTF availability check (`/sys/kernel/btf/vmlinux`)
- Kernel config parser with support for `/proc/config.gz`, `/boot/config-*`, `/lib/modules/*/config`
- `KernelConfig` type with `Get()`, `IsSet()`, and convenience fields (`BPFLSM`, `BTF`, `IMA`, `KprobeMulti`)
- Active LSM list detection (`/sys/kernel/security/lsm`)
- Composite BPF LSM validation (kernel config + boot params + program type)
- IMA detection (LSM list + securityfs directory)
- Process capability probing via `prctl(PR_CAPBSET_READ)`: CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON
- Unprivileged BPF status (`/proc/sys/kernel/unprivileged_bpf_disabled`)
- JIT sysctl probing: `bpf_jit_enable`, `bpf_jit_harden`, `bpf_jit_kallsyms`, `bpf_jit_limit`
- High-level `Check()` API with `FeatureError` for actionable diagnostics
- `Diagnose()` for human-readable remediation steps
- `Feature` enum for type-safe feature references
- Unified `Requirement` model for `Check(...)` with `FeatureGroup` and parameterized requirements (`RequireProgramType`, `RequireMapType`, `RequireProgramHelper`)
- `FromELF(path)` requirement extraction (program types, map types, helper-per-program requirements), with deterministic ordering and fail-closed handling for unknown kinds
- Human-readable `String()` output for `SystemFeatures`
- CLI tool (`cmd/kfeatures`) with `probe`, `check`, `config`, and `version` subcommands
- JSON output support in CLI (`--json`)
- GitHub Actions CI workflow with tests, vet, and golangci-lint
- Release automation with GoReleaser and GitHub generated release notes (`.github/release.yml`)
- SAST workflow (CodeQL)

[Unreleased]: https://github.com/leodido/kfeatures/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/leodido/kfeatures/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/leodido/kfeatures/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/leodido/kfeatures/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/leodido/kfeatures/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/leodido/kfeatures/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/leodido/kfeatures/releases/tag/v0.1.0
