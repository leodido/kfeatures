# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README restructured around user-facing usage: badges, expanded usage section with `Diagnose`, `FromELF`, `FeatureGroup`, and `RequireMount` examples, stability statement, and updated comparison/detect tables.
- API model, feature-addition review checklist, `FromELF` contract, and classification snapshot moved from `README.md` to a new `CONTRIBUTING.md` (governance content kept; relocated to its proper audience).
- Bumped `structcli` from `v0.11.0` to `v0.16.1`. No behavioral change; pure dependency upgrade. New structcli capabilities (`flagkit.Output`, `SetupJSONSchema`, `exitcode`, `SetupHelpTopics`, declarative enum registration) are deferred to follow-up PRs.

## [0.4.0] — 2026-04-23

### Added

- `RequireMount(path, magic)`: parameterized requirement that gates on a filesystem being mounted at `path` with a superblock magic equal to `magic`. Magic constants come from `golang.org/x/sys/unix` (e.g. `unix.BPF_FS_MAGIC`, `unix.TRACEFS_MAGIC`, `unix.CGROUP2_SUPER_MAGIC`). Useful for non-default mount paths (e.g. bpffs mounted at `/run/bpf`) or pseudo-filesystems not covered by the built-in `Feature*` gates. Backed by the same internal `checkMount` helper as `FeatureBPFFS` / `FeatureTraceFS`.
- New `integration` CI job exercises the real `unix.Statfs` / `unix.Mount` paths on `ubuntu-latest` (Go integration tests built with `-tags=integration`, plus a Linux-only bats suite that verifies CLI exit codes against the runner's actual mount state).

### Fixed

- `Check(FeatureBPFFS)` and `Check(FeatureTraceFS)` now verify the filesystem is actually mounted with the expected superblock magic (`BPF_FS_MAGIC`, `TRACEFS_MAGIC`) instead of only checking that a directory exists at the path. Previously, both gates returned success on any system where `/sys/fs/bpf` (resp. `/sys/kernel/tracing`) existed as a directory — which is the case by default on systemd-based distros even when the corresponding pseudo-filesystem is not mounted. Callers gating on these features (e.g. before pinning maps on bpffs) would silently get a false positive and fail later at `bpf_obj_pin()`. Diagnostic-only fields `SystemFeatures.DebugFS` / `.SecurityFS` keep their previous presence-only semantics.

## [0.3.1] — 2026-03-23

### Added

- `FeatureIMAMeasurementActive` and exported `ProbeIMAMeasurementActive()`: detects whether IMA has an active measurement policy by reading the runtime measurement count. A count greater than 1 (beyond the boot aggregate) means at least one rule is active; when the count is exactly 1 the probe executes `/bin/true` and re-reads to confirm. When measurement is active, file hashes are cached in the inode security blob and consumers can skip recomputation on repeated access.

## [0.3.0] — 2026-02-23

### Added

- CLI: `--require` flag value completion (shell completion now suggests valid feature names).
- CLI: case-insensitive parsing of `--require` values backed by generated `Feature` text codecs.
- Generated `Feature` enum via `go-enum` with initialism support and text marshal/unmarshal helpers; CLI parses requirements through the generated helpers.
- Build: top-level `Makefile` with the canonical lint/test/build/release targets; CI workflows now invoke them.

### Changed

- `Check()` no longer special-cases LSM injection — `FeatureBPFLSM` is a composite gate evaluated through the standard `Result` / `Diagnose` paths.
- CLI: `check` help and require UX reworked around the generated enum.
- Bumped `structcli` to `v0.11.0` (via `v0.10.0`).
- CI: pinned the goreleaser CLI version used in the release workflow.

## [0.2.0] — 2026-02-18

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

## [0.1.0] — 2026-02-15

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

[Unreleased]: https://github.com/leodido/kfeatures/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/leodido/kfeatures/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/leodido/kfeatures/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/leodido/kfeatures/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/leodido/kfeatures/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/leodido/kfeatures/releases/tag/v0.1.0
