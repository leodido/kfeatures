# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/leodido/kfeatures/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/leodido/kfeatures/releases/tag/v0.1.0
