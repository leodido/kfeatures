# kfeatures

> Can my eBPF tool actually run here, and if not, exactly what needs to change?

kfeatures is a pure-Go library that answers this question.

It probes kernel capabilities at runtime and returns actionable diagnostics: not just "unsupported", but *why* and *how to fix it*.

```go
if err := kfeatures.Check(kfeatures.FeatureBPFLSM, kfeatures.FeatureBTF); err != nil {
    var fe *kfeatures.FeatureError
    if errors.As(err, &fe) {
        log.Fatalf("%s — %s", fe.Feature, fe.Reason)
        // Output: BPF LSM — CONFIG_BPF_LSM=y but 'bpf' not in active LSM list; add lsm=...,bpf to kernel boot params
    }
}
```

## Why not `cilium/ebpf/features` or `bpftool`?

[`cilium/ebpf/features`](https://pkg.go.dev/github.com/cilium/ebpf/features) answers: *"Does this kernel support program type X?"*

[`bpftool feature probe`](https://man.archlinux.org/man/bpftool-feature.8.en) answers: *"What BPF features does this kernel have?"* (CLI only, not embeddable in Go)

Neither tells you whether your tool can **actually run**. For example, BPF LSM requires three things simultaneously: `CONFIG_BPF_LSM=y` in the kernel config, `bpf` in the active LSM boot parameter list, and the LSM program type supported by the running kernel. `cilium/ebpf/features` can only check the last one. `bpftool` can check the first and last, but not the second. Neither provides remediation guidance.

| Capability | `cilium/ebpf/features` | `bpftool feature probe` | **`kfeatures`** |
|---|:---:|:---:|:---:|
| BPF program type probes | ✅ | ✅ | ✅ |
| BPF map type / helper probes | ✅ | ✅ | ✅ (as parameterized requirements in `Check(...)`) |
| **BTF availability** (`/sys/kernel/btf/vmlinux`) | ❌ | ❌\* | ✅ |
| **Kernel config parsing** (any `CONFIG_*`, =y/=m) | ❌ | ✅ | ✅ |
| **Active LSM list** (`/sys/kernel/security/lsm`) | ❌ | ❌ | ✅ |
| **BPF LSM enabled** (config + boot params + program type) | ❌ | ❌ | ✅ |
| **IMA detection** (LSM list + securityfs directory) | ❌ | ❌ | ✅ |
| **Process capabilities** (CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON) | ❌ | ❌ | ✅ |
| **Unprivileged BPF status** | ❌ | ✅ | ✅ |
| **Composite feature validation** | ❌ | ❌ | ✅ |
| **Actionable diagnostics** (remediation steps) | ❌ | ❌ | ✅ |
| Selective probing (minimize overhead) | Per-function | All-or-nothing | ✅ |
| Pure Go, no CGO | ✅ | ❌ | ✅ |
| Usable as a Go library | ✅ | ❌ | ✅ |

\* `bpftool` checks `CONFIG_DEBUG_INFO_BTF` in kernel config but does not verify `/sys/kernel/btf/vmlinux` exists.

Other Go projects ([libbpfgo](https://github.com/aquasecurity/libbpfgo), [Tetragon](https://github.com/cilium/tetragon), [Falco libs](https://github.com/falcosecurity/libs)) have some feature detection built in, but none is a standalone reusable library. They are either CGO-dependent, tightly coupled to their parent project, or written in C/C++.

## Installation

```bash
go get github.com/leodido/kfeatures
```

## API model

`kfeatures` has two API families with different purposes:

| Intent | API family | Notes |
|---|---|---|
| Validate required capabilities (pass/fail) | `Check(...)` | Returns actionable errors for missing requirements |
| Collect diagnostics/reporting data | `Probe()`, `ProbeWith(WithX...)` | `WithX` selects what to collect; it does not define requirements |

Requirement items consumed by `Check(...)`:

- `Feature` (stable boolean capability)
- `FeatureGroup` (reusable preset of requirements)
- `RequireProgramType(...)`, `RequireMapType(...)`, `RequireProgramHelper(...)` (parameterized workload requirements)
- `FromELF(path)`: producer of requirement items in the same model (program/map types + helper-per-program requirements)

`FromELF` is parser-only and available cross-platform; runtime probing/checking remains Linux-specific.

Feature-addition review checklist:

1. Is the signal a deterministic run/block requirement with actionable remediation text?
2. If no, keep it probe-only behind `ProbeWith(WithX...)`.
3. If yes and boolean, model it as `Feature` and wire `Result(...)`, `Diagnose(...)`, CLI mapping, and tests.
4. If yes and parameterized, model it as a requirement item type consumed by `Check(...)` (avoid enum explosion).
5. Do not add new top-level gate entrypoints (`CheckX`, `CheckGroup`, etc.): keep one gate API (`Check(...)`).
6. Do not use `WithX` as requirements: `WithX` remains probe-scope selection only.

Current classification snapshot:

- Gated via `Check(...)`: `Feature*` readiness checks plus parameterized program/map/helper requirements.
- Probe-only via `ProbeWith(WithX...)`: contextual/descriptive signals without stable universal policy (for example `DebugFS`, `SecurityFS`, `InInitPIDNS`, raw mitigation strings, raw active LSM list, kernel version).

`FromELF` contract:

1. Public API is fixed to `FromELF(path string) (FeatureGroup, error)`.
2. Extraction output must be deterministic: deduplicated and stably ordered.
3. Extraction scope includes program types, map types, and helper-per-program requirements from direct helper calls.
4. Unknown/unsupported ELF kinds are fail-closed (return error, do not silently ignore).

## Usage

### Quick check

Validate that required kernel features are available:

```go
import "github.com/leodido/kfeatures"

if err := kfeatures.Check(kfeatures.FeatureBPFLSM, kfeatures.FeatureBTF); err != nil {
    var fe *kfeatures.FeatureError
    if errors.As(err, &fe) {
        log.Fatalf("kernel not ready: %s — %s", fe.Feature, fe.Reason)
    }
}
```

Mixed requirements example (feature enums + parameterized workload requirements):

```go
import (
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
    "github.com/leodido/kfeatures"
)

if err := kfeatures.Check(
    kfeatures.FeatureBTF,
    kfeatures.RequireProgramType(ebpf.XDP),
    kfeatures.RequireMapType(ebpf.Hash),
    kfeatures.RequireProgramHelper(ebpf.XDP, asm.FnMapLookupElem),
); err != nil {
    log.Fatal(err)
}
```

### Full probe

Probe all features for diagnostics:

```go
sf, err := kfeatures.Probe()
if err != nil {
    log.Fatal(err)
}
fmt.Println(sf)
```

Output:

```
Kernel: 6.1.0-generic

Program Types:
  LSM: yes
  kprobe: yes
  kprobe.multi: yes
  tracepoint: yes
  fentry: yes

Core:
  BTF: yes

Security Subsystems:
  BPF LSM enabled: yes
  IMA enabled: no
  IMA directory: yes
  Active LSMs: lockdown, capability, yama, apparmor, bpf

Capabilities:
  CAP_BPF: yes
  CAP_SYS_ADMIN: yes
  CAP_PERFMON: yes
  Unprivileged BPF disabled: yes

Kernel Config:
  CONFIG_BPF_LSM: y
  CONFIG_IMA: y
  CONFIG_DEBUG_INFO_BTF: y
  CONFIG_FPROBE: y
```

### Selective probing

Probe only what you need:

```go
sf, err := kfeatures.ProbeWith(
    kfeatures.WithProgramTypes(ebpf.LSM, ebpf.Kprobe),
    kfeatures.WithSecuritySubsystems(),
    kfeatures.WithCapabilities(),
)
```

## CLI

A CLI tool is included for operator diagnostics and CI/CD gating:

```bash
go install github.com/leodido/kfeatures/cmd/kfeatures@latest
```

```bash
# Probe all features
kfeatures probe

# Check specific requirements (exit 0 if met, 1 if not)
kfeatures check --require bpf-lsm,btf,cap-bpf

# JSON output
kfeatures probe --json

# Display kernel config
kfeatures config
```

JSON output example:

```json
{
  "LSMProgramType": {"Supported": true},
  "Kprobe": {"Supported": true},
  "KprobeMulti": {"Supported": true},
  "Tracepoint": {"Supported": true},
  "Fentry": {"Supported": true},
  "BTF": {"Supported": true},
  "BPFLSMEnabled": {"Supported": true},
  "ActiveLSMs": ["lockdown", "capability", "yama", "apparmor", "bpf"],
  "IMAEnabled": {"Supported": false},
  "IMADirectory": {"Supported": true},
  "HasCapBPF": {"Supported": true},
  "HasCapSysAdmin": {"Supported": true},
  "HasCapPerfmon": {"Supported": true},
  "UnprivilegedBPFDisabled": {"Supported": true},
  "KernelVersion": "6.1.0-generic"
}
```

## What it detects

| Category | Features |
|---|---|
| Program types | LSM, kprobe, kprobe.multi, tracepoint, fentry |
| Core | BTF availability (CO-RE) |
| Security | BPF LSM enabled, IMA enabled, active LSM list |
| Capabilities and runtime gates | CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON, unprivileged BPF disabled, BPF stats enabled |
| Syscalls | `bpf()`, `perf_event_open()` |
| JIT | enabled, hardened, kallsyms, memory limit, `CONFIG_BPF_JIT_ALWAYS_ON` |
| Filesystems | tracefs, debugfs, securityfs, bpffs |
| Namespaces | initial user namespace, initial PID namespace |
| Parameterized workload requirements | program type, map type, helper-per-program-type via requirement items |
| Mitigation context | Spectre v1/v2 vulnerability status |
| Kernel config | CONFIG_BPF_LSM, CONFIG_IMA, CONFIG_DEBUG_INFO_BTF, CONFIG_FPROBE, any CONFIG_* |

## Requirements

- Linux (feature probing uses Linux-specific syscalls and sysfs)
- Some probes require `CAP_BPF` or `CAP_SYS_ADMIN`

## License

Apache License 2.0
