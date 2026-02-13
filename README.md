# kfeatures

Kernel feature detection for eBPF programs in Go.

kfeatures probes kernel capabilities at runtime, enabling early failure with clear, actionable error messages when requirements aren't met. It complements [`cilium/ebpf/features`](https://pkg.go.dev/github.com/cilium/ebpf/features) by adding BTF availability detection, security subsystem probing (LSM, IMA), kernel config parsing, capability checking, and composite feature validation with operator-facing diagnostics.

## Installation

```bash
go get github.com/leodido/kfeatures
```

## Usage

### Quick check

Validate that required kernel features are available:

```go
import "github.com/leodido/kfeatures"

if err := kfeatures.Check(kfeatures.FeatureBPFLSM, kfeatures.FeatureBTF); err != nil {
    var fe *kfeatures.FeatureError
    if errors.As(err, &fe) {
        log.Fatalf("kernel not ready: %s — %s", fe.Feature, fe.Reason)
        // Output: kernel not ready: BPF LSM — CONFIG_BPF_LSM not set; rebuild kernel with CONFIG_BPF_LSM=y
    }
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

## What it detects

| Category | Features |
|---|---|
| Program types | LSM, kprobe, kprobe.multi, tracepoint, fentry |
| Core | BTF availability (CO-RE) |
| Security | BPF LSM enabled, IMA enabled, active LSM list |
| Capabilities | CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON, unprivileged BPF status |
| Kernel config | CONFIG_BPF_LSM, CONFIG_IMA, CONFIG_DEBUG_INFO_BTF, CONFIG_FPROBE, any CONFIG_* |

## Value over `cilium/ebpf/features`

- **BTF availability** — `/sys/kernel/btf/vmlinux` check (not in cilium/ebpf)
- **Security subsystems** — active LSM list, IMA detection (not in cilium/ebpf)
- **Kernel config parsing** — `/proc/config.gz`, `/boot/config-*`, `/lib/modules/*/config` (not in cilium/ebpf)
- **Composite features** — e.g., kprobe.multi requires both program type support AND CONFIG_FPROBE
- **Capability detection** — CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON (not in cilium/ebpf)
- **Actionable diagnostics** — operator-facing error messages with remediation steps
- **Aggregated results** — single `SystemFeatures` struct vs. individual function calls

## Requirements

- Linux (feature probing uses Linux-specific syscalls and sysfs)
- Some probes require `CAP_BPF` or `CAP_SYS_ADMIN`

## License

Apache License 2.0
