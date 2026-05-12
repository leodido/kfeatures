# kfeatures

[![Go Reference](https://img.shields.io/static/v1?label=&message=reference&color=00ADD8&logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/leodido/kfeatures)
[![CI](https://img.shields.io/github/actions/workflow/status/leodido/kfeatures/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/leodido/kfeatures/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/leodido/kfeatures?sort=semver&style=flat-square)](https://github.com/leodido/kfeatures/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/leodido/kfeatures?style=flat-square)](go.mod)
[![License](https://img.shields.io/github/license/leodido/kfeatures?style=flat-square)](LICENSE)

> Can my eBPF tool actually run here, and if not, exactly what needs to change?

`kfeatures` is a pure-Go library that answers this question.

It probes kernel capabilities at runtime and returns actionable diagnostics: not just *unsupported*, but **why** and **how to fix it**.

```go
if err := kfeatures.Check(kfeatures.FeatureBPFLSM, kfeatures.FeatureBTF); err != nil {
    var fe *kfeatures.FeatureError
    if errors.As(err, &fe) {
        log.Fatalf("%s - %s", fe.Feature, fe.Reason)
        // Output: BPF LSM - CONFIG_BPF_LSM=y but 'bpf' not in active LSM list; add lsm=...,bpf to kernel boot params
    }
}
```

The same answers are available from the CLI for **CI/CD gating** (semantic exit codes), and from `--mcp` mode for **AI agents** (JSON-RPC over stdio, every subcommand exposed as an MCP tool with a discoverable input schema). See [CLI](#cli).

## Why not `cilium/ebpf/features` or `bpftool`?

[`cilium/ebpf/features`](https://pkg.go.dev/github.com/cilium/ebpf/features) answers: *"Does this kernel support program type X?"*

[`bpftool feature probe`](https://man.archlinux.org/man/bpftool-feature.8.en) answers: *"What BPF features does this kernel have?"* (CLI only, not embeddable in Go)

Neither tells you whether your tool can **actually run**. For example, BPF LSM requires three things simultaneously: `CONFIG_BPF_LSM=y` in the kernel config, `bpf` in the active LSM boot parameter list, and the LSM program type supported by the running kernel. `cilium/ebpf/features` can only check the last one. `bpftool` can check the first and last, but not the second. Neither provides remediation guidance.

| Capability | `cilium/ebpf/features` | `bpftool feature probe` | **`kfeatures`** |
|---|:---:|:---:|:---:|
| BPF program type probes | ✓ | ✓ | ✓ |
| BPF map type / helper probes | ✓ | ✓ | ✓ † |
| **BTF availability** (`/sys/kernel/btf/vmlinux`) | ✗ | ✗ * | ✓ |
| **Kernel config parsing** (any `CONFIG_*`, =y/=m) | ✗ | ✓ | ✓ |
| **Active LSM list** (`/sys/kernel/security/lsm`) | ✗ | ✗ | ✓ |
| **BPF LSM enabled** (config + boot params + program type) | ✗ | ✗ | ✓ |
| **IMA detection** (LSM list + securityfs directory) | ✗ | ✗ | ✓ |
| **IMA any measurement active** (runtime policy detection) | ✗ | ✗ | ✓ |
| **Process capabilities** (CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON) | ✗ | ✗ | ✓ |
| **Unprivileged BPF status** | ✗ | ✓ | ✓ |
| **Mount-state gates** (bpffs/tracefs/custom paths via superblock magic) | ✗ | ✗ | ✓ |
| **ELF requirement extraction** (parse `.o`, derive requirements) | ✗ | ✗ | ✓ |
| **Composite feature validation** | ✗ | ✗ | ✓ |
| **Actionable diagnostics** (remediation steps) | ✗ | ✗ | ✓ |
| Selective probing (minimize overhead) | ✓ ‡ | ✗ § | ✓ |
| Pure Go, no CGO | ✓ | ✗ | ✓ |
| Usable as a Go library | ✓ | ✗ | ✓ |

<sup>\* `bpftool` checks `CONFIG_DEBUG_INFO_BTF` in the kernel config but does not verify `/sys/kernel/btf/vmlinux` exists.</sup>
<sup>† Exposed in `kfeatures` as parameterized requirements (`RequireMapType`, `RequireProgramHelper`) consumed by `Check(...)`.</sup>
<sup>‡ `cilium/ebpf/features` is per-function: callers invoke individual probe functions on demand.</sup>
<sup>§ `bpftool feature probe` runs the full probe set on every invocation.</sup>

Other Go projects ([libbpfgo](https://github.com/aquasecurity/libbpfgo), [Tetragon](https://github.com/cilium/tetragon), [Falco libs](https://github.com/falcosecurity/libs)) have some feature detection built in, but none is a standalone reusable library. They are either CGO-dependent, tightly coupled to their parent project, or written in C/C++.

## Installation

Library:

```bash
go get github.com/leodido/kfeatures
```

CLI binary (Linux amd64 / arm64):

```bash
# Replace VERSION (e.g. 0.5.1) and ARCH (amd64 or arm64).
curl -sSLO "https://github.com/leodido/kfeatures/releases/download/v${VERSION}/kfeatures_${VERSION}_linux_${ARCH}.tar.gz"
tar xzf "kfeatures_${VERSION}_linux_${ARCH}.tar.gz"
./kfeatures version
```

For supply-chain verification of the binary before extracting, see
[Verifying releases](#verifying-releases) below.

## Usage

### Quick check

Validate that required kernel features are available:

```go
import (
    "errors"
    "log"

    "github.com/leodido/kfeatures"
)

if err := kfeatures.Check(kfeatures.FeatureBPFLSM, kfeatures.FeatureBTF); err != nil {
    var fe *kfeatures.FeatureError
    if errors.As(err, &fe) {
        log.Fatalf("kernel not ready: %s - %s", fe.Feature, fe.Reason)
    }
}
```

### Mixed requirements

Combine `Feature` enums with parameterized workload requirements:

```go
import (
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
    "github.com/leodido/kfeatures"
)

err := kfeatures.Check(
    kfeatures.FeatureBTF,
    kfeatures.RequireProgramType(ebpf.XDP),
    kfeatures.RequireMapType(ebpf.Hash),
    kfeatures.RequireProgramHelper(ebpf.XDP, asm.FnMapLookupElem),
)
```

### Custom mount paths (`RequireMount`)

Gate on a filesystem mounted at an arbitrary path with the expected superblock magic. Useful when bpffs lives somewhere other than `/sys/fs/bpf`:

```go
import (
    "github.com/leodido/kfeatures"
    "golang.org/x/sys/unix"
)

err := kfeatures.Check(
    kfeatures.RequireMount("/run/bpf", unix.BPF_FS_MAGIC),
)
```

Magic constants come from `golang.org/x/sys/unix` (e.g. `unix.BPF_FS_MAGIC`, `unix.TRACEFS_MAGIC`, `unix.CGROUP2_SUPER_MAGIC`).

### Reusable presets (`FeatureGroup`)

`FeatureGroup` packages a set of requirements as a single value you can pass anywhere a `Requirement` is accepted:

```go
var TracingTool = kfeatures.FeatureGroup{
    kfeatures.FeatureBTF,
    kfeatures.FeatureKprobeMulti,
    kfeatures.RequireProgramType(ebpf.Kprobe),
}

if err := kfeatures.Check(TracingTool); err != nil {
    log.Fatal(err)
}
```

### Extract requirements from a compiled object (`FromELF`)

Point `FromELF` at an eBPF `.o` and get back a `FeatureGroup` describing its program types, map types, and helper-per-program requirements (directly consumable by `Check`):

```go
reqs, err := kfeatures.FromELF("./bpf/probe.o")
if err != nil {
    log.Fatal(err)
}
if err := kfeatures.Check(reqs); err != nil {
    log.Fatalf("kernel cannot run probe.o: %v", err)
}
```

Output is deterministic (deduplicated, stably ordered). Unknown ELF kinds fail closed.

### Render remediation (`Diagnose`)

`Check` returns the diagnosis for the first failing feature. To inspect any feature against a single probe snapshot, call `Diagnose` directly:

```go
sf, _ := kfeatures.Probe()
if !sf.BPFLSMEnabled.Supported {
    fmt.Println(sf.Diagnose(kfeatures.FeatureBPFLSM))
    // CONFIG_BPF_LSM=y but 'bpf' not in active LSM list; add lsm=...,bpf to kernel boot params
}
```

### Full probe

Probe all features for diagnostics and reporting:

```go
sf, err := kfeatures.Probe()
if err != nil {
    log.Fatal(err)
}
fmt.Println(sf)
```

Sample output (truncated):

```
Kernel: 6.1.0-generic

Program Types:
  LSM: yes
  kprobe: yes
  kprobe.multi: yes

Core:
  BTF: yes

Security Subsystems:
  BPF LSM enabled: yes
  IMA enabled: no
  IMA directory: yes
  IMA any measurement active: no
  Active LSMs: lockdown, capability, yama, apparmor, bpf

Filesystems:
  tracefs: yes
  bpffs: yes
```

Individual fields are typed and inspectable programmatically (see [`SystemFeatures`](https://pkg.go.dev/github.com/leodido/kfeatures#SystemFeatures)).

### Selective probing

Probe only what you need:

```go
sf, err := kfeatures.ProbeWith(
    kfeatures.WithProgramTypes(ebpf.LSM, ebpf.Kprobe),
    kfeatures.WithSecuritySubsystems(),
    kfeatures.WithCapabilities(),
)
```

`WithX` options select probe scope. They do not define requirements; use `Check(...)` for gating.

## CLI

A CLI is included for operator diagnostics, CI/CD gating, and AI-agent integration:

```bash
go install github.com/leodido/kfeatures/cmd/kfeatures@latest
```

```bash
kfeatures probe                                    # probe all features
kfeatures check --require bpf-lsm,btf,cap-bpf      # exit 0 if met, 1 otherwise
kfeatures probe --json                             # JSON output
kfeatures config                                   # display kernel config
```

### CI/CD gating (semantic exit codes)

`kfeatures check` exits **0** when all requirements are met and **1** when any are missing. Drop it into a Helm chart pre-install hook, an init container, or a CI job. With `--json` the verdict is a parse-friendly object on stdout:

```bash
$ kfeatures check --require bpf-lsm,btf --json
{
  "ok": false,
  "feature": "bpf-lsm",
  "reason": "CONFIG_BPF_LSM=y but 'bpf' not in active LSM list; add lsm=...,bpf to kernel boot params"
}
$ echo $?
1
```

Invocation errors (missing required flag, unknown flag, invalid value, unknown subcommand) emit a structured JSON envelope on stderr and exit with a **semantic** code so wrappers can distinguish "the user invoked us wrong" from "the kernel is missing a feature":

| Exit code | Category    | Example                                                |
| --------- | ----------- | ------------------------------------------------------ |
| `0`       | OK          | check passed                                           |
| `1`       | Runtime     | `FeatureError`, probe failure, missing kernel config   |
| `10`      | Input       | `missing_required_flag`: required flag not provided    |
| `11`      | Input       | `invalid_flag_value`: wrong type or unknown enum       |
| `12`      | Input       | `unknown_flag`                                         |
| `14`      | Input       | `unknown_command`                                      |

```bash
$ kfeatures check --require bogus
{"error":"invalid_flag_value","exit_code":11,"flag":"require","got":"bogus","expected":"feature","command":"kfeatures check","message":"invalid argument \"bogus\" for \"-r, --require\" flag: unknown feature: \"bogus\" (available: …)"}
$ echo $?
11
```

Codes follow the [structcli/exitcode](https://pkg.go.dev/github.com/leodido/structcli/exitcode) categories: input errors `10`–`19` are agent-fixable, runtime errors `1`–`9` are operator-fixable.

### AI agents (`--jsonschema`, `--mcp`)

`kfeatures` is built to be driven by LLM agents and code-generation tooling without `--help` scraping.

**`--jsonschema`** dumps a JSON Schema describing a command's flags. Use `=tree` to walk the entire subtree:

```bash
$ kfeatures check --jsonschema | jq '.title, .properties | keys'
"kfeatures check"
[
  "json",
  "require"
]

$ kfeatures --jsonschema=tree | jq 'map(.title) | map(select(test("^kfeatures( probe| check| config| version)?$")))'
[
  "kfeatures",
  "kfeatures check",
  "kfeatures config",
  "kfeatures probe",
  "kfeatures version"
]
```

(`--jsonschema=tree` walks every node, including cobra-generated `help` and `completion` leaves; filter with `jq` to the ones you care about.)

**`--mcp`** turns `kfeatures` into a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio. Each runnable leaf command becomes an MCP tool whose input schema mirrors the cobra flag set; agents introspect via `tools/list` and invoke via `tools/call`:

```jsonc
// Claude Desktop / any MCP-aware client config
{
  "mcpServers": {
    "kfeatures": {
      "command": "kfeatures",
      "args": ["--mcp"]
    }
  }
}
```

Tools exposed: `probe`, `check`, `config`. The server stays alive across business-outcome errors (a failing `check` does not terminate the session), and invocation errors flow through the same structured envelope as the CLI. Pure stdlib JSON-RPC inside [structcli](https://github.com/leodido/structcli/tree/main/mcp); no extra heavy SDK dependency.

## What it detects

| Category | Features |
|---|---|
| Program types | LSM, kprobe, kprobe.multi, tracepoint, fentry |
| Core | BTF availability (CO-RE) |
| Security | BPF LSM enabled, IMA enabled, IMA any measurement active, active LSM list |
| Capabilities and runtime gates | CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON, unprivileged BPF disabled, BPF stats enabled |
| Syscalls | `bpf()`, `perf_event_open()` |
| JIT | enabled, hardened, kallsyms, memory limit, `CONFIG_BPF_JIT_ALWAYS_ON` |
| Filesystems | tracefs, debugfs, securityfs, bpffs (gated `tracefs`/`bpffs` checks verify the filesystem is mounted with the expected superblock magic) |
| Custom mount gates | any path + superblock magic via `RequireMount` |
| Namespaces | initial user namespace, initial PID namespace |
| Parameterized workload requirements | program type, map type, helper-per-program-type via requirement items |
| ELF-derived requirements | program/map types and helper-per-program requirements via `FromELF` |
| Mitigation context | Spectre v1/v2 vulnerability status |
| Kernel config | `CONFIG_BPF_LSM`, `CONFIG_IMA`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_FPROBE`, any `CONFIG_*` |

## Stability

Pre-1.0. The public API may change between minor versions; breaking changes are
called out explicitly in [CHANGELOG.md](CHANGELOG.md). The `FromELF` contract
(signature, determinism, fail-closed semantics) is frozen; see
[CONTRIBUTING.md](CONTRIBUTING.md#fromelf-contract).

## Requirements

- Linux for runtime probing/checking (uses Linux-specific syscalls and sysfs).
- `FromELF` is parser-only and works on any platform.
- Some probes require `CAP_BPF` or `CAP_SYS_ADMIN`.

## Verifying releases

Every release artifact (each platform tarball and the `checksums.txt`) is
signed with [cosign](https://github.com/sigstore/cosign) keyless signing
backed by GitHub's OIDC token. Each artifact has a sibling
`<artifact>.sigstore.json` bundle containing the signature, the signing
certificate (with the workflow identity baked in), and the Rekor
transparency-log inclusion proof.

To verify before extracting (replace `VERSION` and `ARCH`):

```bash
curl -sSLO "https://github.com/leodido/kfeatures/releases/download/v${VERSION}/kfeatures_${VERSION}_linux_${ARCH}.tar.gz"
curl -sSLO "https://github.com/leodido/kfeatures/releases/download/v${VERSION}/kfeatures_${VERSION}_linux_${ARCH}.tar.gz.sigstore.json"

cosign verify-blob \
  --bundle "kfeatures_${VERSION}_linux_${ARCH}.tar.gz.sigstore.json" \
  --certificate-identity "https://github.com/leodido/kfeatures/.github/workflows/release.yaml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "kfeatures_${VERSION}_linux_${ARCH}.tar.gz"
```

A successful verification proves that the artifact was produced by the
`release.yaml` workflow at the tagged revision, signed by GitHub's OIDC
issuer, and is recorded on the public Rekor transparency log. Requires
cosign v2.0+.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the API model, the
feature-addition checklist, and the development workflow.

## License

[Apache License 2.0](LICENSE). Project attribution in [NOTICE](NOTICE), per Apache 2.0 §4(d).

### Why Apache 2.0

`kfeatures` is pure-Go userspace. No kernel source embedded, no cgo, no GPL/LGPL deps. Kernel interaction is uABI only: reads from `/proc` and `/sys`, syscalls and constants via [`golang.org/x/sys/unix`](https://pkg.go.dev/golang.org/x/sys/unix) (BSD-3-Clause), ELF parsing via [`github.com/cilium/ebpf`](https://pkg.go.dev/github.com/cilium/ebpf) (MIT; never calls `BPF_PROG_LOAD`). The kernel's `COPYING` carves "user programs that use kernel services by normal system calls" out of GPL: the carve-out `ps`, `ls`, and `mount` rely on.

Apache 2.0 over MIT:

- Patent grant (§3). Probing eBPF, LSM, IMA, namespaces, and Spectre mitigations is patent-adjacent. Apache 2.0 grants an irrevocable patent license with defensive termination. MIT has none.
- Adopter alignment. Cilium, Tetragon, Tracee, Falco, Pixie, and Inspektor Gadget are Apache 2.0. No compatibility review needed.
