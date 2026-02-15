package kfeatures

import "fmt"

// ProbeResult represents the outcome of a kernel feature probe.
type ProbeResult struct {
	// Supported indicates whether the feature is available.
	Supported bool
	// Error is non-nil if the probe itself failed (not just unsupported).
	Error error
}

// FeatureError represents an error when a required kernel feature is unavailable.
type FeatureError struct {
	Feature string
	Reason  string
	Err     error
}

func (e *FeatureError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("feature %s: %s: %v", e.Feature, e.Reason, e.Err)
	}
	return fmt.Sprintf("feature %s: %s", e.Feature, e.Reason)
}

func (e *FeatureError) Unwrap() error {
	return e.Err
}

// SystemFeatures holds the results of all kernel feature probes.
type SystemFeatures struct {
	// Syscall availability
	// BPFSyscall: Supported=true means the bpf() syscall is available.
	BPFSyscall ProbeResult
	// PerfEventOpen: Supported=true means the perf_event_open() syscall is available.
	// Required for kprobe/tracepoint/uprobe attachment.
	PerfEventOpen ProbeResult

	// Program types (runtime probes via cilium/ebpf)
	LSMProgramType ProbeResult
	Kprobe         ProbeResult
	KprobeMulti    ProbeResult
	Tracepoint     ProbeResult
	Fentry         ProbeResult

	// BTF (BPF Type Format) for CO-RE programs
	BTF ProbeResult

	// Security subsystems (sysfs checks)
	// These use ProbeResult because reading /sys/kernel/security/lsm can fail
	// (permissions, securityfs not mounted, etc.)
	BPFLSMEnabled ProbeResult
	ActiveLSMs    []string

	// IMA detection (multiple signals for diagnostics)
	// IMAEnabled is the authoritative signal: true only if "ima" is in the LSM list.
	// This is required for bpf_ima_file_hash to work.
	IMAEnabled ProbeResult
	// IMADirectory indicates /sys/kernel/security/ima exists.
	// IMA securityfs is mounted, but IMA may not be actively measuring files.
	IMADirectory ProbeResult

	// Process capabilities relevant to BPF operations
	HasCapBPF      ProbeResult // CAP_BPF (kernel 5.8+)
	HasCapSysAdmin ProbeResult // CAP_SYS_ADMIN (fallback for pre-5.8 kernels)
	HasCapPerfmon  ProbeResult // CAP_PERFMON (perf events, tracepoints)

	// Unprivileged BPF access
	// Supported=true means unprivileged BPF is disabled (the common/secure default).
	UnprivilegedBPFDisabled ProbeResult

	// Filesystem mounts relevant to BPF operations
	// TraceFS: required for kprobe/tracepoint attachment via ftrace.
	TraceFS ProbeResult
	// DebugFS: legacy mount point, fallback for tracefs on older kernels.
	DebugFS ProbeResult
	// SecurityFS: required for reading LSM state (/sys/kernel/security/*).
	SecurityFS ProbeResult
	// BPFFS: required for pinning BPF maps and programs (/sys/fs/bpf).
	BPFFS ProbeResult

	// JIT compiler status (sysctl values)
	// JITEnabled: Supported=true means BPF JIT compiler is enabled.
	// Values: 0=disabled, 1=enabled, 2=enabled+debug (emit to kernel log).
	JITEnabled ProbeResult
	// JITHardened: Supported=true means BPF JIT hardening is active.
	// Values: 0=disabled, 1=enabled for unprivileged, 2=enabled for all.
	JITHardened ProbeResult
	// JITKallsyms: Supported=true means JIT-compiled BPF programs are exposed in /proc/kallsyms.
	JITKallsyms ProbeResult
	// JITLimit: the memory limit in bytes for JIT-compiled BPF programs (0 if unavailable).
	JITLimit int64

	// JIT always-on mode (derived from kernel config).
	// When CONFIG_BPF_JIT_ALWAYS_ON=y, the BPF interpreter is disabled and
	// all programs must be JIT-compiled. Forced by some Spectre mitigation policies.
	JITAlwaysOn ConfigValue

	// CPU vulnerability mitigations.
	// Each field contains the raw mitigation string from /sys/devices/system/cpu/vulnerabilities/
	// or empty if the file doesn't exist. Values like "Mitigation: ..." mean active protection.
	SpectreV1 string // spectre_v1
	SpectreV2 string // spectre_v2

	// Kernel preemption model (derived from kernel config).
	// Affects sleepable BPF programs (BPF_F_SLEEPABLE).
	PreemptMode PreemptMode

	// Namespace awareness.
	// InInitUserNS: Supported=true means the process runs in the initial user namespace.
	// BPF is often restricted in non-initial user namespaces.
	InInitUserNS ProbeResult
	// InInitPIDNS: Supported=true means the process runs in the initial PID namespace.
	// bpf_get_current_pid_tgid() returns the PID in the current PID namespace, which
	// differs from the host PID when running in a nested PID namespace.
	InInitPIDNS ProbeResult

	// BPF runtime statistics
	// BPFStatsEnabled: Supported=true means /proc/sys/kernel/bpf_stats_enabled is non-zero.
	// When enabled, the kernel collects per-program runtime stats (run count, run time).
	// Useful for verifier profiling and performance debugging.
	BPFStatsEnabled ProbeResult

	// Kernel config (optional, may be nil if not probed)
	KernelConfig *KernelConfig

	// Metadata
	KernelVersion string
}

// ConfigValue represents a kernel configuration option's state.
type ConfigValue int

const (
	// ConfigNotSet means the option is not set or not found.
	ConfigNotSet ConfigValue = iota
	// ConfigModule means the option is set to =m (module).
	ConfigModule
	// ConfigBuiltin means the option is set to =y (built-in).
	ConfigBuiltin
)

// IsEnabled returns true if the config option is set (either =m or =y).
func (v ConfigValue) IsEnabled() bool {
	return v == ConfigModule || v == ConfigBuiltin
}

// IsBuiltin returns true if the config option is built-in (=y).
func (v ConfigValue) IsBuiltin() bool {
	return v == ConfigBuiltin
}

func (v ConfigValue) String() string {
	switch v {
	case ConfigNotSet:
		return "not set"
	case ConfigModule:
		return "m"
	case ConfigBuiltin:
		return "y"
	default:
		return fmt.Sprintf("ConfigValue(%d)", v)
	}
}

// PreemptMode represents the kernel preemption model.
type PreemptMode int

const (
	// PreemptUnknown means the preemption model could not be determined.
	PreemptUnknown PreemptMode = iota
	// PreemptNone means no forced preemption (server workloads).
	PreemptNone
	// PreemptVoluntary means voluntary preemption (desktop default).
	PreemptVoluntary
	// PreemptFull means full preemption (low-latency).
	PreemptFull
	// PreemptDynamic means runtime-switchable preemption (kernel 5.12+).
	PreemptDynamic
)

func (m PreemptMode) String() string {
	switch m {
	case PreemptNone:
		return "none"
	case PreemptVoluntary:
		return "voluntary"
	case PreemptFull:
		return "full"
	case PreemptDynamic:
		return "dynamic"
	default:
		return "unknown"
	}
}

// SupportsSleepable reports whether the preemption model supports
// sleepable BPF programs (BPF_F_SLEEPABLE). Requires full preemption
// or dynamic preemption.
func (m PreemptMode) SupportsSleepable() bool {
	return m == PreemptFull || m == PreemptDynamic
}

// KernelConfig holds parsed kernel configuration values.
type KernelConfig struct {
	// raw stores all parsed config values for ad-hoc lookups.
	raw map[string]ConfigValue

	// Convenience fields for common checks (populated from raw).
	BPFLSM      ConfigValue // CONFIG_BPF_LSM
	IMA         ConfigValue // CONFIG_IMA
	BTF         ConfigValue // CONFIG_DEBUG_INFO_BTF
	KprobeMulti ConfigValue // CONFIG_FPROBE (required for kprobe.multi)
	JITAlwaysOn ConfigValue // CONFIG_BPF_JIT_ALWAYS_ON
	Preempt     PreemptMode // Derived from CONFIG_PREEMPT_*
}

// Get returns the ConfigValue for a kernel config key.
// The key should not include the CONFIG_ prefix.
func (kc *KernelConfig) Get(key string) ConfigValue {
	if kc == nil || kc.raw == nil {
		return ConfigNotSet
	}
	return kc.raw[key]
}

// IsSet returns true if the config option is enabled (=m or =y).
func (kc *KernelConfig) IsSet(key string) bool {
	return kc.Get(key).IsEnabled()
}

// NewKernelConfig creates a KernelConfig from a raw config map.
// The map is copied to ensure immutability after construction.
func NewKernelConfig(raw map[string]ConfigValue) *KernelConfig {
	copied := make(map[string]ConfigValue, len(raw))
	for k, v := range raw {
		copied[k] = v
	}
	return &KernelConfig{
		raw:         copied,
		BPFLSM:      copied["BPF_LSM"],
		IMA:         copied["IMA"],
		BTF:         copied["DEBUG_INFO_BTF"],
		KprobeMulti: copied["FPROBE"],
		JITAlwaysOn: copied["BPF_JIT_ALWAYS_ON"],
		Preempt:     derivePreemptMode(copied),
	}
}

// derivePreemptMode determines the preemption model from kernel config values.
// Priority: dynamic > full > voluntary > none.
func derivePreemptMode(raw map[string]ConfigValue) PreemptMode {
	if raw["PREEMPT_DYNAMIC"] == ConfigBuiltin {
		return PreemptDynamic
	}
	if raw["PREEMPT"] == ConfigBuiltin {
		return PreemptFull
	}
	if raw["PREEMPT_VOLUNTARY"] == ConfigBuiltin {
		return PreemptVoluntary
	}
	if raw["PREEMPT_NONE"] == ConfigBuiltin {
		return PreemptNone
	}
	return PreemptUnknown
}

// Feature represents a kernel capability that can be checked via [Check].
type Feature int

const (
	// FeatureBPFLSM requires BPF LSM support (CONFIG_BPF_LSM + enabled at boot).
	FeatureBPFLSM Feature = iota
	// FeatureBTF requires BTF support (CONFIG_DEBUG_INFO_BTF) for CO-RE programs.
	FeatureBTF
	// FeatureIMA requires Integrity Measurement Architecture support.
	FeatureIMA
	// FeatureKprobe requires kprobe program support.
	FeatureKprobe
	// FeatureKprobeMulti requires kprobe.multi program support.
	FeatureKprobeMulti
	// FeatureFentry requires fentry/fexit program support.
	FeatureFentry
	// FeatureTracepoint requires tracepoint program support.
	FeatureTracepoint
	// FeatureCapBPF requires the CAP_BPF capability (kernel 5.8+).
	FeatureCapBPF
	// FeatureCapSysAdmin requires the CAP_SYS_ADMIN capability.
	FeatureCapSysAdmin
	// FeatureCapPerfmon requires the CAP_PERFMON capability.
	FeatureCapPerfmon
	// FeatureJITEnabled requires the BPF JIT compiler to be enabled.
	FeatureJITEnabled
	// FeatureJITHardened requires BPF JIT hardening to be active.
	FeatureJITHardened
	// FeatureBPFSyscall requires the bpf() syscall to be available.
	FeatureBPFSyscall
	// FeaturePerfEventOpen requires the perf_event_open() syscall to be available.
	FeaturePerfEventOpen
	// FeatureSleepableBPF requires a preemptible kernel for BPF_F_SLEEPABLE programs.
	FeatureSleepableBPF
	// FeatureTraceFS requires tracefs to be mounted.
	FeatureTraceFS
	// FeatureBPFFS requires bpffs to be mounted.
	FeatureBPFFS
	// FeatureInitUserNS requires running in the initial user namespace.
	FeatureInitUserNS
	// FeatureUnprivilegedBPFDisabled requires unprivileged BPF to be disabled.
	FeatureUnprivilegedBPFDisabled
	// FeatureBPFStatsEnabled requires BPF runtime stats collection to be enabled.
	FeatureBPFStatsEnabled
)

var featureNames = map[Feature]string{
	FeatureBPFLSM:                  "BPF LSM",
	FeatureBTF:                     "BTF",
	FeatureIMA:                     "IMA",
	FeatureKprobe:                  "kprobe",
	FeatureKprobeMulti:             "kprobe.multi",
	FeatureFentry:                  "fentry",
	FeatureTracepoint:              "tracepoint",
	FeatureCapBPF:                  "CAP_BPF",
	FeatureCapSysAdmin:             "CAP_SYS_ADMIN",
	FeatureCapPerfmon:              "CAP_PERFMON",
	FeatureJITEnabled:              "BPF JIT",
	FeatureJITHardened:             "BPF JIT hardening",
	FeatureBPFSyscall:              "bpf() syscall",
	FeaturePerfEventOpen:           "perf_event_open() syscall",
	FeatureSleepableBPF:            "sleepable BPF",
	FeatureTraceFS:                 "tracefs",
	FeatureBPFFS:                   "bpffs",
	FeatureInitUserNS:              "initial user namespace",
	FeatureUnprivilegedBPFDisabled: "unprivileged BPF disabled",
	FeatureBPFStatsEnabled:         "BPF stats enabled",
}

func (f Feature) String() string {
	if name, ok := featureNames[f]; ok {
		return name
	}
	return fmt.Sprintf("Feature(%d)", f)
}
