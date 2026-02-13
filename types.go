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

// KernelConfig holds parsed kernel configuration values.
type KernelConfig struct {
	// raw stores all parsed config values for ad-hoc lookups.
	raw map[string]ConfigValue

	// Convenience fields for common checks (populated from raw).
	BPFLSM      ConfigValue // CONFIG_BPF_LSM
	IMA         ConfigValue // CONFIG_IMA
	BTF         ConfigValue // CONFIG_DEBUG_INFO_BTF
	KprobeMulti ConfigValue // CONFIG_FPROBE (required for kprobe.multi)
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
	}
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
)

var featureNames = map[Feature]string{
	FeatureBPFLSM:      "BPF LSM",
	FeatureBTF:         "BTF",
	FeatureIMA:         "IMA",
	FeatureKprobe:      "kprobe",
	FeatureKprobeMulti: "kprobe.multi",
	FeatureFentry:      "fentry",
	FeatureTracepoint:  "tracepoint",
	FeatureCapBPF:      "CAP_BPF",
	FeatureCapSysAdmin: "CAP_SYS_ADMIN",
	FeatureCapPerfmon:  "CAP_PERFMON",
	FeatureJITEnabled:  "BPF JIT",
	FeatureJITHardened: "BPF JIT hardening",
}

func (f Feature) String() string {
	if name, ok := featureNames[f]; ok {
		return name
	}
	return fmt.Sprintf("Feature(%d)", f)
}
