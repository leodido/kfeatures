//go:build linux

package kfeatures

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Check probes the specified kernel features and returns a *[FeatureError]
// for the first unsatisfied requirement, or nil if all are met.
// Kernel config is always probed to provide actionable diagnostics.
func Check(required ...Feature) error {
	opts := probeOptionsFor(required)
	opts = append(opts, WithKernelConfig())
	sf, err := ProbeWith(opts...)
	if err != nil {
		return fmt.Errorf("probe features: %w", err)
	}
	for _, f := range required {
		result, known := sf.Result(f)
		if !known {
			return &FeatureError{Feature: f.String(), Reason: "unknown feature"}
		}
		if !result.Supported {
			return &FeatureError{
				Feature: f.String(),
				Reason:  sf.Diagnose(f),
				Err:     result.Error,
			}
		}
	}
	return nil
}

// Result maps a [Feature] to its corresponding [ProbeResult] in SystemFeatures.
// Returns false as the second value if the feature is unknown.
func (sf *SystemFeatures) Result(f Feature) (ProbeResult, bool) {
	switch f {
	case FeatureBPFLSM:
		return sf.BPFLSMEnabled, true
	case FeatureBTF:
		return sf.BTF, true
	case FeatureIMA:
		return sf.IMAEnabled, true
	case FeatureKprobe:
		return sf.Kprobe, true
	case FeatureKprobeMulti:
		return sf.KprobeMulti, true
	case FeatureFentry:
		return sf.Fentry, true
	case FeatureTracepoint:
		return sf.Tracepoint, true
	case FeatureCapBPF:
		return sf.HasCapBPF, true
	case FeatureCapSysAdmin:
		return sf.HasCapSysAdmin, true
	case FeatureCapPerfmon:
		return sf.HasCapPerfmon, true
	case FeatureJITEnabled:
		return sf.JITEnabled, true
	case FeatureJITHardened:
		return sf.JITHardened, true
	case FeatureBPFSyscall:
		return sf.BPFSyscall, true
	case FeaturePerfEventOpen:
		return sf.PerfEventOpen, true
	case FeatureSleepableBPF:
		return ProbeResult{Supported: sf.PreemptMode.SupportsSleepable()}, true
	default:
		return ProbeResult{}, false
	}
}

// Diagnose returns an enriched reason string explaining why a feature
// is not supported and what the operator can do to fix it.
func (sf *SystemFeatures) Diagnose(f Feature) string {
	kc := sf.KernelConfig // may be nil

	switch f {
	case FeatureBPFLSM:
		if kc != nil && !kc.BPFLSM.IsEnabled() {
			return "CONFIG_BPF_LSM not set; rebuild kernel with CONFIG_BPF_LSM=y"
		}
		if kc != nil && kc.BPFLSM.IsEnabled() && sf.LSMProgramType.Supported && !sf.BPFLSMEnabled.Supported {
			return "CONFIG_BPF_LSM=y but 'bpf' not in active LSM list; add lsm=...,bpf to kernel boot params"
		}
	case FeatureBTF:
		if kc != nil && !kc.BTF.IsEnabled() {
			return "CONFIG_DEBUG_INFO_BTF not set; rebuild kernel with CONFIG_DEBUG_INFO_BTF=y"
		}
	case FeatureKprobeMulti:
		if kc != nil && !kc.KprobeMulti.IsEnabled() {
			return "CONFIG_FPROBE not set; requires kernel 5.18+ with CONFIG_FPROBE=y"
		}
	case FeatureIMA:
		if kc != nil && !kc.IMA.IsEnabled() {
			return "CONFIG_IMA not set; rebuild kernel with CONFIG_IMA=y"
		}
	case FeatureCapBPF:
		return "missing CAP_BPF; run with CAP_BPF or as root"
	case FeatureCapSysAdmin:
		return "missing CAP_SYS_ADMIN; run as root or add CAP_SYS_ADMIN"
	case FeatureCapPerfmon:
		return "missing CAP_PERFMON; run with CAP_PERFMON or as root"
	case FeatureJITEnabled:
		return "BPF JIT disabled; set /proc/sys/net/core/bpf_jit_enable to 1"
	case FeatureJITHardened:
		return "BPF JIT hardening disabled; set /proc/sys/net/core/bpf_jit_harden to 1 or 2"
	case FeatureBPFSyscall:
		return "bpf() syscall not available; kernel too old or CONFIG_BPF not enabled"
	case FeaturePerfEventOpen:
		return "perf_event_open() syscall not available; kernel too old or CONFIG_PERF_EVENTS not enabled"
	case FeatureSleepableBPF:
		if kc != nil {
			return fmt.Sprintf("kernel preemption model is %s; sleepable BPF (BPF_F_SLEEPABLE) requires CONFIG_PREEMPT or CONFIG_PREEMPT_DYNAMIC", kc.Preempt)
		}
		return "cannot determine preemption model; kernel config not available"
	}

	// Fallback: use the probe error if available.
	result, known := sf.Result(f)
	if known && result.Error != nil {
		return result.Error.Error()
	}
	return "not supported"
}

// probeOptionsFor determines which [ProbeOption] functions are needed
// for the given feature requirements.
func probeOptionsFor(reqs []Feature) []ProbeOption {
	var needSecurity bool
	var needKernelConfig bool
	var needCapabilities bool
	var needJIT bool
	var needSyscalls bool
	var programTypes []ebpf.ProgramType

	for _, f := range reqs {
		switch f {
		case FeatureBPFLSM, FeatureIMA:
			needSecurity = true
		case FeatureKprobe:
			programTypes = append(programTypes, ebpf.Kprobe)
		case FeatureKprobeMulti:
			programTypes = append(programTypes, ebpf.Kprobe)
			needKernelConfig = true // kprobe.multi requires CONFIG_FPROBE check
		case FeatureFentry:
			programTypes = append(programTypes, ebpf.Tracing)
		case FeatureTracepoint:
			programTypes = append(programTypes, ebpf.TracePoint)
		case FeatureCapBPF, FeatureCapSysAdmin, FeatureCapPerfmon:
			needCapabilities = true
		case FeatureJITEnabled, FeatureJITHardened:
			needJIT = true
		case FeatureBPFSyscall, FeaturePerfEventOpen:
			needSyscalls = true
		case FeatureSleepableBPF:
			needKernelConfig = true
		}
	}

	var opts []ProbeOption
	if needSyscalls {
		opts = append(opts, WithSyscalls())
	}
	if needSecurity {
		opts = append(opts, WithSecuritySubsystems())
	}
	if len(programTypes) > 0 {
		opts = append(opts, WithProgramTypes(programTypes...))
	}
	if needKernelConfig {
		opts = append(opts, WithKernelConfig())
	}
	if needCapabilities {
		opts = append(opts, WithCapabilities())
	}
	if needJIT {
		opts = append(opts, WithJIT())
	}
	return opts
}
