//go:build linux

package kfeatures

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// Check validates the specified requirements and returns a *[FeatureError]
// for the first unsatisfied requirement, or nil if all are met.
//
// Accepted requirement kinds:
//   - [Feature] (stable boolean gates)
//   - [FeatureGroup] (reusable requirement presets)
//   - [ProgramTypeRequirement], [MapTypeRequirement], [ProgramHelperRequirement]
//
// Check is the only gate entrypoint. Keep ProbeWith/WithX for diagnostics-only
// data collection, not for expressing required readiness conditions.
// Kernel config is always probed to provide actionable diagnostics.
func Check(required ...Requirement) error {
	rs := normalizeRequirements(required)

	// BPF LSM requires that the kernel also supports loading LSM programs.
	for _, f := range rs.features {
		if f == FeatureBPFLSM {
			rs.programTypes = append(rs.programTypes, ebpf.LSM)
			break
		}
	}

	opts := probeOptionsFor(rs.features)
	opts = append(opts, WithKernelConfig())
	sf, err := ProbeWith(opts...)
	if err != nil {
		return fmt.Errorf("probe features: %w", err)
	}

	for _, f := range rs.features {
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

	for _, pt := range rs.programTypes {
		err := features.HaveProgramType(pt)
		if err == nil {
			continue
		}
		return &FeatureError{
			Feature: fmt.Sprintf("program type %s", pt),
			Reason:  reasonForProgramTypeError(pt, err),
			Err:     err,
		}
	}

	for _, mt := range rs.mapTypes {
		err := features.HaveMapType(mt)
		if err == nil {
			continue
		}
		return &FeatureError{
			Feature: fmt.Sprintf("map type %s", mt),
			Reason:  reasonForMapTypeError(mt, err),
			Err:     err,
		}
	}

	for _, req := range rs.programHelpers {
		err := features.HaveProgramHelper(req.ProgramType, req.Helper)
		if err == nil {
			continue
		}
		return &FeatureError{
			Feature: fmt.Sprintf("helper %s for program type %s", req.Helper, req.ProgramType),
			Reason:  reasonForProgramHelperError(req, err),
			Err:     err,
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
	case FeatureTraceFS:
		return sf.TraceFS, true
	case FeatureBPFFS:
		return sf.BPFFS, true
	case FeatureInitUserNS:
		return sf.InInitUserNS, true
	case FeatureUnprivilegedBPFDisabled:
		return sf.UnprivilegedBPFDisabled, true
	case FeatureBPFStatsEnabled:
		return sf.BPFStatsEnabled, true
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
		if sf.BPFLSMEnabled.Error != nil {
			return "unable to read active LSM list (/sys/kernel/security/lsm); ensure securityfs is mounted and readable"
		}
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
	case FeatureKprobe:
		return "kprobe program type not supported; use a kernel with BPF kprobe support or switch to a supported attach type"
	case FeatureFentry:
		return "fentry/fexit program type not supported; use a kernel with BPF trampoline support (and BTF) or switch attach strategy"
	case FeatureTracepoint:
		return "tracepoint program type not supported; ensure perf events are enabled and use a kernel with tracepoint BPF support"
	case FeatureIMA:
		if sf.IMAEnabled.Error != nil {
			return "unable to read active LSM list (/sys/kernel/security/lsm); ensure securityfs is mounted and readable to verify IMA state"
		}
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
	case FeatureTraceFS:
		return "tracefs not mounted; mount tracefs at /sys/kernel/tracing (or /sys/kernel/debug/tracing on older kernels)"
	case FeatureBPFFS:
		return "bpffs not mounted; mount bpffs at /sys/fs/bpf"
	case FeatureInitUserNS:
		return "process not in initial user namespace; run in host user namespace or adjust container runtime settings"
	case FeatureUnprivilegedBPFDisabled:
		return "unprivileged BPF is enabled; set /proc/sys/kernel/unprivileged_bpf_disabled to 1 or 2"
	case FeatureBPFStatsEnabled:
		return "BPF runtime stats are disabled; set /proc/sys/kernel/bpf_stats_enabled to 1"
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
//
// Classification rule for future additions:
// promote to [Feature] only when the signal can be expressed as a deterministic
// requirement with actionable remediation text in Diagnose. Keep descriptive
// context-only signals probe-only behind WithX options.
func probeOptionsFor(reqs []Feature) []ProbeOption {
	var needSecurity bool
	var needKernelConfig bool
	var needCapabilities bool
	var needJIT bool
	var needSyscalls bool
	var needFilesystems bool
	var needNamespaces bool
	var programTypes []ebpf.ProgramType

	// Phase-B classification decisions:
	// - DebugFS stays diagnostics-only because TraceFS is the primary readiness gate
	//   and DebugFS is a legacy/fallback mount signal.
	// - SecurityFS stays diagnostics-only because BPFLSM/IMA checks already validate
	//   functional readiness via active LSM state, not only mount presence.
	// - InInitPIDNS stays diagnostics-only because PID namespace context affects helper
	//   semantics, but is not a universal run/block condition.
	for _, f := range reqs {
		switch f {
		case FeatureBPFLSM:
			needSecurity = true
			programTypes = append(programTypes, ebpf.LSM)
		case FeatureIMA:
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
		case FeatureTraceFS, FeatureBPFFS:
			needFilesystems = true
		case FeatureInitUserNS:
			needNamespaces = true
		case FeatureUnprivilegedBPFDisabled:
			needCapabilities = true
		case FeatureBPFStatsEnabled:
			needCapabilities = true
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
	if needFilesystems {
		opts = append(opts, WithFilesystems())
	}
	if needNamespaces {
		opts = append(opts, WithNamespaces())
	}
	return opts
}

func reasonForProgramTypeError(pt ebpf.ProgramType, err error) string {
	switch {
	case errors.Is(err, ebpf.ErrNotSupported):
		return fmt.Sprintf("program type %s is unavailable on this kernel; use a kernel/workload combination that supports it", pt)
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Sprintf("cannot probe program type %s due to insufficient privileges; run as root or add CAP_BPF/CAP_SYS_ADMIN", pt)
	default:
		return fmt.Sprintf("unable to validate program type %s support; verify kernel BPF support and required privileges (CAP_BPF/CAP_SYS_ADMIN)", pt)
	}
}

func reasonForMapTypeError(mt ebpf.MapType, err error) string {
	switch {
	case errors.Is(err, ebpf.ErrNotSupported):
		return fmt.Sprintf("map type %s is unavailable on this kernel; use a supported map type or a newer kernel", mt)
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Sprintf("cannot probe map type %s due to insufficient privileges; run as root or add CAP_BPF/CAP_SYS_ADMIN", mt)
	default:
		return fmt.Sprintf("unable to validate map type %s support; verify kernel BPF support and required privileges (CAP_BPF/CAP_SYS_ADMIN)", mt)
	}
}

func reasonForProgramHelperError(req ProgramHelperRequirement, err error) string {
	switch {
	case errors.Is(err, ebpf.ErrNotSupported):
		return fmt.Sprintf("helper %s is unavailable for program type %s; choose a compatible helper/program combination or newer kernel", req.Helper, req.ProgramType)
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Sprintf("cannot probe helper %s for program type %s due to insufficient privileges; run as root or add CAP_BPF/CAP_SYS_ADMIN", req.Helper, req.ProgramType)
	default:
		return fmt.Sprintf("unable to validate helper %s for program type %s; verify kernel support and required privileges (CAP_BPF/CAP_SYS_ADMIN)", req.Helper, req.ProgramType)
	}
}
