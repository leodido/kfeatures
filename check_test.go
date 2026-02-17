//go:build linux

package kfeatures

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestSystemFeatures_Result(t *testing.T) {
	sf := &SystemFeatures{
		LSMProgramType:          ProbeResult{Supported: true},
		BPFLSMEnabled:           ProbeResult{Supported: true},
		BTF:                     ProbeResult{Supported: true},
		IMAEnabled:              ProbeResult{Supported: false},
		Kprobe:                  ProbeResult{Supported: true},
		KprobeMulti:             ProbeResult{Supported: true},
		Fentry:                  ProbeResult{Supported: true},
		Tracepoint:              ProbeResult{Supported: true},
		HasCapBPF:               ProbeResult{Supported: true},
		HasCapSysAdmin:          ProbeResult{Supported: true},
		HasCapPerfmon:           ProbeResult{Supported: false},
		UnprivilegedBPFDisabled: ProbeResult{Supported: true},
		JITEnabled:              ProbeResult{Supported: true},
		JITHardened:             ProbeResult{Supported: false},
		BPFSyscall:              ProbeResult{Supported: true},
		PerfEventOpen:           ProbeResult{Supported: true},
		TraceFS:                 ProbeResult{Supported: true},
		BPFFS:                   ProbeResult{Supported: false},
		InInitUserNS:            ProbeResult{Supported: false},
		BPFStatsEnabled:         ProbeResult{Supported: false},
		PreemptMode:             PreemptDynamic,
	}

	tests := []struct {
		feature   Feature
		wantOK    bool
		wantValue bool
	}{
		{FeatureBPFLSM, true, true},
		{FeatureBTF, true, true},
		{FeatureIMA, true, false},
		{FeatureKprobe, true, true},
		{FeatureKprobeMulti, true, true},
		{FeatureFentry, true, true},
		{FeatureTracepoint, true, true},
		{FeatureCapBPF, true, true},
		{FeatureCapSysAdmin, true, true},
		{FeatureCapPerfmon, true, false},
		{FeatureJITEnabled, true, true},
		{FeatureJITHardened, true, false},
		{FeatureBPFSyscall, true, true},
		{FeaturePerfEventOpen, true, true},
		{FeatureSleepableBPF, true, true},
		{FeatureTraceFS, true, true},
		{FeatureBPFFS, true, false},
		{FeatureInitUserNS, true, false},
		{FeatureUnprivilegedBPFDisabled, true, true},
		{FeatureBPFStatsEnabled, true, false},
		{Feature(999), false, false},
	}

	for _, tt := range tests {
		t.Run(tt.feature.String(), func(t *testing.T) {
			result, ok := sf.Result(tt.feature)
			if ok != tt.wantOK {
				t.Errorf("Result() ok = %v, want %v", ok, tt.wantOK)
			}
			if result.Supported != tt.wantValue {
				t.Errorf("Result() Supported = %v, want %v", result.Supported, tt.wantValue)
			}
		})
	}
}

func TestResult_BPFLSMComposite(t *testing.T) {
	t.Run("both supported", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: true},
			BPFLSMEnabled:  ProbeResult{Supported: true},
		}
		result, ok := sf.Result(FeatureBPFLSM)
		if !ok || !result.Supported {
			t.Error("expected Supported=true when both LSM program type and sysfs pass")
		}
	})

	t.Run("program type fails with error", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: false, Error: unix.EPERM},
			BPFLSMEnabled:  ProbeResult{Supported: true},
		}
		result, ok := sf.Result(FeatureBPFLSM)
		if !ok {
			t.Fatal("expected known=true")
		}
		if result.Supported {
			t.Error("expected Supported=false when LSM program type probe fails")
		}
		if result.Error != unix.EPERM {
			t.Errorf("expected Error=EPERM, got %v", result.Error)
		}
	})

	t.Run("program type not supported", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: false},
			BPFLSMEnabled:  ProbeResult{Supported: true},
		}
		result, ok := sf.Result(FeatureBPFLSM)
		if !ok {
			t.Fatal("expected known=true")
		}
		if result.Supported {
			t.Error("expected Supported=false when kernel doesn't support LSM programs")
		}
	})

	t.Run("program type ok but sysfs fails", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: true},
			BPFLSMEnabled:  ProbeResult{Supported: false},
		}
		result, ok := sf.Result(FeatureBPFLSM)
		if !ok {
			t.Fatal("expected known=true")
		}
		if result.Supported {
			t.Error("expected Supported=false when 'bpf' not in LSM list")
		}
	})
}

func TestSystemFeatures_Diagnose(t *testing.T) {
	t.Run("BPF LSM not in config", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: true},
			KernelConfig:   NewKernelConfig(map[string]ConfigValue{}),
		}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "CONFIG_BPF_LSM not set; rebuild kernel with CONFIG_BPF_LSM=y" {
			t.Errorf("Diagnose(FeatureBPFLSM) = %q", got)
		}
	})

	t.Run("BPF LSM probe error has deterministic remediation", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: true},
			BPFLSMEnabled:  ProbeResult{Error: errors.New("permission denied")},
		}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "unable to read active LSM list (/sys/kernel/security/lsm); ensure securityfs is mounted and readable" {
			t.Errorf("Diagnose(FeatureBPFLSM) = %q", got)
		}
	})

	t.Run("BPF LSM compiled but not in boot params", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: true},
			BPFLSMEnabled:  ProbeResult{Supported: false},
			KernelConfig:   NewKernelConfig(map[string]ConfigValue{"BPF_LSM": ConfigBuiltin}),
		}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "CONFIG_BPF_LSM=y but 'bpf' not in active LSM list; add lsm=...,bpf to kernel boot params" {
			t.Errorf("Diagnose(FeatureBPFLSM) = %q", got)
		}
	})

	t.Run("BPF LSM program type probe error (EPERM)", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: false, Error: unix.EPERM},
		}
		got := sf.Diagnose(FeatureBPFLSM)
		want := "cannot probe LSM program type: operation not permitted; run as root or add CAP_BPF/CAP_SYS_ADMIN"
		if got != want {
			t.Errorf("Diagnose(FeatureBPFLSM) = %q, want %q", got, want)
		}
	})

	t.Run("BPF LSM program type not supported", func(t *testing.T) {
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: false},
			BPFLSMEnabled:  ProbeResult{Supported: true}, // sysfs says yes, but kernel can't load LSM
		}
		got := sf.Diagnose(FeatureBPFLSM)
		want := "LSM program type not supported; use a kernel with BPF LSM support (CONFIG_BPF_LSM=y)"
		if got != want {
			t.Errorf("Diagnose(FeatureBPFLSM) = %q, want %q", got, want)
		}
	})

	t.Run("BTF not in config", func(t *testing.T) {
		sf := &SystemFeatures{
			KernelConfig: NewKernelConfig(map[string]ConfigValue{}),
		}
		got := sf.Diagnose(FeatureBTF)
		if got != "CONFIG_DEBUG_INFO_BTF not set; rebuild kernel with CONFIG_DEBUG_INFO_BTF=y" {
			t.Errorf("Diagnose(FeatureBTF) = %q", got)
		}
	})

	t.Run("kprobe.multi not in config", func(t *testing.T) {
		sf := &SystemFeatures{
			KernelConfig: NewKernelConfig(map[string]ConfigValue{}),
		}
		got := sf.Diagnose(FeatureKprobeMulti)
		if got != "CONFIG_FPROBE not set; requires kernel 5.18+ with CONFIG_FPROBE=y" {
			t.Errorf("Diagnose(FeatureKprobeMulti) = %q", got)
		}
	})

	t.Run("program-type diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureKprobe); got != "kprobe program type not supported; use a kernel with BPF kprobe support or switch to a supported attach type" {
			t.Errorf("Diagnose(FeatureKprobe) = %q", got)
		}
		if got := sf.Diagnose(FeatureFentry); got != "fentry/fexit program type not supported; use a kernel with BPF trampoline support (and BTF) or switch attach strategy" {
			t.Errorf("Diagnose(FeatureFentry) = %q", got)
		}
		if got := sf.Diagnose(FeatureTracepoint); got != "tracepoint program type not supported; ensure perf events are enabled and use a kernel with tracepoint BPF support" {
			t.Errorf("Diagnose(FeatureTracepoint) = %q", got)
		}
	})

	t.Run("IMA not in config", func(t *testing.T) {
		sf := &SystemFeatures{
			KernelConfig: NewKernelConfig(map[string]ConfigValue{}),
		}
		got := sf.Diagnose(FeatureIMA)
		if got != "CONFIG_IMA not set; rebuild kernel with CONFIG_IMA=y" {
			t.Errorf("Diagnose(FeatureIMA) = %q", got)
		}
	})

	t.Run("IMA probe error has deterministic remediation", func(t *testing.T) {
		sf := &SystemFeatures{
			IMAEnabled: ProbeResult{Error: errors.New("permission denied")},
		}
		got := sf.Diagnose(FeatureIMA)
		if got != "unable to read active LSM list (/sys/kernel/security/lsm); ensure securityfs is mounted and readable to verify IMA state" {
			t.Errorf("Diagnose(FeatureIMA) = %q", got)
		}
	})

	t.Run("capability diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureCapBPF); got != "missing CAP_BPF; run with CAP_BPF or as root" {
			t.Errorf("Diagnose(FeatureCapBPF) = %q", got)
		}
		if got := sf.Diagnose(FeatureCapSysAdmin); got != "missing CAP_SYS_ADMIN; run as root or add CAP_SYS_ADMIN" {
			t.Errorf("Diagnose(FeatureCapSysAdmin) = %q", got)
		}
		if got := sf.Diagnose(FeatureCapPerfmon); got != "missing CAP_PERFMON; run with CAP_PERFMON or as root" {
			t.Errorf("Diagnose(FeatureCapPerfmon) = %q", got)
		}
	})

	t.Run("JIT diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureJITEnabled); got != "BPF JIT disabled; set /proc/sys/net/core/bpf_jit_enable to 1" {
			t.Errorf("Diagnose(FeatureJITEnabled) = %q", got)
		}
		if got := sf.Diagnose(FeatureJITHardened); got != "BPF JIT hardening disabled; set /proc/sys/net/core/bpf_jit_harden to 1 or 2" {
			t.Errorf("Diagnose(FeatureJITHardened) = %q", got)
		}
	})

	t.Run("syscall diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureBPFSyscall); got != "bpf() syscall not available; kernel too old or CONFIG_BPF not enabled" {
			t.Errorf("Diagnose(FeatureBPFSyscall) = %q", got)
		}
		if got := sf.Diagnose(FeaturePerfEventOpen); got != "perf_event_open() syscall not available; kernel too old or CONFIG_PERF_EVENTS not enabled" {
			t.Errorf("Diagnose(FeaturePerfEventOpen) = %q", got)
		}
	})

	t.Run("sleepable BPF with non-preemptible kernel", func(t *testing.T) {
		sf := &SystemFeatures{
			KernelConfig: NewKernelConfig(map[string]ConfigValue{"PREEMPT_NONE": ConfigBuiltin}),
		}
		got := sf.Diagnose(FeatureSleepableBPF)
		if got != "kernel preemption model is none; sleepable BPF (BPF_F_SLEEPABLE) requires CONFIG_PREEMPT or CONFIG_PREEMPT_DYNAMIC" {
			t.Errorf("Diagnose(FeatureSleepableBPF) = %q", got)
		}
	})

	t.Run("sleepable BPF without kernel config", func(t *testing.T) {
		sf := &SystemFeatures{}
		got := sf.Diagnose(FeatureSleepableBPF)
		if got != "cannot determine preemption model; kernel config not available" {
			t.Errorf("Diagnose(FeatureSleepableBPF) = %q", got)
		}
	})

	t.Run("filesystem diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureTraceFS); got != "tracefs not mounted; mount tracefs at /sys/kernel/tracing (or /sys/kernel/debug/tracing on older kernels)" {
			t.Errorf("Diagnose(FeatureTraceFS) = %q", got)
		}
		if got := sf.Diagnose(FeatureBPFFS); got != "bpffs not mounted; mount bpffs at /sys/fs/bpf" {
			t.Errorf("Diagnose(FeatureBPFFS) = %q", got)
		}
	})

	t.Run("namespace diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureInitUserNS); got != "process not in initial user namespace; run in host user namespace or adjust container runtime settings" {
			t.Errorf("Diagnose(FeatureInitUserNS) = %q", got)
		}
	})

	t.Run("unprivileged bpf diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureUnprivilegedBPFDisabled); got != "unprivileged BPF is enabled; set /proc/sys/kernel/unprivileged_bpf_disabled to 1 or 2" {
			t.Errorf("Diagnose(FeatureUnprivilegedBPFDisabled) = %q", got)
		}
	})

	t.Run("bpf stats diagnostics", func(t *testing.T) {
		sf := &SystemFeatures{}
		if got := sf.Diagnose(FeatureBPFStatsEnabled); got != "BPF runtime stats are disabled; set /proc/sys/kernel/bpf_stats_enabled to 1" {
			t.Errorf("Diagnose(FeatureBPFStatsEnabled) = %q", got)
		}
	})

	t.Run("no kernel config fallback", func(t *testing.T) {
		// With zero-value SystemFeatures, LSMProgramType is {Supported: false},
		// so Diagnose reports the program type as the blocker.
		sf := &SystemFeatures{}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "LSM program type not supported; use a kernel with BPF LSM support (CONFIG_BPF_LSM=y)" {
			t.Errorf("Diagnose(FeatureBPFLSM) without config = %q", got)
		}
	})

	t.Run("no kernel config fallback with LSM program type supported", func(t *testing.T) {
		// LSM program type works but no kernel config and sysfs check failed.
		sf := &SystemFeatures{
			LSMProgramType: ProbeResult{Supported: true},
		}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "not supported" {
			t.Errorf("Diagnose(FeatureBPFLSM) = %q, want 'not supported'", got)
		}
	})
}

func TestProbeOptionsFor(t *testing.T) {
	t.Run("security features", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureBPFLSM, FeatureIMA})
		// Should include security subsystems.
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.securitySubsystems {
			t.Error("expected securitySubsystems=true for BPF LSM + IMA")
		}
	})

	t.Run("kprobe.multi needs kernel config", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureKprobeMulti})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.kernelConfig {
			t.Error("expected kernelConfig=true for kprobe.multi")
		}
		if len(cfg.programTypes) == 0 {
			t.Error("expected programTypes to include Kprobe")
		}
	})

	t.Run("capabilities", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureCapBPF})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.capabilities {
			t.Error("expected capabilities=true for CAP_BPF")
		}
	})

	t.Run("JIT features", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureJITEnabled, FeatureJITHardened})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.jit {
			t.Error("expected jit=true for JIT features")
		}
	})

	t.Run("syscall features", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureBPFSyscall, FeaturePerfEventOpen})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.syscalls {
			t.Error("expected syscalls=true for syscall features")
		}
	})

	t.Run("sleepable BPF needs kernel config", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureSleepableBPF})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.kernelConfig {
			t.Error("expected kernelConfig=true for sleepable BPF")
		}
	})

	t.Run("filesystem features", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureTraceFS, FeatureBPFFS})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.filesystems {
			t.Error("expected filesystems=true for filesystem features")
		}
	})

	t.Run("namespace features", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureInitUserNS})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.namespaces {
			t.Error("expected namespaces=true for namespace features")
		}
	})

	t.Run("unprivileged bpf disabled needs capabilities", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureUnprivilegedBPFDisabled})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.capabilities {
			t.Error("expected capabilities=true for unprivileged bpf feature")
		}
	})

	t.Run("bpf stats enabled needs capabilities", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureBPFStatsEnabled})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.capabilities {
			t.Error("expected capabilities=true for bpf stats feature")
		}
	})

	t.Run("BPF LSM includes LSM program type", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureBPFLSM})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.securitySubsystems {
			t.Error("expected securitySubsystems=true for FeatureBPFLSM")
		}
		hasLSM := false
		for _, pt := range cfg.programTypes {
			if pt == ebpf.LSM {
				hasLSM = true
				break
			}
		}
		if !hasLSM {
			t.Error("expected programTypes to include ebpf.LSM for FeatureBPFLSM")
		}
	})

	t.Run("IMA alone sets security but no program types", func(t *testing.T) {
		opts := probeOptionsFor([]Feature{FeatureIMA})
		cfg := &probeConfig{}
		for _, opt := range opts {
			opt(cfg)
		}
		if !cfg.securitySubsystems {
			t.Error("expected securitySubsystems=true for FeatureIMA")
		}
		if len(cfg.programTypes) != 0 {
			t.Errorf("expected no programTypes for FeatureIMA, got %v", cfg.programTypes)
		}
	})

	t.Run("empty", func(t *testing.T) {
		opts := probeOptionsFor(nil)
		if len(opts) != 0 {
			t.Errorf("expected 0 options for nil, got %d", len(opts))
		}
	})
}

func TestNormalizeRequirements(t *testing.T) {
	rs := normalizeRequirements([]Requirement{
		FeatureBTF,
		FeatureGroup{
			FeatureKprobe,
			RequireProgramType(ebpf.XDP),
			RequireMapType(ebpf.Hash),
			RequireProgramHelper(ebpf.Kprobe, asm.FnGetCurrentPidTgid),
		},
		FeatureGroup{
			FeatureBTF, // duplicate
			FeatureCapBPF,
		},
		RequireProgramType(ebpf.XDP),                               // duplicate
		RequireMapType(ebpf.Hash),                                  // duplicate
		RequireProgramHelper(ebpf.Kprobe, asm.FnGetCurrentPidTgid), // duplicate
	})

	if !reflect.DeepEqual(rs.features, []Feature{
		FeatureBTF,
		FeatureKprobe,
		FeatureCapBPF,
	}) {
		t.Fatalf("features = %#v", rs.features)
	}

	if !reflect.DeepEqual(rs.programTypes, []ebpf.ProgramType{
		ebpf.XDP,
	}) {
		t.Fatalf("programTypes = %#v", rs.programTypes)
	}

	if !reflect.DeepEqual(rs.mapTypes, []ebpf.MapType{
		ebpf.Hash,
	}) {
		t.Fatalf("mapTypes = %#v", rs.mapTypes)
	}

	if !reflect.DeepEqual(rs.programHelpers, []ProgramHelperRequirement{
		{
			ProgramType: ebpf.Kprobe,
			Helper:      asm.FnGetCurrentPidTgid,
		},
	}) {
		t.Fatalf("programHelpers = %#v", rs.programHelpers)
	}
}

func TestParameterizedRequirementReasonHelpers(t *testing.T) {
	t.Run("program type reason classification", func(t *testing.T) {
		pt := ebpf.XDP

		if got := reasonForProgramTypeError(pt, ebpf.ErrNotSupported); got != "program type XDP is unavailable on this kernel; use a kernel/workload combination that supports it" {
			t.Fatalf("reasonForProgramTypeError(not-supported) = %q", got)
		}
		if got := reasonForProgramTypeError(pt, unix.EPERM); got != "cannot probe program type XDP due to insufficient privileges; run as root or add CAP_BPF/CAP_SYS_ADMIN" {
			t.Fatalf("reasonForProgramTypeError(EPERM) = %q", got)
		}
		if got := reasonForProgramTypeError(pt, errors.New("boom")); got != "unable to validate program type XDP support; verify kernel BPF support and required privileges (CAP_BPF/CAP_SYS_ADMIN)" {
			t.Fatalf("reasonForProgramTypeError(default) = %q", got)
		}
	})

	t.Run("map type reason classification", func(t *testing.T) {
		mt := ebpf.Hash

		if got := reasonForMapTypeError(mt, ebpf.ErrNotSupported); got != "map type Hash is unavailable on this kernel; use a supported map type or a newer kernel" {
			t.Fatalf("reasonForMapTypeError(not-supported) = %q", got)
		}
		if got := reasonForMapTypeError(mt, unix.EACCES); got != "cannot probe map type Hash due to insufficient privileges; run as root or add CAP_BPF/CAP_SYS_ADMIN" {
			t.Fatalf("reasonForMapTypeError(EACCES) = %q", got)
		}
		if got := reasonForMapTypeError(mt, errors.New("boom")); got != "unable to validate map type Hash support; verify kernel BPF support and required privileges (CAP_BPF/CAP_SYS_ADMIN)" {
			t.Fatalf("reasonForMapTypeError(default) = %q", got)
		}
	})

	t.Run("program helper reason classification", func(t *testing.T) {
		req := ProgramHelperRequirement{
			ProgramType: ebpf.XDP,
			Helper:      asm.FnMapLookupElem,
		}

		if got := reasonForProgramHelperError(req, ebpf.ErrNotSupported); got != "helper FnMapLookupElem is unavailable for program type XDP; choose a compatible helper/program combination or newer kernel" {
			t.Fatalf("reasonForProgramHelperError(not-supported) = %q", got)
		}
		if got := reasonForProgramHelperError(req, unix.EPERM); got != "cannot probe helper FnMapLookupElem for program type XDP due to insufficient privileges; run as root or add CAP_BPF/CAP_SYS_ADMIN" {
			t.Fatalf("reasonForProgramHelperError(EPERM) = %q", got)
		}
		if got := reasonForProgramHelperError(req, errors.New("boom")); got != "unable to validate helper FnMapLookupElem for program type XDP; verify kernel support and required privileges (CAP_BPF/CAP_SYS_ADMIN)" {
			t.Fatalf("reasonForProgramHelperError(default) = %q", got)
		}
	})
}

func TestCheck_WithFeatureGroup(t *testing.T) {
	err := Check(FeatureGroup{Feature(999)})
	if err == nil {
		t.Fatal("expected error")
	}

	var fe *FeatureError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FeatureError, got %T", err)
	}
	if fe.Feature != "Feature(999)" {
		t.Fatalf("FeatureError.Feature = %q", fe.Feature)
	}
	if fe.Reason != "unknown feature" {
		t.Fatalf("FeatureError.Reason = %q", fe.Reason)
	}
}
