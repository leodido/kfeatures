//go:build linux

package kfeatures

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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
		Tracefs:                 ProbeResult{Supported: true},
		BPFfs:                   ProbeResult{Supported: false},
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

func TestSystemFeatures_Diagnose(t *testing.T) {
	t.Run("BPF LSM not in config", func(t *testing.T) {
		sf := &SystemFeatures{
			KernelConfig: NewKernelConfig(map[string]ConfigValue{}),
		}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "CONFIG_BPF_LSM not set; rebuild kernel with CONFIG_BPF_LSM=y" {
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

	t.Run("IMA not in config", func(t *testing.T) {
		sf := &SystemFeatures{
			KernelConfig: NewKernelConfig(map[string]ConfigValue{}),
		}
		got := sf.Diagnose(FeatureIMA)
		if got != "CONFIG_IMA not set; rebuild kernel with CONFIG_IMA=y" {
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
		sf := &SystemFeatures{}
		got := sf.Diagnose(FeatureBPFLSM)
		if got != "not supported" {
			t.Errorf("Diagnose(FeatureBPFLSM) without config = %q, want 'not supported'", got)
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
