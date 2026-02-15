package kfeatures

import (
	"errors"
	"fmt"
	"testing"
)

func TestConfigValue_IsEnabled(t *testing.T) {
	tests := []struct {
		value ConfigValue
		want  bool
	}{
		{ConfigNotSet, false},
		{ConfigModule, true},
		{ConfigBuiltin, true},
	}
	for _, tt := range tests {
		if got := tt.value.IsEnabled(); got != tt.want {
			t.Errorf("ConfigValue(%d).IsEnabled() = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestConfigValue_IsBuiltin(t *testing.T) {
	tests := []struct {
		value ConfigValue
		want  bool
	}{
		{ConfigNotSet, false},
		{ConfigModule, false},
		{ConfigBuiltin, true},
	}
	for _, tt := range tests {
		if got := tt.value.IsBuiltin(); got != tt.want {
			t.Errorf("ConfigValue(%d).IsBuiltin() = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestConfigValue_String(t *testing.T) {
	tests := []struct {
		value ConfigValue
		want  string
	}{
		{ConfigNotSet, "not set"},
		{ConfigModule, "m"},
		{ConfigBuiltin, "y"},
		{ConfigValue(99), "ConfigValue(99)"},
	}
	for _, tt := range tests {
		if got := tt.value.String(); got != tt.want {
			t.Errorf("ConfigValue(%d).String() = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestKernelConfig_Get(t *testing.T) {
	kc := NewKernelConfig(map[string]ConfigValue{
		"BPF_LSM":        ConfigBuiltin,
		"IMA":            ConfigBuiltin,
		"DEBUG_INFO_BTF": ConfigBuiltin,
		"FPROBE":         ConfigBuiltin,
		"XDP_SOCKETS":    ConfigBuiltin,
	})

	if got := kc.Get("BPF_LSM"); got != ConfigBuiltin {
		t.Errorf("Get(BPF_LSM) = %v, want ConfigBuiltin", got)
	}
	if got := kc.Get("NONEXISTENT"); got != ConfigNotSet {
		t.Errorf("Get(NONEXISTENT) = %v, want ConfigNotSet", got)
	}

	// Convenience fields.
	if kc.BPFLSM != ConfigBuiltin {
		t.Errorf("BPFLSM = %v, want ConfigBuiltin", kc.BPFLSM)
	}
	if kc.IMA != ConfigBuiltin {
		t.Errorf("IMA = %v, want ConfigBuiltin", kc.IMA)
	}
	if kc.BTF != ConfigBuiltin {
		t.Errorf("BTF = %v, want ConfigBuiltin", kc.BTF)
	}
	if kc.KprobeMulti != ConfigBuiltin {
		t.Errorf("KprobeMulti = %v, want ConfigBuiltin", kc.KprobeMulti)
	}
}

func TestKernelConfig_IsSet(t *testing.T) {
	kc := NewKernelConfig(map[string]ConfigValue{
		"BPF_LSM": ConfigBuiltin,
		"NET":     ConfigModule,
	})

	if !kc.IsSet("BPF_LSM") {
		t.Error("IsSet(BPF_LSM) = false, want true")
	}
	if !kc.IsSet("NET") {
		t.Error("IsSet(NET) = false, want true")
	}
	if kc.IsSet("MISSING") {
		t.Error("IsSet(MISSING) = true, want false")
	}
}

func TestKernelConfig_Nil(t *testing.T) {
	var kc *KernelConfig
	if got := kc.Get("anything"); got != ConfigNotSet {
		t.Errorf("nil KernelConfig.Get() = %v, want ConfigNotSet", got)
	}
	if kc.IsSet("anything") {
		t.Error("nil KernelConfig.IsSet() = true, want false")
	}
}

func TestKernelConfig_Immutability(t *testing.T) {
	raw := map[string]ConfigValue{
		"BPF_LSM": ConfigBuiltin,
	}
	kc := NewKernelConfig(raw)

	// Mutate the original map.
	raw["BPF_LSM"] = ConfigNotSet
	raw["NEW_KEY"] = ConfigModule

	// KernelConfig should not be affected.
	if kc.Get("BPF_LSM") != ConfigBuiltin {
		t.Error("KernelConfig was affected by mutation of original map")
	}
	if kc.Get("NEW_KEY") != ConfigNotSet {
		t.Error("KernelConfig was affected by addition to original map")
	}
}

func TestFeature_String(t *testing.T) {
	tests := []struct {
		f    Feature
		want string
	}{
		{FeatureBPFLSM, "BPF LSM"},
		{FeatureBTF, "BTF"},
		{FeatureIMA, "IMA"},
		{FeatureKprobe, "kprobe"},
		{FeatureKprobeMulti, "kprobe.multi"},
		{FeatureFentry, "fentry"},
		{FeatureTracepoint, "tracepoint"},
		{FeatureCapBPF, "CAP_BPF"},
		{FeatureCapSysAdmin, "CAP_SYS_ADMIN"},
		{FeatureCapPerfmon, "CAP_PERFMON"},
		{FeatureJITEnabled, "BPF JIT"},
		{FeatureJITHardened, "BPF JIT hardening"},
		{FeatureBPFSyscall, "bpf() syscall"},
		{FeaturePerfEventOpen, "perf_event_open() syscall"},
		{FeatureSleepableBPF, "sleepable BPF"},
		{FeatureTracefs, "tracefs"},
		{FeatureBPFfs, "bpffs"},
		{FeatureInitUserNS, "initial user namespace"},
		{FeatureUnprivilegedBPFDisabled, "unprivileged BPF disabled"},
		{Feature(999), "Feature(999)"},
	}
	for _, tt := range tests {
		if got := tt.f.String(); got != tt.want {
			t.Errorf("Feature(%d).String() = %q, want %q", tt.f, got, tt.want)
		}
	}
}

func TestPreemptMode(t *testing.T) {
	tests := []struct {
		mode          PreemptMode
		wantStr       string
		wantSleepable bool
	}{
		{PreemptUnknown, "unknown", false},
		{PreemptNone, "none", false},
		{PreemptVoluntary, "voluntary", false},
		{PreemptFull, "full", true},
		{PreemptDynamic, "dynamic", true},
	}
	for _, tt := range tests {
		t.Run(tt.wantStr, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.wantStr {
				t.Errorf("String() = %q, want %q", got, tt.wantStr)
			}
			if got := tt.mode.SupportsSleepable(); got != tt.wantSleepable {
				t.Errorf("SupportsSleepable() = %v, want %v", got, tt.wantSleepable)
			}
		})
	}
}

func TestDerivePreemptMode(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]ConfigValue
		want PreemptMode
	}{
		{"dynamic", map[string]ConfigValue{"PREEMPT_DYNAMIC": ConfigBuiltin}, PreemptDynamic},
		{"full", map[string]ConfigValue{"PREEMPT": ConfigBuiltin}, PreemptFull},
		{"voluntary", map[string]ConfigValue{"PREEMPT_VOLUNTARY": ConfigBuiltin}, PreemptVoluntary},
		{"none", map[string]ConfigValue{"PREEMPT_NONE": ConfigBuiltin}, PreemptNone},
		{"empty", map[string]ConfigValue{}, PreemptUnknown},
		{"dynamic wins", map[string]ConfigValue{"PREEMPT_DYNAMIC": ConfigBuiltin, "PREEMPT": ConfigBuiltin}, PreemptDynamic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := NewKernelConfig(tt.raw)
			if kc.Preempt != tt.want {
				t.Errorf("Preempt = %v, want %v", kc.Preempt, tt.want)
			}
		})
	}
}

func TestFeatureError(t *testing.T) {
	t.Run("without underlying error", func(t *testing.T) {
		fe := &FeatureError{Feature: "BPF LSM", Reason: "not set"}
		want := "feature BPF LSM: not set"
		if got := fe.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
		if fe.Unwrap() != nil {
			t.Error("Unwrap() should be nil")
		}
	})

	t.Run("with underlying error", func(t *testing.T) {
		inner := errors.New("permission denied")
		fe := &FeatureError{Feature: "BTF", Reason: "probe failed", Err: inner}
		want := "feature BTF: probe failed: permission denied"
		if got := fe.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
		if !errors.Is(fe, inner) {
			t.Error("errors.Is should match underlying error")
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		fe := &FeatureError{Feature: "IMA", Reason: "not supported"}
		err := fmt.Errorf("check failed: %w", fe)

		var target *FeatureError
		if !errors.As(err, &target) {
			t.Fatal("errors.As should match FeatureError")
		}
		if target.Feature != "IMA" {
			t.Errorf("Feature = %q, want %q", target.Feature, "IMA")
		}
	})
}

func TestProbeResult(t *testing.T) {
	t.Run("supported", func(t *testing.T) {
		r := ProbeResult{Supported: true}
		if !r.Supported {
			t.Error("Supported should be true")
		}
		if r.Error != nil {
			t.Error("Error should be nil")
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		r := ProbeResult{Supported: false}
		if r.Supported {
			t.Error("Supported should be false")
		}
	})

	t.Run("error", func(t *testing.T) {
		r := ProbeResult{Supported: false, Error: errors.New("oops")}
		if r.Supported {
			t.Error("Supported should be false")
		}
		if r.Error == nil {
			t.Error("Error should not be nil")
		}
	})
}
