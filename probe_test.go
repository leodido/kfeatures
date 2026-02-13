//go:build linux

package kfeatures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadActiveLSMsFrom(t *testing.T) {
	t.Run("standard LSM list", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lsm")
		if err := os.WriteFile(path, []byte("lockdown,capability,yama,apparmor,bpf\n"), 0644); err != nil {
			t.Fatal(err)
		}

		lsms, err := readActiveLSMsFrom(path)
		if err != nil {
			t.Fatalf("readActiveLSMsFrom() error = %v", err)
		}

		expected := []string{"lockdown", "capability", "yama", "apparmor", "bpf"}
		if len(lsms) != len(expected) {
			t.Fatalf("got %d LSMs, want %d", len(lsms), len(expected))
		}
		for i, got := range lsms {
			if got != expected[i] {
				t.Errorf("LSM[%d] = %q, want %q", i, got, expected[i])
			}
		}
	})

	t.Run("empty file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lsm")
		if err := os.WriteFile(path, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}

		lsms, err := readActiveLSMsFrom(path)
		if err != nil {
			t.Fatalf("readActiveLSMsFrom() error = %v", err)
		}
		if lsms != nil {
			t.Errorf("expected nil for empty file, got %v", lsms)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := readActiveLSMsFrom("/nonexistent/path")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("with trailing whitespace", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lsm")
		if err := os.WriteFile(path, []byte("  lockdown,bpf  \n"), 0644); err != nil {
			t.Fatal(err)
		}

		lsms, err := readActiveLSMsFrom(path)
		if err != nil {
			t.Fatalf("readActiveLSMsFrom() error = %v", err)
		}
		if len(lsms) != 2 {
			t.Fatalf("got %d LSMs, want 2", len(lsms))
		}
	})
}

func TestProbeWith_WithLSMPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lsm")
	if err := os.WriteFile(path, []byte("lockdown,capability,bpf,ima\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sf, err := ProbeWith(
		WithSecuritySubsystems(),
		WithLSMPath(path),
	)
	if err != nil {
		t.Fatalf("ProbeWith() error = %v", err)
	}

	if !sf.BPFLSMEnabled.Supported {
		t.Error("BPFLSMEnabled should be true when 'bpf' is in LSM list")
	}
	if !sf.IMAEnabled.Supported {
		t.Error("IMAEnabled should be true when 'ima' is in LSM list")
	}
	if len(sf.ActiveLSMs) != 4 {
		t.Errorf("ActiveLSMs = %v, want 4 entries", sf.ActiveLSMs)
	}
}

func TestProbeWith_LSMNotInList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lsm")
	if err := os.WriteFile(path, []byte("lockdown,capability,yama\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sf, err := ProbeWith(
		WithSecuritySubsystems(),
		WithLSMPath(path),
	)
	if err != nil {
		t.Fatalf("ProbeWith() error = %v", err)
	}

	if sf.BPFLSMEnabled.Supported {
		t.Error("BPFLSMEnabled should be false when 'bpf' is not in LSM list")
	}
	if sf.IMAEnabled.Supported {
		t.Error("IMAEnabled should be false when 'ima' is not in LSM list")
	}
}

func TestProbeWith_NoOptions(t *testing.T) {
	sf, err := ProbeWith()
	if err != nil {
		t.Fatalf("ProbeWith() error = %v", err)
	}

	// BTF and kernel version are always probed.
	if sf.KernelVersion == "" {
		t.Error("KernelVersion should always be populated")
	}
}

func TestProbeWith_WithAll(t *testing.T) {
	cfg := &probeConfig{}
	WithAll()(cfg)

	if len(cfg.programTypes) == 0 {
		t.Error("WithAll should set program types")
	}
	if !cfg.securitySubsystems {
		t.Error("WithAll should enable security subsystems")
	}
	if !cfg.kernelConfig {
		t.Error("WithAll should enable kernel config")
	}
	if !cfg.capabilities {
		t.Error("WithAll should enable capabilities")
	}
	if !cfg.jit {
		t.Error("WithAll should enable JIT")
	}
	if !cfg.filesystems {
		t.Error("WithAll should enable filesystems")
	}
}

func TestProbeFilesystemMount(t *testing.T) {
	t.Run("existing directory", func(t *testing.T) {
		dir := t.TempDir()
		result := probeFilesystemMount(dir)
		if !result.Supported {
			t.Error("probeFilesystemMount should return Supported=true for existing directory")
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		result := probeFilesystemMount("/nonexistent/path/that/should/not/exist")
		if result.Supported {
			t.Error("probeFilesystemMount should return Supported=false for nonexistent path")
		}
	})

	t.Run("fallback to second path", func(t *testing.T) {
		dir := t.TempDir()
		result := probeFilesystemMount("/nonexistent/path", dir)
		if !result.Supported {
			t.Error("probeFilesystemMount should return Supported=true when fallback path exists")
		}
	})

	t.Run("file not directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		result := probeFilesystemMount(path)
		if result.Supported {
			t.Error("probeFilesystemMount should return Supported=false for regular file")
		}
	})
}

func TestCacheReset(t *testing.T) {
	ResetCache()

	// After reset, next Probe() should re-probe.
	// We just verify the function doesn't panic.
	ResetCache()
}

func TestSystemFeatures_String(t *testing.T) {
	sf := &SystemFeatures{
		KernelVersion:  "6.1.0-test",
		BPFSyscall:     ProbeResult{Supported: true},
		PerfEventOpen:  ProbeResult{Supported: true},
		LSMProgramType: ProbeResult{Supported: true},
		Kprobe:         ProbeResult{Supported: true},
		KprobeMulti:    ProbeResult{Supported: true},
		Tracepoint:     ProbeResult{Supported: true},
		Fentry:         ProbeResult{Supported: true},
		BTF:            ProbeResult{Supported: true},
		BPFLSMEnabled:  ProbeResult{Supported: true},
		IMAEnabled:     ProbeResult{Supported: false},
		IMADirectory:   ProbeResult{Supported: true},
		HasCapBPF:      ProbeResult{Supported: true},
		HasCapSysAdmin: ProbeResult{Supported: true},
		HasCapPerfmon:  ProbeResult{Supported: false},
		Tracefs:        ProbeResult{Supported: true},
		Debugfs:        ProbeResult{Supported: true},
		Securityfs:     ProbeResult{Supported: true},
		BPFfs:          ProbeResult{Supported: false},
		JITEnabled:     ProbeResult{Supported: true},
		JITHardened:    ProbeResult{Supported: false},
		JITKallsyms:    ProbeResult{Supported: true},
		JITLimit:        268435456,
		ActiveLSMs:     []string{"lockdown", "bpf"},
		KernelConfig: NewKernelConfig(map[string]ConfigValue{
			"BPF_LSM":        ConfigBuiltin,
			"IMA":            ConfigBuiltin,
			"DEBUG_INFO_BTF": ConfigBuiltin,
			"FPROBE":         ConfigBuiltin,
		}),
	}

	output := sf.String()
	if !strings.Contains(output, "6.1.0-test") {
		t.Error("String() should contain kernel version")
	}
	if !strings.Contains(output, "Syscalls:") {
		t.Error("String() should contain Syscalls section")
	}
	if !strings.Contains(output, "bpf(): yes") {
		t.Error("String() should show bpf() syscall status")
	}
	if !strings.Contains(output, "perf_event_open(): yes") {
		t.Error("String() should show perf_event_open() syscall status")
	}
	if !strings.Contains(output, "BTF: yes") {
		t.Error("String() should contain BTF status")
	}
	if !strings.Contains(output, "IMA enabled: no") {
		t.Error("String() should contain IMA status")
	}
	if !strings.Contains(output, "lockdown, bpf") {
		t.Error("String() should contain active LSMs")
	}
	if !strings.Contains(output, "CONFIG_BPF_LSM: y") {
		t.Error("String() should contain kernel config")
	}
	if !strings.Contains(output, "Filesystems:") {
		t.Error("String() should contain Filesystems section")
	}
	if !strings.Contains(output, "tracefs: yes") {
		t.Error("String() should show tracefs status")
	}
	if !strings.Contains(output, "bpffs: no") {
		t.Error("String() should show bpffs status")
	}
	if !strings.Contains(output, "JIT:") {
		t.Error("String() should contain JIT section")
	}
	if !strings.Contains(output, "Enabled: yes") {
		t.Error("String() should show JIT enabled")
	}
	if !strings.Contains(output, "Hardened: no") {
		t.Error("String() should show JIT hardened status")
	}
	if !strings.Contains(output, "268435456 bytes") {
		t.Error("String() should show JIT memory limit")
	}
}
