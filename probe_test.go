//go:build linux

package kfeatures

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
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
		func(c *probeConfig) { c.imaPaths = []string{filepath.Join(dir, "ima")} },
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
		func(c *probeConfig) { c.imaPaths = []string{filepath.Join(dir, "ima")} },
	)
	if err != nil {
		t.Fatalf("ProbeWith() error = %v", err)
	}

	if sf.BPFLSMEnabled.Supported {
		t.Error("BPFLSMEnabled should be false when 'bpf' is not in LSM list")
	}
	if sf.IMAEnabled.Supported {
		t.Error("IMAEnabled should be false without LSM or directory evidence")
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
	if !cfg.mitigations {
		t.Error("WithAll should enable mitigations")
	}
	if !cfg.namespaces {
		t.Error("WithAll should enable namespaces")
	}
	if !cfg.syscalls {
		t.Error("WithAll should enable syscalls")
	}
}

func TestProbeFilesystemPresent(t *testing.T) {
	t.Run("existing directory", func(t *testing.T) {
		dir := t.TempDir()
		result := probeFilesystemPresent(dir)
		if !result.Supported {
			t.Error("probeFilesystemPresent should return Supported=true for existing directory")
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		result := probeFilesystemPresent("/nonexistent/path/that/should/not/exist")
		if result.Supported {
			t.Error("probeFilesystemPresent should return Supported=false for nonexistent path")
		}
	})

	t.Run("fallback to second path", func(t *testing.T) {
		dir := t.TempDir()
		result := probeFilesystemPresent("/nonexistent/path", dir)
		if !result.Supported {
			t.Error("probeFilesystemPresent should return Supported=true when fallback path exists")
		}
	})

	t.Run("file not directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		result := probeFilesystemPresent(path)
		if result.Supported {
			t.Error("probeFilesystemPresent should return Supported=false for regular file")
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
		IMAEnabled:     ProbeResult{Supported: true},
		IMADirectory:   ProbeResult{Supported: true},
		HasCapBPF:      ProbeResult{Supported: true},
		HasCapSysAdmin: ProbeResult{Supported: true},
		HasCapPerfmon:  ProbeResult{Supported: false},
		TraceFS:        ProbeResult{Supported: true},
		DebugFS:        ProbeResult{Supported: true},
		SecurityFS:     ProbeResult{Supported: true},
		BPFFS:          ProbeResult{Supported: false},
		InInitUserNS:   ProbeResult{Supported: true},
		InInitPIDNS:    ProbeResult{Supported: false},
		JITEnabled:     ProbeResult{Supported: true},
		JITHardened:    ProbeResult{Supported: false},
		JITKallsyms:    ProbeResult{Supported: true},
		JITLimit:       268435456,
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
	if !strings.Contains(output, "IMA enabled: yes") {
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
	if !strings.Contains(output, "Namespaces:") {
		t.Error("String() should contain Namespaces section")
	}
	if !strings.Contains(output, "Initial user namespace: yes") {
		t.Error("String() should show initial user namespace status")
	}
	if !strings.Contains(output, "Initial PID namespace: no") {
		t.Error("String() should show initial PID namespace status")
	}
}

func TestProbeKprobeMulti_NilConfig(t *testing.T) {
	result := probeKprobeMulti(nil)
	// When kprobe program type itself is not supported, the function
	// returns early with Supported: false and no Error (or an error about
	// the program type). We only care about the nil-config behavior when
	// kprobe IS supported, so skip if it's not.
	if result.Error != nil && !errors.Is(result.Error, ErrNoKernelConfig) {
		t.Skipf("BPF probe failed with unexpected error, skipping: %v", result.Error)
	}
	if err := features.HaveProgramType(ebpf.Kprobe); err != nil {
		t.Skip("kprobe program type not supported on this system, skipping")
	}

	// When kernel config is unavailable, the result should indicate
	// the probe was inconclusive (not just "unsupported")
	if result.Error == nil {
		t.Error("probeKprobeMulti(nil) should set Error to indicate config unavailable, got nil")
	}
	if !errors.Is(result.Error, ErrNoKernelConfig) {
		t.Errorf("probeKprobeMulti(nil) Error = %v, want ErrNoKernelConfig", result.Error)
	}
}

func TestProbeKprobeMulti_WithConfig(t *testing.T) {
	// Skip if kprobe program type is not supported.
	if err := features.HaveProgramType(ebpf.Kprobe); err != nil {
		t.Skip("kprobe program type not supported on this system, skipping")
	}

	t.Run("CONFIG_FPROBE enabled", func(t *testing.T) {
		kc := NewKernelConfig(map[string]ConfigValue{"FPROBE": ConfigBuiltin})
		result := probeKprobeMulti(kc)
		if !result.Supported {
			t.Error("probeKprobeMulti with FPROBE enabled should return Supported=true")
		}
		if result.Error != nil {
			t.Errorf("probeKprobeMulti with FPROBE enabled should have nil Error, got %v", result.Error)
		}
	})

	t.Run("CONFIG_FPROBE not set", func(t *testing.T) {
		kc := NewKernelConfig(map[string]ConfigValue{})
		result := probeKprobeMulti(kc)
		if result.Supported {
			t.Error("probeKprobeMulti without FPROBE should return Supported=false")
		}
		if result.Error != nil {
			t.Errorf("probeKprobeMulti without FPROBE should have nil Error, got %v", result.Error)
		}
	})
}

func TestReadMeasurementCountFrom(t *testing.T) {
	t.Run("valid count", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "runtime_measurements_count")
		if err := os.WriteFile(path, []byte("42\n"), 0644); err != nil {
			t.Fatal(err)
		}

		count, err := readMeasurementCountFrom(path)
		if err != nil {
			t.Fatalf("readMeasurementCountFrom() error = %v", err)
		}
		if count != 42 {
			t.Errorf("count = %d, want 42", count)
		}
	})

	t.Run("zero count", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "runtime_measurements_count")
		if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
			t.Fatal(err)
		}

		count, err := readMeasurementCountFrom(path)
		if err != nil {
			t.Fatalf("readMeasurementCountFrom() error = %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0", count)
		}
	})

	t.Run("whitespace around number", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "runtime_measurements_count")
		if err := os.WriteFile(path, []byte("  7  \n"), 0644); err != nil {
			t.Fatal(err)
		}

		count, err := readMeasurementCountFrom(path)
		if err != nil {
			t.Fatalf("readMeasurementCountFrom() error = %v", err)
		}
		if count != 7 {
			t.Errorf("count = %d, want 7", count)
		}
	})

	t.Run("malformed content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "runtime_measurements_count")
		if err := os.WriteFile(path, []byte("not-a-number\n"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := readMeasurementCountFrom(path)
		if err == nil {
			t.Error("expected error for malformed content")
		}
	})

	t.Run("empty content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "runtime_measurements_count")
		if err := os.WriteFile(path, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := readMeasurementCountFrom(path)
		if err == nil {
			t.Error("expected error for empty content")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := readMeasurementCountFrom("/nonexistent/path")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("trailing junk rejected", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "runtime_measurements_count")
		if err := os.WriteFile(path, []byte("42abc\n"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := readMeasurementCountFrom(path)
		if err == nil {
			t.Error("expected error for trailing junk")
		}
	})
}

func TestCreateFreshTempBinary(t *testing.T) {
	t.Run("creates executable path", func(t *testing.T) {
		bin, cleanup, err := createFreshTempBinary()
		if err != nil {
			t.Fatalf("createFreshTempBinary() error = %v", err)
		}
		defer cleanup()

		info, err := os.Stat(bin)
		if err != nil {
			t.Fatalf("stat(%s) error = %v", bin, err)
		}
		if info.Mode()&0100 == 0 {
			t.Errorf("binary not executable: mode = %v", info.Mode())
		}
	})

	t.Run("cleanup removes temp directory", func(t *testing.T) {
		bin, cleanup, err := createFreshTempBinary()
		if err != nil {
			t.Fatalf("createFreshTempBinary() error = %v", err)
		}

		dir := filepath.Dir(bin)
		cleanup()

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("temp directory still exists after cleanup: %s", dir)
		}
	})
}

func TestExecTempBinary(t *testing.T) {
	t.Run("executes successfully", func(t *testing.T) {
		bin, cleanup, err := createFreshTempBinary()
		if err != nil {
			t.Fatalf("createFreshTempBinary() error = %v", err)
		}
		defer cleanup()

		if err := execTempBinary(bin); err != nil {
			t.Fatalf("execTempBinary() error = %v", err)
		}
	})

	t.Run("nonexistent path returns error", func(t *testing.T) {
		if err := execTempBinary("/nonexistent/binary"); err == nil {
			t.Error("expected error for nonexistent binary")
		}
	})
}

func TestCreateFreshTempFile(t *testing.T) {
	t.Run("creates regular file with content", func(t *testing.T) {
		path, cleanup, err := createFreshTempFile()
		if err != nil {
			t.Fatalf("createFreshTempFile() error = %v", err)
		}
		defer cleanup()

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat(%s) error = %v", path, err)
		}
		if !info.Mode().IsRegular() {
			t.Errorf("expected regular file, got mode = %v", info.Mode())
		}
		if info.Size() == 0 {
			t.Error("expected non-empty file")
		}
	})

	t.Run("cleanup removes temp directory", func(t *testing.T) {
		path, cleanup, err := createFreshTempFile()
		if err != nil {
			t.Fatalf("createFreshTempFile() error = %v", err)
		}

		dir := filepath.Dir(path)
		cleanup()

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("temp directory still exists after cleanup: %s", dir)
		}
	})
}

func TestUniqueTrailer(t *testing.T) {
	t.Run("returns non-empty content", func(t *testing.T) {
		data, err := uniqueTrailer()
		if err != nil {
			t.Fatalf("uniqueTrailer() error = %v", err)
		}
		if len(data) == 0 {
			t.Error("expected non-empty trailer")
		}
	})

	t.Run("successive calls produce different content", func(t *testing.T) {
		a, err := uniqueTrailer()
		if err != nil {
			t.Fatalf("uniqueTrailer() error = %v", err)
		}
		b, err := uniqueTrailer()
		if err != nil {
			t.Fatalf("uniqueTrailer() error = %v", err)
		}
		if string(a) == string(b) {
			t.Error("expected different trailers on successive calls")
		}
	})
}

func TestIsNonTmpfs(t *testing.T) {
	t.Run("root filesystem is non-tmpfs", func(t *testing.T) {
		if !isNonTmpfs("/") {
			t.Skip("root is tmpfs on this system")
		}
	})

	t.Run("nonexistent path returns false", func(t *testing.T) {
		if isNonTmpfs("/nonexistent/path/that/should/not/exist") {
			t.Error("expected false for nonexistent path")
		}
	})
}

func TestImaProbeTempDir(t *testing.T) {
	t.Run("creates directory on non-tmpfs when available", func(t *testing.T) {
		dir, err := imaProbeTempDir()
		if err != nil {
			t.Fatalf("imaProbeTempDir() error = %v", err)
		}
		defer os.RemoveAll(dir)

		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat(%s) error = %v", dir, err)
		}
		if !info.IsDir() {
			t.Errorf("expected directory, got mode = %v", info.Mode())
		}

		// Verify it's not on tmpfs if /var/tmp is available and non-tmpfs.
		if isNonTmpfs("/var/tmp") && !isNonTmpfs(dir) {
			t.Error("expected non-tmpfs directory when /var/tmp is available")
		}
	})
}

func TestProbeWithLegacyIMA(t *testing.T) {
	withIMASecurityFS(t)
	root := t.TempDir()
	ima := filepath.Join(root, "integrity", "ima")
	if err := os.MkdirAll(ima, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ima, "runtime_measurements_count"), []byte("42\n"), 0644); err != nil {
		t.Fatal(err)
	}
	lsm := filepath.Join(root, "lsm")
	if err := os.WriteFile(lsm, []byte("capability,integrity,bpf\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sf, err := ProbeWith(WithSecuritySubsystems(), WithLSMPath(lsm), func(c *probeConfig) { c.imaPaths = []string{filepath.Join(root, "ima"), ima} })
	if err != nil {
		t.Fatal(err)
	}
	if !sf.IMAEnabled.Supported || !sf.IMAAnyMeasurementActive.Supported {
		t.Fatalf("legacy IMA: availability=%+v measurement=%+v", sf.IMAEnabled, sf.IMAAnyMeasurementActive)
	}
	if !sf.BPFLSMEnabled.Supported {
		t.Fatal("BPF LSM lost")
	}
}

func TestIMAVisibility(t *testing.T) {
	withIMASecurityFS(t)
	for _, tc := range []struct {
		name, lsm, directory, count                              string
		available, directoryError, measurement, measurementError bool
	}{
		{"modern", "bpf,ima", "missing", "", true, false, false, true},
		{"legacy", "integrity,bpf", "directory", "7", true, false, true, false},
		{"integrity alone", "integrity", "missing", "", false, false, false, true},
		{"LSM missing", "", "directory", "7", true, false, true, false},
		{"LSM unreadable", "unreadable", "directory", "7", true, false, true, false},
		{"no activity", "integrity", "directory", "1", true, false, false, false},
		{"bad count", "integrity", "directory", "bad", true, false, false, true},
		{"missing count", "integrity", "directory", "", true, false, false, true},
		{"not a directory", "integrity", "file", "", false, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			lsm := filepath.Join(root, "lsm")
			ima := filepath.Join(root, "ima")
			if tc.lsm == "unreadable" {
				if err := os.Mkdir(lsm, 0755); err != nil {
					t.Fatal(err)
				}
			} else if tc.lsm != "" {
				if err := os.WriteFile(lsm, []byte(tc.lsm), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.directory == "directory" {
				if err := os.Mkdir(ima, 0755); err != nil {
					t.Fatal(err)
				}
			} else if tc.directory == "file" {
				if err := os.WriteFile(ima, nil, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.count != "" {
				if err := os.WriteFile(filepath.Join(ima, "runtime_measurements_count"), []byte(tc.count), 0644); err != nil {
					t.Fatal(err)
				}
			}
			sf, err := ProbeWith(WithSecuritySubsystems(), WithLSMPath(lsm), func(c *probeConfig) { c.imaPaths = []string{ima} })
			if err != nil {
				t.Fatal(err)
			}
			if sf.IMAEnabled.Supported != tc.available || (sf.IMAEnabled.Error == nil) != tc.available {
				t.Fatalf("availability=%+v", sf.IMAEnabled)
			}
			if (sf.IMADirectory.Error != nil) != tc.directoryError {
				t.Fatalf("directory=%+v", sf.IMADirectory)
			}
			if sf.IMAAnyMeasurementActive.Supported != tc.measurement || (sf.IMAAnyMeasurementActive.Error != nil) != tc.measurementError {
				t.Fatalf("measurement=%+v", sf.IMAAnyMeasurementActive)
			}
			if tc.count == "bad" && !strings.Contains(sf.IMAAnyMeasurementActive.Error.Error(), "invalid syntax") {
				t.Fatalf("parse error lost: %v", sf.IMAAnyMeasurementActive.Error)
			}
			if tc.directory == "directory" && tc.count == "" && !errors.Is(sf.IMAAnyMeasurementActive.Error, os.ErrNotExist) {
				t.Fatalf("missing count error lost: %v", sf.IMAAnyMeasurementActive.Error)
			}
			if tc.lsm == "" || tc.lsm == "unreadable" {
				if sf.ActiveLSMs != nil {
					t.Fatalf("ActiveLSMs=%v", sf.ActiveLSMs)
				}
			} else if strings.Join(sf.ActiveLSMs, ",") != tc.lsm {
				t.Fatalf("ActiveLSMs=%v", sf.ActiveLSMs)
			}
			if sf.BPFLSMEnabled.Supported != strings.Contains(tc.lsm, "bpf") {
				t.Fatalf("BPF=%+v", sf.BPFLSMEnabled)
			}
			if (sf.BPFLSMEnabled.Error != nil) != (tc.lsm == "" || tc.lsm == "unreadable") {
				t.Fatalf("BPF error=%v", sf.BPFLSMEnabled.Error)
			}
		})
	}
}

func TestIMADirectoryEvidence(t *testing.T) {
	withIMASecurityFS(t)
	root := t.TempDir()
	target := filepath.Join(root, "integrity", "ima")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "ima")
	if err := os.Symlink("integrity/ima", link); err != nil {
		t.Fatal(err)
	}
	result, path := probeIMADirectories([]string{link, target}, os.Stat)
	if !result.Supported || path != link {
		t.Fatalf("compatibility link: %+v %s", result, path)
	}
	denied := &os.PathError{Op: "stat", Path: link, Err: os.ErrPermission}
	for _, positive := range []bool{false, true} {
		stat := func(path string) (os.FileInfo, error) {
			if path == link {
				return nil, denied
			}
			if positive {
				return os.Stat(target)
			}
			return nil, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
		}
		directory, _ := probeIMADirectories([]string{link, target}, stat)
		if directory.Supported != positive || errors.Is(directory.Error, os.ErrPermission) == positive {
			t.Fatalf("directory=%+v", directory)
		}
		availability := imaAvailability([]string{"integrity"}, os.ErrPermission, directory)
		if availability.Supported != positive || errors.Is(availability.Error, os.ErrPermission) == positive {
			t.Fatalf("availability=%+v", availability)
		}
		modern := imaAvailability([]string{"ima"}, nil, directory)
		if !modern.Supported || modern.Error != nil {
			t.Fatalf("modern=%+v", modern)
		}
	}
}

func TestIMAAnyMeasurementReadSequence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		counts    []int
		failAt    int
		supported bool
	}{
		{"existing measurements", []int{42}, -1, true},
		{"unchanged boot aggregate", []int{1, 1}, -1, false},
		{"empty log", []int{0, 0}, -1, false},
		{"stimulus increase", []int{1, 2}, -1, true},
		{"initial read failure", nil, 0, false},
		{"second read failure", []int{1}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			result := probeIMAAnyMeasurementActiveWith(func() (int, error) {
				i := calls
				calls++
				if i == tc.failAt {
					return 0, os.ErrPermission
				}
				if i >= len(tc.counts) {
					t.Fatal("unexpected count read")
				}
				return tc.counts[i], nil
			})
			if result.Supported != tc.supported || errors.Is(result.Error, os.ErrPermission) != (tc.failAt >= 0) {
				t.Fatalf("result=%+v", result)
			}
			want := len(tc.counts)
			if tc.failAt >= 0 {
				want++
			}
			if calls != want {
				t.Fatalf("reads=%d want %d", calls, want)
			}
		})
	}
}

func TestIMARejectsOrdinaryDirectory(t *testing.T) {
	root := t.TempDir()
	ima := filepath.Join(root, "ima")
	if err := os.Mkdir(ima, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "ima-link")
	if err := os.Symlink("ima", link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{ima, link} {
		sf, err := ProbeWith(WithSecuritySubsystems(), WithLSMPath(filepath.Join(root, "lsm")), func(c *probeConfig) { c.imaPaths = []string{candidate} })
		if err != nil {
			t.Fatal(err)
		}
		if sf.IMAEnabled.Supported || sf.IMADirectory.Supported {
			t.Fatalf("ordinary directory accepted: IMA=%+v directory=%+v", sf.IMAEnabled, sf.IMADirectory)
		}
		if sf.IMAEnabled.Error == nil || sf.IMAAnyMeasurementActive.Error == nil {
			t.Fatal("unavailable evidence and skipped measurement must retain errors")
		}
	}
}

// withIMASecurityFS supplies kernel filesystem identity for ordinary fixture
// directories. Tests that reject placeholders use real statfs instead.
func withIMASecurityFS(t *testing.T) {
	t.Helper()
	withFakeStatfs(t, func(_ string, st *unix.Statfs_t) error {
		setStatfsType(st, unix.SECURITYFS_MAGIC)
		return nil
	})
}

func TestIMAFilesystemEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		firstMagic, secondMagic uint32
		lookupErr               error
		wantDirectory           bool
	}{
		{"securityfs", unix.SECURITYFS_MAGIC, unix.TMPFS_MAGIC, nil, true},
		{"tmpfs placeholders", unix.TMPFS_MAGIC, unix.TMPFS_MAGIC, nil, false},
		{"fallback to securityfs", unix.TMPFS_MAGIC, unix.SECURITYFS_MAGIC, nil, true},
		{"permission denied", 0, unix.TMPFS_MAGIC, unix.EACCES, false},
		{"lookup IO error", 0, unix.TMPFS_MAGIC, unix.EIO, false},
		{"disappeared during lookup", 0, unix.TMPFS_MAGIC, unix.ENOENT, false},
		{"positive overrides lookup error", 0, unix.SECURITYFS_MAGIC, unix.EACCES, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			first := filepath.Join(root, "ima")
			second := filepath.Join(root, "integrity", "ima")
			if err := os.MkdirAll(second, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(first, 0755); err != nil {
				t.Fatal(err)
			}
			withFakeStatfs(t, fakeStatfsTable(map[string]struct {
				magic uint32
				err   error
			}{
				first: {tc.firstMagic, tc.lookupErr}, second: {tc.secondMagic, nil},
			}))
			for _, modern := range []bool{false, true} {
				lsm := filepath.Join(root, "lsm")
				if modern {
					if err := os.WriteFile(lsm, []byte("bpf,ima"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				sf, err := ProbeWith(WithSecuritySubsystems(), WithLSMPath(lsm), func(c *probeConfig) { c.imaPaths = []string{first, second} })
				if err != nil {
					t.Fatal(err)
				}
				if sf.IMADirectory.Supported != tc.wantDirectory || (sf.IMADirectory.Error == nil) != tc.wantDirectory {
					t.Fatalf("directory=%+v", sf.IMADirectory)
				}
				if sf.IMAEnabled.Supported != (modern || tc.wantDirectory) {
					t.Fatalf("IMA=%+v", sf.IMAEnabled)
				}
				if modern || tc.wantDirectory {
					if sf.IMAEnabled.Error != nil {
						t.Fatalf("positive lost: %v", sf.IMAEnabled.Error)
					}
				} else if tc.lookupErr != nil && !errors.Is(sf.IMAEnabled.Error, tc.lookupErr) {
					t.Fatalf("lookup error lost: %v", sf.IMAEnabled.Error)
				}
				if !tc.wantDirectory && tc.lookupErr != nil && !errors.Is(sf.IMADirectory.Error, tc.lookupErr) {
					t.Fatalf("directory lookup error lost: %v", sf.IMADirectory.Error)
				}
			}
		})
	}
}
