//go:build linux

package kfeatures

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// withFakeStatfs swaps the package-level statfs implementation for the
// duration of t and restores the original on cleanup.
func withFakeStatfs(t *testing.T, fake func(path string, st *unix.Statfs_t) error) {
	t.Helper()
	prev := statfs
	statfs = fake
	t.Cleanup(func() { statfs = prev })
}

// fakeStatfsTable returns a statfs implementation that serves results from
// a path → (magic, error) table. Paths absent from the table return ENOENT.
func fakeStatfsTable(table map[string]struct {
	magic uint32
	err   error
}) func(string, *unix.Statfs_t) error {
	return func(path string, st *unix.Statfs_t) error {
		entry, ok := table[path]
		if !ok {
			return unix.ENOENT
		}
		if entry.err != nil {
			return entry.err
		}
		// Statfs_t.Type is int64 on 64-bit architectures and int32 on
		// 32-bit ones; setStatfsType handles both via build-tagged files.
		setStatfsType(st, entry.magic)
		return nil
	}
}

func TestCheckMount(t *testing.T) {
	const (
		path = "/some/mount"
		want = unix.BPF_FS_MAGIC
	)

	t.Run("matching magic returns nil", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			path: {magic: want},
		}))
		if err := checkMount(path, want); err != nil {
			t.Fatalf("checkMount() = %v, want nil", err)
		}
	})

	t.Run("magic mismatch returns descriptive error", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			path: {magic: unix.TMPFS_MAGIC},
		}))
		err := checkMount(path, want)
		if err == nil {
			t.Fatal("checkMount() = nil, want error")
		}
		msg := err.Error()
		for _, want := range []string{path, "not mounted with expected filesystem"} {
			if !strings.Contains(msg, want) {
				t.Errorf("error %q missing %q", msg, want)
			}
		}
	})

	t.Run("missing path returns not-found error", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{}))
		err := checkMount(path, want)
		if err == nil {
			t.Fatal("checkMount() = nil, want error")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error %q should report not found", err.Error())
		}
	})

	t.Run("syscall errno is wrapped", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			path: {err: unix.EACCES},
		}))
		err := checkMount(path, want)
		if err == nil {
			t.Fatal("checkMount() = nil, want error")
		}
		if !errors.Is(err, unix.EACCES) {
			t.Errorf("checkMount() error chain should contain EACCES, got %v", err)
		}
		if !strings.Contains(err.Error(), "statfs") {
			t.Errorf("error %q should mention statfs", err.Error())
		}
	})
}

func TestProbeFilesystemMounted(t *testing.T) {
	t.Run("mounted with expected magic", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			"/sys/fs/bpf": {magic: unix.BPF_FS_MAGIC},
		}))
		got := probeFilesystemMounted("/sys/fs/bpf", unix.BPF_FS_MAGIC)
		if !got.Supported {
			t.Fatalf("Supported = false (err=%v), want true", got.Error)
		}
		if got.Error != nil {
			t.Errorf("Error = %v, want nil", got.Error)
		}
	})

	t.Run("directory exists but wrong filesystem", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			"/sys/fs/bpf": {magic: unix.SYSFS_MAGIC},
		}))
		got := probeFilesystemMounted("/sys/fs/bpf", unix.BPF_FS_MAGIC)
		if got.Supported {
			t.Error("Supported = true, want false (wrong FS magic)")
		}
		if got.Error == nil {
			t.Error("Error = nil, want descriptive error")
		}
	})

	t.Run("path missing", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(nil))
		got := probeFilesystemMounted("/missing", unix.BPF_FS_MAGIC)
		if got.Supported {
			t.Error("Supported = true, want false")
		}
	})
}

func TestProbeFilesystemMountedAny(t *testing.T) {
	primary := mountCandidate{path: "/sys/kernel/tracing", magic: unix.TRACEFS_MAGIC}
	fallback := mountCandidate{path: "/sys/kernel/debug/tracing", magic: unix.TRACEFS_MAGIC}

	t.Run("primary mounted", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			primary.path: {magic: unix.TRACEFS_MAGIC},
		}))
		got := probeFilesystemMountedAny(primary, fallback)
		if !got.Supported {
			t.Errorf("Supported = false (err=%v), want true", got.Error)
		}
	})

	t.Run("fallback mounted", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			fallback.path: {magic: unix.TRACEFS_MAGIC},
		}))
		got := probeFilesystemMountedAny(primary, fallback)
		if !got.Supported {
			t.Errorf("Supported = false (err=%v), want true", got.Error)
		}
	})

	t.Run("neither mounted", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(nil))
		got := probeFilesystemMountedAny(primary, fallback)
		if got.Supported {
			t.Error("Supported = true, want false")
		}
		if got.Error == nil {
			t.Error("Error = nil, want last attempt's error")
		}
	})

	t.Run("magic mismatch on both", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			primary.path:  {magic: unix.SYSFS_MAGIC},
			fallback.path: {magic: unix.SYSFS_MAGIC},
		}))
		got := probeFilesystemMountedAny(primary, fallback)
		if got.Supported {
			t.Error("Supported = true, want false")
		}
		if got.Error == nil || !strings.Contains(got.Error.Error(), "not mounted") {
			t.Errorf("Error = %v, want magic-mismatch message", got.Error)
		}
	})
}
