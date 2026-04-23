//go:build linux

package kfeatures

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheck_RequireMount(t *testing.T) {
	const path = "/test/mount"

	t.Run("matching magic passes", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			path: {magic: unix.BPF_FS_MAGIC},
		}))
		if err := Check(RequireMount(path, unix.BPF_FS_MAGIC)); err != nil {
			t.Fatalf("Check() = %v, want nil", err)
		}
	})

	t.Run("magic mismatch surfaces FeatureError", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			path: {magic: unix.TMPFS_MAGIC},
		}))
		err := Check(RequireMount(path, unix.BPF_FS_MAGIC))
		if err == nil {
			t.Fatal("Check() = nil, want FeatureError")
		}
		var fe *FeatureError
		if !errors.As(err, &fe) {
			t.Fatalf("expected *FeatureError, got %T: %v", err, err)
		}
		if !strings.Contains(fe.Feature, path) {
			t.Errorf("FeatureError.Feature = %q, want to contain %q", fe.Feature, path)
		}
		if !strings.Contains(fe.Reason, "not mounted with expected filesystem") {
			t.Errorf("FeatureError.Reason = %q, want magic-mismatch message", fe.Reason)
		}
	})

	t.Run("missing path surfaces not-found", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(nil))
		err := Check(RequireMount(path, unix.BPF_FS_MAGIC))
		if err == nil {
			t.Fatal("Check() = nil, want FeatureError")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error %q should report not found", err.Error())
		}
	})

	t.Run("syscall errno wrapped through FeatureError", func(t *testing.T) {
		withFakeStatfs(t, fakeStatfsTable(map[string]struct {
			magic uint32
			err   error
		}{
			path: {err: unix.EACCES},
		}))
		err := Check(RequireMount(path, unix.BPF_FS_MAGIC))
		if err == nil {
			t.Fatal("Check() = nil, want FeatureError")
		}
		if !errors.Is(err, unix.EACCES) {
			t.Errorf("error chain should contain EACCES, got %v", err)
		}
	})

	t.Run("dedup: identical RequireMount evaluated once", func(t *testing.T) {
		var calls int
		withFakeStatfs(t, func(p string, st *unix.Statfs_t) error {
			calls++
			setStatfsType(st, unix.BPF_FS_MAGIC)
			return nil
		})
		req := RequireMount(path, unix.BPF_FS_MAGIC)
		if err := Check(req, req, req); err != nil {
			t.Fatalf("Check() = %v, want nil", err)
		}
		if calls != 1 {
			t.Errorf("statfs called %d times, want 1 (dedup expected)", calls)
		}
	})

	t.Run("distinct path+magic pairs evaluated separately", func(t *testing.T) {
		seen := map[string]int{}
		withFakeStatfs(t, func(p string, st *unix.Statfs_t) error {
			seen[p]++
			setStatfsType(st, unix.BPF_FS_MAGIC)
			return nil
		})
		err := Check(
			RequireMount("/a", unix.BPF_FS_MAGIC),
			RequireMount("/b", unix.BPF_FS_MAGIC),
		)
		if err != nil {
			t.Fatalf("Check() = %v, want nil", err)
		}
		if seen["/a"] != 1 || seen["/b"] != 1 {
			t.Errorf("statfs call counts = %v, want /a=1 /b=1", seen)
		}
	})
}

func TestRequireMount_RejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		path string
		// Zero-value uint32 sentinel doubles as "magic == 0" trigger.
		magic uint32
		want  string
	}{
		{name: "empty path", path: "", magic: unix.BPF_FS_MAGIC, want: "path must not be empty"},
		{name: "zero magic", path: "/sys/fs/bpf", magic: 0, want: "magic must not be zero"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("RequireMount(%q, 0x%x) did not panic", tc.path, tc.magic)
				}
				msg, ok := r.(string)
				if !ok {
					t.Fatalf("panic value is not a string: %T %v", r, r)
				}
				if !strings.Contains(msg, tc.want) {
					t.Errorf("panic message %q does not contain %q", msg, tc.want)
				}
			}()
			_ = RequireMount(tc.path, tc.magic)
		})
	}
}

func TestRequirementSet_DedupMounts(t *testing.T) {
	rs := normalizeRequirements([]Requirement{
		RequireMount("/x", 1),
		RequireMount("/x", 1),
		RequireMount("/x", 2),
		RequireMount("/y", 1),
	})
	if got, want := len(rs.mounts), 3; got != want {
		t.Fatalf("len(rs.mounts) = %d, want %d (got %v)", got, want, rs.mounts)
	}
}
