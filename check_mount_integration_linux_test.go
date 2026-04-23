//go:build linux && integration

package kfeatures

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// mountTmpfs mounts a tmpfs at a t.TempDir() and registers cleanup that
// unmounts it. The test is skipped if the process lacks the privileges
// required for unix.Mount (typically root / CAP_SYS_ADMIN).
func mountTmpfs(t *testing.T) string {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root (unix.Mount needs CAP_SYS_ADMIN)")
	}

	dir := t.TempDir()
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("mount tmpfs at %s: %v (sandboxed?)", dir, err)
		}
		t.Fatalf("mount tmpfs at %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(dir, 0); err != nil {
			t.Logf("unmount %s: %v", dir, err)
		}
	})
	return dir
}

func TestRequireMountIntegration_Tmpfs(t *testing.T) {
	dir := mountTmpfs(t)

	t.Run("matching magic passes against real Statfs", func(t *testing.T) {
		if err := Check(RequireMount(dir, unix.TMPFS_MAGIC)); err != nil {
			t.Fatalf("Check(RequireMount(%q, TMPFS_MAGIC)) = %v, want nil", dir, err)
		}
	})

	t.Run("magic mismatch fails against real Statfs", func(t *testing.T) {
		err := Check(RequireMount(dir, unix.BPF_FS_MAGIC))
		if err == nil {
			t.Fatalf("Check(RequireMount(%q, BPF_FS_MAGIC)) = nil, want error", dir)
		}
		var fe *FeatureError
		if !errors.As(err, &fe) {
			t.Fatalf("expected *FeatureError, got %T: %v", err, err)
		}
		if !strings.Contains(fe.Reason, "not mounted with expected filesystem") {
			t.Errorf("FeatureError.Reason = %q, want magic-mismatch message", fe.Reason)
		}
	})
}

func TestRequireMountIntegration_MissingPath(t *testing.T) {
	// No root check: the //go:build integration tag scopes this test to the
	// dedicated CI job, and the assertion (Statfs on a nonexistent path) does
	// not require any privilege.
	err := Check(RequireMount("/nonexistent/integration/path", unix.TMPFS_MAGIC))
	if err == nil {
		t.Fatal("Check(RequireMount(missing)) = nil, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q should report not found", err.Error())
	}
}
