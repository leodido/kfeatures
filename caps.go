//go:build linux

package kfeatures

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Linux capability constants for BPF operations.
// These match the values in <linux/capability.h>.
const (
	capSysAdmin = 21 // CAP_SYS_ADMIN
	capPerfmon  = 38 // CAP_PERFMON (kernel 5.8+)
	capBPF      = 39 // CAP_BPF (kernel 5.8+)
)

// probeCapability checks if the current process has the specified capability
// in its effective capability set using prctl(PR_CAPBSET_READ).
func probeCapability(cap uintptr) ProbeResult {
	ret, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, cap, 0, 0, 0)
	if err != nil {
		return ProbeResult{Supported: false, Error: err}
	}
	return ProbeResult{Supported: ret == 1}
}

const unprivilegedBPFPath = "/proc/sys/kernel/unprivileged_bpf_disabled"

// probeUnprivilegedBPF reads /proc/sys/kernel/unprivileged_bpf_disabled.
// Supported=true means unprivileged BPF is disabled (the common/secure default).
// Values: 0=allowed, 1=disabled, 2=disabled+locked (cannot be re-enabled).
func probeUnprivilegedBPF() ProbeResult {
	data, err := os.ReadFile(unprivilegedBPFPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist: kernel too old or BPF not compiled in.
			return ProbeResult{Supported: false}
		}
		return ProbeResult{Supported: false, Error: err}
	}
	val := strings.TrimSpace(string(data))
	// "1" or "2" means unprivileged BPF is disabled.
	return ProbeResult{Supported: val == "1" || val == "2"}
}
