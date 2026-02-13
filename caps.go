//go:build linux

package kfeatures

import (
	"fmt"
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

// JIT compiler sysctl paths.
const (
	jitEnablePath   = "/proc/sys/net/core/bpf_jit_enable"
	jitHardenPath   = "/proc/sys/net/core/bpf_jit_harden"
	jitKallsymsPath = "/proc/sys/net/core/bpf_jit_kallsyms"
	jitLimitPath    = "/proc/sys/net/core/bpf_jit_limit"
)

// probeJITEnabled reads /proc/sys/net/core/bpf_jit_enable.
// Supported=true means the BPF JIT compiler is enabled.
// Values: 0=disabled, 1=enabled, 2=enabled with debugging output to kernel log.
func probeJITEnabled() ProbeResult {
	return probeSysctlNonZero(jitEnablePath)
}

// probeJITHardened reads /proc/sys/net/core/bpf_jit_harden.
// Supported=true means JIT hardening is active.
// Values: 0=disabled, 1=enabled for unprivileged users, 2=enabled for all users.
func probeJITHardened() ProbeResult {
	return probeSysctlNonZero(jitHardenPath)
}

// probeJITKallsyms reads /proc/sys/net/core/bpf_jit_kallsyms.
// Supported=true means JIT-compiled BPF programs are exposed in /proc/kallsyms.
func probeJITKallsyms() ProbeResult {
	return probeSysctlNonZero(jitKallsymsPath)
}

// probeJITLimit reads /proc/sys/net/core/bpf_jit_limit and returns the
// memory limit in bytes for JIT-compiled BPF programs.
// Returns 0 if the file doesn't exist or cannot be read.
func probeJITLimit() int64 {
	data, err := os.ReadFile(jitLimitPath)
	if err != nil {
		return 0
	}
	val := strings.TrimSpace(string(data))
	var n int64
	fmt.Sscanf(val, "%d", &n)
	return n
}

// probeSysctlNonZero reads a sysctl file and returns Supported=true
// if the value is a non-zero integer.
func probeSysctlNonZero(path string) ProbeResult {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ProbeResult{Supported: false}
		}
		return ProbeResult{Supported: false, Error: err}
	}
	val := strings.TrimSpace(string(data))
	return ProbeResult{Supported: val != "0" && val != ""}
}
