//go:build linux

package kfeatures

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"unsafe"

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

const bpfStatsPath = "/proc/sys/kernel/bpf_stats_enabled"

// probeBPFStats reads /proc/sys/kernel/bpf_stats_enabled.
// Supported=true means BPF runtime statistics collection is enabled.
// When enabled, the kernel collects per-program run count and run time.
func probeBPFStats() ProbeResult {
	return probeSysctlNonZero(bpfStatsPath)
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
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// Filesystem mount paths for BPF-relevant pseudo-filesystems.
const (
	tracefsPath         = "/sys/kernel/tracing"
	tracefsFallbackPath = "/sys/kernel/debug/tracing"
	debugfsPath         = "/sys/kernel/debug"
	securityfsPath      = "/sys/kernel/security"
	bpffsPath           = "/sys/fs/bpf"
)

// probeFilesystemMount checks if any of the given paths exist and are directories.
// Returns Supported=true if at least one path is a mounted directory.
func probeFilesystemMount(paths ...string) ProbeResult {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			return ProbeResult{Supported: true}
		}
	}
	return ProbeResult{Supported: false}
}

// probeBPFSyscall checks if the bpf() syscall is available.
// It issues a minimal BPF_PROG_TYPE_UNSPEC command that is guaranteed to fail
// with EINVAL (syscall exists) or ENOSYS (syscall not available).
func probeBPFSyscall() ProbeResult {
	// BPF_PROG_TYPE_UNSPEC with NULL attr and zero size.
	// On kernels with bpf() this returns EINVAL or EPERM.
	// On kernels without bpf() this returns ENOSYS.
	_, _, errno := unix.Syscall(unix.SYS_BPF, 0, 0, 0)
	if errors.Is(errno, unix.ENOSYS) {
		return ProbeResult{Supported: false}
	}
	// Any other error (EINVAL, EPERM, EFAULT) means the syscall exists.
	return ProbeResult{Supported: true}
}

// probePerfEventOpen checks if the perf_event_open() syscall is available.
// Required for kprobe/tracepoint/uprobe attachment.
// It issues a minimal call with invalid args to distinguish ENOSYS from other errors.
func probePerfEventOpen() ProbeResult {
	// perf_event_open with a zeroed perf_event_attr and invalid parameters.
	// This will fail but not with ENOSYS on kernels that support it.
	attr := unix.PerfEventAttr{}
	_, _, errno := unix.Syscall6(
		unix.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(&attr)),
		uintptr(0),    // pid: current process
		uintptr(^uint(0)), // cpu: -1 (any CPU, but combined with pid=0 this is invalid without a group)
		uintptr(^uint(0)), // group_fd: -1
		uintptr(0),    // flags
		0,
	)
	if errors.Is(errno, unix.ENOSYS) {
		return ProbeResult{Supported: false}
	}
	// EINVAL, EPERM, ENOENT, etc. all mean the syscall exists.
	return ProbeResult{Supported: true}
}

// Namespace detection.
// probeInitUserNS checks if the process is running in the initial user namespace
// by comparing the user namespace inode of /proc/self/ns/user with /proc/1/ns/user.
func probeInitUserNS() ProbeResult {
	return probeInitNS("/proc/self/ns/user", "/proc/1/ns/user")
}

// probeInitPIDNS checks if the process is running in the initial PID namespace
// by comparing /proc/self/ns/pid with /proc/1/ns/pid.
func probeInitPIDNS() ProbeResult {
	return probeInitNS("/proc/self/ns/pid", "/proc/1/ns/pid")
}

// probeInitNS compares two namespace symlinks by inode number.
// Supported=true means both resolve to the same namespace (i.e., the initial one).
func probeInitNS(selfPath, initPath string) ProbeResult {
	selfInfo, err := os.Stat(selfPath)
	if err != nil {
		return ProbeResult{Supported: false, Error: err}
	}
	initInfo, err := os.Stat(initPath)
	if err != nil {
		// Cannot read /proc/1/ns/*: likely in a container with restricted /proc.
		// Assume non-initial namespace.
		return ProbeResult{Supported: false}
	}
	return ProbeResult{Supported: os.SameFile(selfInfo, initInfo)}
}

// CPU vulnerability sysfs paths.
const (
	spectreV1Path = "/sys/devices/system/cpu/vulnerabilities/spectre_v1"
	spectreV2Path = "/sys/devices/system/cpu/vulnerabilities/spectre_v2"
)

// readVulnerabilityStatus reads a CPU vulnerability status file.
// Returns the trimmed content string, or empty if the file doesn't exist.
func readVulnerabilityStatus(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
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
