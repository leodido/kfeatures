//go:build linux

package kfeatures

import (
	"errors"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// Cache for Probe() results. Kernel features don't change at runtime,
// so we cache after the first probe to avoid repeated syscalls.
var (
	cachedFeatures *SystemFeatures
	cacheMu        sync.Mutex
	cacheErr       error
)

// probeConfig holds the configuration for a probe operation.
type probeConfig struct {
	programTypes       []ebpf.ProgramType
	securitySubsystems bool
	kernelConfig       bool
	capabilities       bool
	jit                bool
	filesystems        bool
	syscalls           bool
	lsmPath            string // custom path for LSM file (for testing)
}

// ProbeOption configures what features to probe.
type ProbeOption func(*probeConfig)

// WithProgramTypes probes the specified eBPF program types.
func WithProgramTypes(types ...ebpf.ProgramType) ProbeOption {
	return func(c *probeConfig) {
		c.programTypes = append(c.programTypes, types...)
	}
}

// WithSecuritySubsystems probes security subsystem status (LSM list, IMA).
func WithSecuritySubsystems() ProbeOption {
	return func(c *probeConfig) {
		c.securitySubsystems = true
	}
}

// WithKernelConfig parses and includes kernel configuration.
func WithKernelConfig() ProbeOption {
	return func(c *probeConfig) {
		c.kernelConfig = true
	}
}

// WithCapabilities probes process capabilities (CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON)
// and unprivileged BPF access status.
func WithCapabilities() ProbeOption {
	return func(c *probeConfig) {
		c.capabilities = true
	}
}

// WithJIT probes BPF JIT compiler status (enabled, hardening, kallsyms, memory limit).
func WithJIT() ProbeOption {
	return func(c *probeConfig) {
		c.jit = true
	}
}

// WithSyscalls probes availability of BPF-relevant syscalls (bpf(), perf_event_open).
func WithSyscalls() ProbeOption {
	return func(c *probeConfig) {
		c.syscalls = true
	}
}

// WithFilesystems probes filesystem mounts relevant to BPF operations
// (tracefs, debugfs, securityfs, bpffs).
func WithFilesystems() ProbeOption {
	return func(c *probeConfig) {
		c.filesystems = true
	}
}

// WithLSMPath sets a custom path for the LSM file.
// This is primarily for testing; production code uses the default /sys/kernel/security/lsm.
func WithLSMPath(path string) ProbeOption {
	return func(c *probeConfig) {
		c.lsmPath = path
	}
}

// WithAll enables probing of all features.
func WithAll() ProbeOption {
	return func(c *probeConfig) {
		c.programTypes = []ebpf.ProgramType{
			ebpf.LSM,
			ebpf.Kprobe,
			ebpf.Tracing, // covers fentry/fexit
			ebpf.TracePoint,
		}
		c.securitySubsystems = true
		c.kernelConfig = true
		c.capabilities = true
		c.jit = true
		c.filesystems = true
		c.syscalls = true
	}
}

// ProbeWith probes kernel features based on the provided options.
// BTF and kernel version are always probed regardless of options (both are cheap).
// If no options are provided, only BTF and kernel version are populated.
func ProbeWith(opts ...ProbeOption) (*SystemFeatures, error) {
	cfg := &probeConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	sf := &SystemFeatures{}

	// Probe kernel config first (needed for kprobe.multi check)
	var kc *KernelConfig
	if cfg.kernelConfig {
		kc, _ = readKernelConfig()
		sf.KernelConfig = kc
		// Ignore errors: kernel config is optional
	}

	// Probe syscall availability
	if cfg.syscalls {
		sf.BPFSyscall = probeBPFSyscall()
		sf.PerfEventOpen = probePerfEventOpen()
	}

	// Probe program types
	for _, pt := range cfg.programTypes {
		result := probeProgramType(pt)
		switch pt {
		case ebpf.LSM:
			sf.LSMProgramType = result
		case ebpf.Kprobe:
			sf.Kprobe = result
		case ebpf.Tracing:
			sf.Fentry = result
		case ebpf.TracePoint:
			sf.Tracepoint = result
		}
	}

	// Probe kprobe.multi separately (requires kernel config for CONFIG_FPROBE check)
	for _, pt := range cfg.programTypes {
		if pt == ebpf.Kprobe {
			sf.KprobeMulti = probeKprobeMulti(kc)
			break
		}
	}

	// Always probe BTF availability (cheap single stat, useful regardless of options)
	sf.BTF = probeBTF()

	// Always populate kernel version (cheap uname syscall, useful for diagnostics)
	sf.KernelVersion = probeKernelVersion()

	// Probe security subsystems
	if cfg.securitySubsystems {
		lsmPath := cfg.lsmPath
		if lsmPath == "" {
			lsmPath = defaultLSMPath
		}
		lsms, err := readActiveLSMsFrom(lsmPath)
		if err != nil {
			sf.BPFLSMEnabled = ProbeResult{Supported: false, Error: err}
			sf.IMAEnabled = ProbeResult{Supported: false, Error: err}
		} else {
			sf.ActiveLSMs = lsms
			sf.BPFLSMEnabled = ProbeResult{Supported: slices.Contains(lsms, "bpf")}
			// IMAEnabled: strict check, only true if "ima" is in LSM list.
			// This is required for bpf_ima_file_hash to work.
			sf.IMAEnabled = ProbeResult{Supported: slices.Contains(lsms, "ima")}
		}
		// IMADirectory: check if /sys/kernel/security/ima exists.
		// This indicates IMA is compiled in and securityfs is mounted,
		// but does not guarantee IMA is actively measuring files.
		sf.IMADirectory = probeIMADirectory()
	}

	// Probe capabilities
	if cfg.capabilities {
		sf.HasCapBPF = probeCapability(capBPF)
		sf.HasCapSysAdmin = probeCapability(capSysAdmin)
		sf.HasCapPerfmon = probeCapability(capPerfmon)
		sf.UnprivilegedBPFDisabled = probeUnprivilegedBPF()
		sf.BPFStatsEnabled = probeBPFStats()
	}

	// Probe JIT compiler status
	if cfg.jit {
		sf.JITEnabled = probeJITEnabled()
		sf.JITHardened = probeJITHardened()
		sf.JITKallsyms = probeJITKallsyms()
		sf.JITLimit = probeJITLimit()
	}

	// Probe filesystem mounts
	if cfg.filesystems {
		sf.Tracefs = probeFilesystemMount(tracefsPath, tracefsFallbackPath)
		sf.Debugfs = probeFilesystemMount(debugfsPath)
		sf.Securityfs = probeFilesystemMount(securityfsPath)
		sf.BPFfs = probeFilesystemMount(bpffsPath)
	}

	return sf, nil
}

// Probe probes all kernel features and caches the result.
// Subsequent calls return the cached result without re-probing.
// Use [ProbeNoCache] if you need fresh results.
func Probe() (*SystemFeatures, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if cachedFeatures != nil || cacheErr != nil {
		return cachedFeatures, cacheErr
	}
	cachedFeatures, cacheErr = ProbeWith(WithAll())
	return cachedFeatures, cacheErr
}

// ProbeNoCache probes all kernel features without using the cache.
// Use this when you need fresh results, e.g., after loading kernel modules.
func ProbeNoCache() (*SystemFeatures, error) {
	return ProbeWith(WithAll())
}

// ResetCache clears cached probe results, forcing the next [Probe] call to re-probe.
// This is primarily useful for testing.
func ResetCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cachedFeatures = nil
	cacheErr = nil
}

// probeProgramType checks if a BPF program type is supported.
func probeProgramType(pt ebpf.ProgramType) ProbeResult {
	err := features.HaveProgramType(pt)
	if err == nil {
		return ProbeResult{Supported: true}
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return ProbeResult{Supported: false}
	}
	return ProbeResult{Supported: false, Error: err}
}

// probeKprobeMulti checks if kprobe.multi (multi-attach kprobes) is supported.
// This requires CONFIG_FPROBE (kernel 5.18+) which is checked via kernel config.
func probeKprobeMulti(kc *KernelConfig) ProbeResult {
	// First check if basic kprobe is supported.
	if err := features.HaveProgramType(ebpf.Kprobe); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return ProbeResult{Supported: false}
		}
		return ProbeResult{Supported: false, Error: err}
	}

	// kprobe.multi requires CONFIG_FPROBE.
	if kc != nil && kc.KprobeMulti.IsEnabled() {
		return ProbeResult{Supported: true}
	}

	// Cannot confirm without kernel config.
	return ProbeResult{Supported: false}
}

const btfPath = "/sys/kernel/btf/vmlinux"

// probeBTF checks if BTF (BPF Type Format) is available for CO-RE programs.
func probeBTF() ProbeResult {
	_, err := os.Stat(btfPath)
	if err == nil {
		return ProbeResult{Supported: true}
	}
	if os.IsNotExist(err) {
		return ProbeResult{Supported: false}
	}
	return ProbeResult{Supported: false, Error: err}
}

const defaultLSMPath = "/sys/kernel/security/lsm"

// readActiveLSMsFrom reads the list of active LSMs from the specified path.
func readActiveLSMsFrom(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, nil
	}
	return strings.Split(content, ","), nil
}

// probeKernelVersion returns the kernel release string (e.g., "6.1.0-generic").
func probeKernelVersion() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uname.Release[:])
}

const imaDirectoryPath = "/sys/kernel/security/ima"

// probeIMADirectory checks if the IMA securityfs directory exists.
// This indicates IMA is compiled in and securityfs is mounted,
// but does not guarantee IMA is actively measuring files.
func probeIMADirectory() ProbeResult {
	_, err := os.Stat(imaDirectoryPath)
	if err == nil {
		return ProbeResult{Supported: true}
	}
	if os.IsNotExist(err) {
		return ProbeResult{Supported: false}
	}
	return ProbeResult{Supported: false, Error: err}
}
