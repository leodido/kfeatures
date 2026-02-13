package kfeatures

import (
	"fmt"
	"strings"
)

// String returns a human-readable summary of all probe results.
func (sf *SystemFeatures) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "Kernel: %s\n", sf.KernelVersion)
	b.WriteString("\n")

	b.WriteString("Syscalls:\n")
	writeResult(&b, "  bpf()", sf.BPFSyscall)
	writeResult(&b, "  perf_event_open()", sf.PerfEventOpen)
	b.WriteString("\n")

	b.WriteString("Program Types:\n")
	writeResult(&b, "  LSM", sf.LSMProgramType)
	writeResult(&b, "  kprobe", sf.Kprobe)
	writeResult(&b, "  kprobe.multi", sf.KprobeMulti)
	writeResult(&b, "  tracepoint", sf.Tracepoint)
	writeResult(&b, "  fentry", sf.Fentry)
	b.WriteString("\n")

	b.WriteString("Core:\n")
	writeResult(&b, "  BTF", sf.BTF)
	b.WriteString("\n")

	b.WriteString("Security Subsystems:\n")
	writeResult(&b, "  BPF LSM enabled", sf.BPFLSMEnabled)
	writeResult(&b, "  IMA enabled", sf.IMAEnabled)
	writeResult(&b, "  IMA directory", sf.IMADirectory)
	if len(sf.ActiveLSMs) > 0 {
		fmt.Fprintf(&b, "  Active LSMs: %s\n", strings.Join(sf.ActiveLSMs, ", "))
	}
	b.WriteString("\n")

	b.WriteString("Capabilities:\n")
	writeResult(&b, "  CAP_BPF", sf.HasCapBPF)
	writeResult(&b, "  CAP_SYS_ADMIN", sf.HasCapSysAdmin)
	writeResult(&b, "  CAP_PERFMON", sf.HasCapPerfmon)
	writeResult(&b, "  Unprivileged BPF disabled", sf.UnprivilegedBPFDisabled)
	writeResult(&b, "  BPF stats enabled", sf.BPFStatsEnabled)
	b.WriteString("\n")

	b.WriteString("Filesystems:\n")
	writeResult(&b, "  tracefs", sf.Tracefs)
	writeResult(&b, "  debugfs", sf.Debugfs)
	writeResult(&b, "  securityfs", sf.Securityfs)
	writeResult(&b, "  bpffs", sf.BPFfs)
	b.WriteString("\n")

	b.WriteString("JIT:\n")
	writeResult(&b, "  Enabled", sf.JITEnabled)
	writeResult(&b, "  Hardened", sf.JITHardened)
	writeResult(&b, "  Kallsyms", sf.JITKallsyms)
	if sf.JITLimit > 0 {
		fmt.Fprintf(&b, "  Memory limit: %d bytes\n", sf.JITLimit)
	} else {
		b.WriteString("  Memory limit: unknown\n")
	}
	b.WriteString("\n")

	b.WriteString("Namespaces:\n")
	writeResult(&b, "  Initial user namespace", sf.InInitUserNS)
	writeResult(&b, "  Initial PID namespace", sf.InInitPIDNS)
	b.WriteString("\n")

	if sf.SpectreV1 != "" || sf.SpectreV2 != "" {
		b.WriteString("CPU Mitigations:\n")
		if sf.SpectreV1 != "" {
			fmt.Fprintf(&b, "  Spectre v1: %s\n", sf.SpectreV1)
		}
		if sf.SpectreV2 != "" {
			fmt.Fprintf(&b, "  Spectre v2: %s\n", sf.SpectreV2)
		}
		b.WriteString("\n")
	}

	if sf.KernelConfig != nil {
		b.WriteString("Kernel Config:\n")
		writeConfig(&b, "  CONFIG_BPF_LSM", sf.KernelConfig.BPFLSM)
		writeConfig(&b, "  CONFIG_IMA", sf.KernelConfig.IMA)
		writeConfig(&b, "  CONFIG_DEBUG_INFO_BTF", sf.KernelConfig.BTF)
		writeConfig(&b, "  CONFIG_FPROBE", sf.KernelConfig.KprobeMulti)
		writeConfig(&b, "  CONFIG_BPF_JIT_ALWAYS_ON", sf.KernelConfig.JITAlwaysOn)
		fmt.Fprintf(&b, "  Preemption model: %s\n", sf.KernelConfig.Preempt)
		fmt.Fprintf(&b, "  Sleepable BPF: %s\n", map[bool]string{true: "yes", false: "no"}[sf.KernelConfig.Preempt.SupportsSleepable()])
	}

	return b.String()
}

func writeResult(b *strings.Builder, name string, r ProbeResult) {
	status := "no"
	if r.Supported {
		status = "yes"
	}
	if r.Error != nil {
		fmt.Fprintf(b, "%s: %s (error: %v)\n", name, status, r.Error)
	} else {
		fmt.Fprintf(b, "%s: %s\n", name, status)
	}
}

func writeConfig(b *strings.Builder, name string, v ConfigValue) {
	fmt.Fprintf(b, "%s: %s\n", name, v)
}
