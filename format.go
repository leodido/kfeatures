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
	b.WriteString("\n")

	if sf.KernelConfig != nil {
		b.WriteString("Kernel Config:\n")
		writeConfig(&b, "  CONFIG_BPF_LSM", sf.KernelConfig.BPFLSM)
		writeConfig(&b, "  CONFIG_IMA", sf.KernelConfig.IMA)
		writeConfig(&b, "  CONFIG_DEBUG_INFO_BTF", sf.KernelConfig.BTF)
		writeConfig(&b, "  CONFIG_FPROBE", sf.KernelConfig.KprobeMulti)
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
