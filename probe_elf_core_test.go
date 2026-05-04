package kfeatures

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestClassifyMemoryAccessesNil(t *testing.T) {
	if got := computeMemoryAccessSummary(nil); got != (MemoryAccessSummary{}) {
		t.Errorf("nil prog should yield zero summary, got %+v", got)
	}
}

func TestComputeCOREWarningsNil(t *testing.T) {
	if got := computeCOREWarnings("p", nil); got != nil {
		t.Errorf("nil prog should yield nil, got %+v", got)
	}
}

func TestClassifyContextSafeAccess(t *testing.T) {
	// Load from R1 (context). Should be context-safe.
	prog := &ebpf.ProgramSpec{
		Name: "ctx",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			// R2 = *(u64 *)(R1 + 0)
			asm.LoadMem(asm.R2, asm.R1, 0, asm.DWord),
			asm.Return(),
		},
	}
	got := computeMemoryAccessSummary(prog)
	if got.Total != 1 || got.ContextSafe != 1 {
		t.Errorf("summary = %+v, want Total=1 ContextSafe=1", got)
	}
}

func TestClassifyMapValueSafeAccess(t *testing.T) {
	prog := &ebpf.ProgramSpec{
		Name: "mv",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			// R0 = bpf_map_lookup_elem(...)
			asm.FnMapLookupElem.Call(),
			// R1 = *(u64 *)(R0 + 0)
			asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}
	got := computeMemoryAccessSummary(prog)
	if got.Total != 1 || got.MapValueSafe != 1 {
		t.Errorf("summary = %+v, want Total=1 MapValueSafe=1", got)
	}
}

func TestClassifyKernelDirectAccessAndWarning(t *testing.T) {
	prog := &ebpf.ProgramSpec{
		Name: "kd",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			// R0 = bpf_get_current_task()
			asm.FnGetCurrentTask.Call(),
			// R1 = *(u64 *)(R0 + 0)  // unprotected kernel deref
			asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}
	got := computeMemoryAccessSummary(prog)
	if got.Total != 1 || got.KernelDirect != 1 {
		t.Errorf("summary = %+v, want Total=1 KernelDirect=1", got)
	}
	warnings := computeCOREWarnings("kd", prog)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %d, want 1: %+v", len(warnings), warnings)
	}
	w := warnings[0]
	if w.Severity != "warning" || w.Program != "kd" {
		t.Errorf("warning = %+v", w)
	}
	if !strings.Contains(w.Message, "kernel pointer dereferenced without CO-RE") {
		t.Errorf("warning message = %q", w.Message)
	}
}

func TestClassifyUncategorizedAccess(t *testing.T) {
	prog := &ebpf.ProgramSpec{
		Name: "u",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			// Load a constant into R6, then dereference R6.
			asm.LoadImm(asm.R6, 0xdeadbeef, asm.DWord),
			asm.LoadMem(asm.R1, asm.R6, 0, asm.DWord),
			asm.Return(),
		},
	}
	got := computeMemoryAccessSummary(prog)
	if got.Total != 1 || got.Uncategorized != 1 {
		t.Errorf("summary = %+v, want Total=1 Uncategorized=1", got)
	}
	if warnings := computeCOREWarnings("u", prog); len(warnings) != 0 {
		t.Errorf("uncategorized should not warn, got %d", len(warnings))
	}
}

func TestClassifyMovPropagatesProvenance(t *testing.T) {
	prog := &ebpf.ProgramSpec{
		Name: "mov",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			// R6 = R1 (context)
			asm.Mov.Reg(asm.R6, asm.R1),
			// R2 = *(u64 *)(R6 + 0)  // context-safe via mov
			asm.LoadMem(asm.R2, asm.R6, 0, asm.DWord),
			asm.Return(),
		},
	}
	got := computeMemoryAccessSummary(prog)
	if got.ContextSafe != 1 {
		t.Errorf("expected mov-propagated context-safe, got %+v", got)
	}
}

func TestClassifyHelperClobbersR1R5(t *testing.T) {
	// After a helper call, R1-R5 must be cleared so subsequent loads
	// from those registers are uncategorized (not context-safe).
	prog := &ebpf.ProgramSpec{
		Name: "clobber",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.FnGetSmpProcessorId.Call(),
			// R2 = *(u64 *)(R1 + 0). R1 was the helper's argv slot; now unknown.
			asm.LoadMem(asm.R2, asm.R1, 0, asm.DWord),
			asm.Return(),
		},
	}
	got := computeMemoryAccessSummary(prog)
	if got.Uncategorized != 1 {
		t.Errorf("expected R1 clobbered post-helper, got %+v", got)
	}
}

func TestLineInfoStubReturnsEmpty(t *testing.T) {
	file, line := lineInfo(asm.Return())
	if file != "" || line != 0 {
		t.Errorf("lineInfo stub = (%q, %d), want (\"\", 0)", file, line)
	}
}

func TestProvenanceForHelperUnknown(t *testing.T) {
	// A helper not in the table degrades to provUnknown.
	if got := provenanceForHelper(asm.FnTracePrintk); got != provUnknown {
		t.Errorf("provenanceForHelper(FnTracePrintk) = %v, want provUnknown", got)
	}
}

func TestClassifyAccessAllProvenances(t *testing.T) {
	cases := map[regProvenance]memoryAccessKind{
		provContext:       accessContextSafe,
		provMapValue:      accessMapValueSafe,
		provKernelDirect:  accessKernelDirect,
		provCOREProtected: accessCOREProtected,
		provUnknown:       accessUncategorized,
	}
	for p, want := range cases {
		if got := classifyAccess(p); got != want {
			t.Errorf("classifyAccess(%v) = %v, want %v", p, got, want)
		}
	}
	// Sanity: accessNotLoad is the zero value and is never produced
	// by classifyAccess (callers reserve that for non-load slots).
	var zero memoryAccessKind
	if zero != accessNotLoad {
		t.Errorf("zero value of memoryAccessKind = %v, want accessNotLoad", zero)
	}
}

func TestInheritFromSourceAllProvenances(t *testing.T) {
	for _, p := range []regProvenance{provContext, provMapValue, provKernelDirect, provCOREProtected} {
		if got := inheritFromSource(p); got != p {
			t.Errorf("inheritFromSource(%v) = %v, want %v", p, got, p)
		}
	}
	if got := inheritFromSource(provUnknown); got != provUnknown {
		t.Errorf("inheritFromSource(provUnknown) = %v", got)
	}
}

func TestWithCOREChecksEndToEnd(t *testing.T) {
	// Drive through ProbeELFWith via probesFromCollectionSpec.
	prog := &ebpf.ProgramSpec{
		Name:    "drive",
		Type:    ebpf.Kprobe,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentTask.Call(),
			asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{"drive": prog},
	}
	probes, err := probesFromCollectionSpec(spec, &elfProbeConfig{withCORE: true})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	if probes.Programs[0].MemoryAccesses.KernelDirect != 1 {
		t.Errorf("MemoryAccesses = %+v", probes.Programs[0].MemoryAccesses)
	}
	// Should have the CO-RE warning plus the FnGetCurrentTask superseded warning.
	var hasCore, hasSuperseded bool
	for _, w := range probes.Warnings {
		if strings.Contains(w.Message, "kernel pointer dereferenced") {
			hasCore = true
		}
		if strings.Contains(w.Message, "deprecated helper") {
			hasSuperseded = true
		}
	}
	if !hasCore {
		t.Error("expected CO-RE warning")
	}
	if !hasSuperseded {
		t.Error("expected superseded-helper warning")
	}

	// Without WithCOREChecks(), MemoryAccesses must be zero and no CO-RE warning.
	probes2, err := probesFromCollectionSpec(spec, &elfProbeConfig{})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	if probes2.Programs[0].MemoryAccesses != (MemoryAccessSummary{}) {
		t.Errorf("MemoryAccesses without WithCOREChecks = %+v, want zero", probes2.Programs[0].MemoryAccesses)
	}
	for _, w := range probes2.Warnings {
		if strings.Contains(w.Message, "kernel pointer dereferenced") {
			t.Error("CO-RE warning leaked without WithCOREChecks()")
		}
	}
}
