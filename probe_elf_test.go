package kfeatures

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/leodido/kfeatures/internal/kernelversions"
)

func TestKernelVersionPublic(t *testing.T) {
	a := KernelVersion{Major: 5, Minor: 8}
	if got := a.String(); got != "5.8" {
		t.Errorf("String() = %q, want %q", got, "5.8")
	}
	if a.IsZero() {
		t.Errorf("5.8 should not be IsZero")
	}
	if !(KernelVersion{}).IsZero() {
		t.Errorf("zero should be IsZero")
	}
	if (KernelVersion{Major: 5, Minor: 8}).less(KernelVersion{Major: 5, Minor: 8}) {
		t.Errorf("equal versions should not be less")
	}
	if !(KernelVersion{Major: 5, Minor: 8}).less(KernelVersion{Major: 6, Minor: 0}) {
		t.Errorf("5.8 < 6.0")
	}
	if (KernelVersion{Major: 6, Minor: 0}).less(KernelVersion{Major: 5, Minor: 8}) {
		t.Errorf("6.0 should not be less than 5.8")
	}
	if !(KernelVersion{Major: 5, Minor: 8}).less(KernelVersion{Major: 5, Minor: 9}) {
		t.Errorf("5.8 < 5.9")
	}
}

func TestMaxKernelVersion(t *testing.T) {
	a := KernelVersion{Major: 5, Minor: 8}
	b := KernelVersion{Major: 6, Minor: 0}
	if got := maxKernelVersion(a, b); got != b {
		t.Errorf("max(5.8, 6.0) = %v, want %v", got, b)
	}
	if got := maxKernelVersion(b, a); got != b {
		t.Errorf("max(6.0, 5.8) = %v, want %v", got, b)
	}
}

func TestFromInternal(t *testing.T) {
	got := fromInternal(kernelversions.KernelVersion{Major: 5, Minor: 8})
	if got != (KernelVersion{Major: 5, Minor: 8}) {
		t.Errorf("fromInternal = %v", got)
	}
}

func TestRequirementsFromHandBuiltProbes(t *testing.T) {
	// Confirm Requirements() emits the same FeatureGroup shape as
	// FromELF: program types sorted, then map types sorted, then
	// program-helper pairs sorted by (programType, helper).
	p := &ELFProbes{
		Programs: []ELFProgram{
			{
				Name:        "prog_kprobe",
				Type:        ebpf.Kprobe.String(),
				ProgramType: ebpf.Kprobe,
				Helpers: []ELFHelperRequirement{
					{Name: "FnMapLookupElem", Helper: asm.FnMapLookupElem},
					{Name: "FnTracePrintk", Helper: asm.FnTracePrintk},
					// Duplicate within the same program (different probe-of-the-same-helper)
					{Name: "FnMapLookupElem", Helper: asm.FnMapLookupElem},
				},
			},
			{
				Name:        "prog_xdp",
				Type:        ebpf.XDP.String(),
				ProgramType: ebpf.XDP,
				Helpers: []ELFHelperRequirement{
					{Name: "FnMapLookupElem", Helper: asm.FnMapLookupElem},
				},
			},
		},
		ProgramTypes: []ELFProgramTypeRequirement{
			{Name: "XDP", Type: ebpf.XDP},
			{Name: "Kprobe", Type: ebpf.Kprobe},
		},
		MapTypes: []ELFMapTypeRequirement{
			{Name: "RingBuf", Type: ebpf.RingBuf},
			{Name: "Hash", Type: ebpf.Hash},
		},
	}
	got := p.Requirements()
	want := FeatureGroup{
		// program types sorted by enum value (Kprobe < XDP)
		RequireProgramType(ebpf.Kprobe),
		RequireProgramType(ebpf.XDP),
		// map types sorted by enum value (Hash < RingBuf)
		RequireMapType(ebpf.Hash),
		RequireMapType(ebpf.RingBuf),
		// program-helper pairs sorted by (ProgramType, Helper)
		RequireProgramHelper(ebpf.Kprobe, asm.FnMapLookupElem),
		RequireProgramHelper(ebpf.Kprobe, asm.FnTracePrintk),
		RequireProgramHelper(ebpf.XDP, asm.FnMapLookupElem),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Requirements() mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestRequirementsNilReceiver(t *testing.T) {
	var p *ELFProbes
	if got := p.Requirements(); got != nil {
		t.Errorf("nil receiver should return nil, got %+v", got)
	}
}

func TestRequirementsEmptyProbes(t *testing.T) {
	p := &ELFProbes{}
	got := p.Requirements()
	if len(got) != 0 {
		t.Errorf("empty probes should yield empty FeatureGroup, got %+v", got)
	}
}
