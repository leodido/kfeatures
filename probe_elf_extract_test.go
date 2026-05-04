package kfeatures

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// makeFixtureSpec builds a minimal *ebpf.CollectionSpec without touching
// disk. The shape is chosen to exercise multi-program / multi-map
// deduplication and ordering.
func makeFixtureSpec() *ebpf.CollectionSpec {
	kprobeInsns := asm.Instructions{
		asm.LoadImm(asm.R1, 0, asm.DWord),
		asm.FnMapLookupElem.Call(),
		asm.FnTracePrintk.Call(),
		// Duplicate within program.
		asm.FnMapLookupElem.Call(),
		asm.Return(),
	}
	xdpInsns := asm.Instructions{
		asm.LoadImm(asm.R1, 0, asm.DWord),
		asm.FnMapLookupElem.Call(),
		asm.Return(),
	}
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"events": {
				Name:       "events",
				Type:       ebpf.RingBuf,
				MaxEntries: 4096,
			},
			"hashy": {
				Name:       "hashy",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 1024,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"kprobe_prog": {
				Name:         "kprobe_prog",
				Type:         ebpf.Kprobe,
				SectionName:  "kprobe/do_sys_openat2",
				License:      "GPL",
				Instructions: kprobeInsns,
			},
			"xdp_prog": {
				Name:         "xdp_prog",
				Type:         ebpf.XDP,
				SectionName:  "xdp/main",
				License:      "GPL",
				Instructions: xdpInsns,
			},
		},
	}
}

func TestProbeFromCollectionSpec(t *testing.T) {
	got, err := probesFromCollectionSpec(makeFixtureSpec(), &elfProbeConfig{})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	if got.License != "GPL" {
		t.Errorf("License = %q, want GPL", got.License)
	}
	if got.HasBTF {
		t.Errorf("HasBTF should be false for fixture without BTF")
	}
	if got.CORERelocations != 0 {
		t.Errorf("CORERelocations = %d, want 0", got.CORERelocations)
	}
	// MinKernel = max across helpers/progtypes/maptypes.
	// RingBuf was introduced in 5.8, which dominates everything else here.
	want := KernelVersion{Major: 5, Minor: 8}
	if got.MinKernel != want {
		t.Errorf("MinKernel = %v, want %v", got.MinKernel, want)
	}
	// Transport detection.
	if len(got.Transport) != 1 || got.Transport[0] != "event streaming via RingBuf" {
		t.Errorf("Transport = %v, want [\"event streaming via RingBuf\"]", got.Transport)
	}
	// Programs are ordered alphabetically.
	if len(got.Programs) != 2 || got.Programs[0].Name != "kprobe_prog" || got.Programs[1].Name != "xdp_prog" {
		t.Fatalf("program order wrong: %+v", got.Programs)
	}
	if got.Programs[0].Type != ebpf.Kprobe.String() {
		t.Errorf("kprobe program type = %q", got.Programs[0].Type)
	}
	if got.Programs[0].NumInsns != 5 {
		t.Errorf("kprobe NumInsns = %d, want 5", got.Programs[0].NumInsns)
	}
	// Per-program helpers deduped.
	if len(got.Programs[0].Helpers) != 2 {
		t.Errorf("kprobe helpers = %d, want 2 (deduped)", len(got.Programs[0].Helpers))
	}
	// Maps deterministic order (alphabetical).
	if len(got.Maps) != 2 || got.Maps[0].Name != "events" || got.Maps[1].Name != "hashy" {
		t.Fatalf("map order wrong: %+v", got.Maps)
	}
	if got.Maps[1].KeySize != 4 || got.Maps[1].ValueSize != 8 {
		t.Errorf("hashy sizes = key=%d val=%d", got.Maps[1].KeySize, got.Maps[1].ValueSize)
	}
}

func TestRequirementsParityWithFromELF(t *testing.T) {
	spec := makeFixtureSpec()
	probes, err := probesFromCollectionSpec(spec, &elfProbeConfig{})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	want, err := requirementsFromCollectionSpec(spec)
	if err != nil {
		t.Fatalf("requirementsFromCollectionSpec: %v", err)
	}
	got := probes.Requirements()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Requirements() != FromELF():\n got: %+v\nwant: %+v", got, want)
	}
}

func TestProbeELFEmptyPath(t *testing.T) {
	_, err := ProbeELF("")
	if err == nil {
		t.Fatal("ProbeELF(\"\"): expected error")
	}
}

func TestProbeELFLoadFailure(t *testing.T) {
	_, err := ProbeELF("/nonexistent/path/that/does/not/exist.bpf.o")
	if err == nil {
		t.Fatal("ProbeELF(missing): expected error")
	}
}

func TestProbeNilSpec(t *testing.T) {
	_, err := probesFromCollectionSpec(nil, &elfProbeConfig{})
	if err == nil {
		t.Fatal("nil spec: expected error")
	}
}

func TestProbeNilProgramSpec(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"prog": nil,
		},
	}
	if _, err := probesFromCollectionSpec(spec, &elfProbeConfig{}); err == nil {
		t.Fatal("nil program spec: expected error")
	}
}

func TestProbeNilMapSpec(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"m": nil,
		},
	}
	if _, err := probesFromCollectionSpec(spec, &elfProbeConfig{}); err == nil {
		t.Fatal("nil map spec: expected error")
	}
}

func TestProbeUnknownProgramType(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"prog": {
				Name: "prog",
				Type: ebpf.UnspecifiedProgram,
				Instructions: asm.Instructions{
					asm.Return(),
				},
			},
		},
	}
	if _, err := probesFromCollectionSpec(spec, &elfProbeConfig{}); err == nil {
		t.Fatal("unspecified program type: expected error")
	}
}

func TestProbeUnknownMapType(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"m": {Name: "m", Type: ebpf.UnspecifiedMap, MaxEntries: 1},
		},
	}
	if _, err := probesFromCollectionSpec(spec, &elfProbeConfig{}); err == nil {
		t.Fatal("unspecified map type: expected error")
	}
}

// TestProbeHelperSortBranches adds helpers in an order that forces both
// arms of the union-sort comparator and both arms of the version-desc
// stable sort comparator to fire (helpers introduced in different
// kernel versions, with at least one tie on the same version to take
// the secondary-key arms).
func TestProbeHelperSortBranches(t *testing.T) {
	insns := asm.Instructions{
		// FnGetCurrentTaskBtf (5.11) > FnTracePrintk (4.1) > FnMapLookupElem (3.18)
		// inserted in non-monotonic order.
		asm.FnTracePrintk.Call(),
		asm.FnGetCurrentTaskBtf.Call(),
		asm.FnMapLookupElem.Call(),
		// Two helpers added in the same kernel version (4.1) so the
		// sort hits the equal-version secondary-key branch.
		asm.FnGetCurrentPidTgid.Call(),
		asm.FnGetCurrentUidGid.Call(),
		asm.Return(),
	}
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"p": {
				Name:         "p",
				Type:         ebpf.Kprobe,
				License:      "GPL",
				Instructions: insns,
			},
		},
	}
	got, err := probesFromCollectionSpec(spec, &elfProbeConfig{})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	if len(got.Helpers) != 5 {
		t.Fatalf("Helpers = %d, want 5", len(got.Helpers))
	}
	// Verify version-desc ordering: FnGetCurrentTaskBtf (5.11) must be first.
	if got.Helpers[0].Helper != asm.FnGetCurrentTaskBtf {
		t.Errorf("Helpers[0] = %v, want FnGetCurrentTaskBtf", got.Helpers[0].Helper)
	}
}

func TestProbeWithCOREChecksHook(t *testing.T) {
	// Swap the classifier hook for one that returns a non-zero summary
	// so we exercise the cfg.withCORE branch end to end without taking
	// a dependency on the real classifier (covered by its own tests).
	prev := classifyMemoryAccesses
	prevWarn := coreWarnings
	defer func() {
		classifyMemoryAccesses = prev
		coreWarnings = prevWarn
	}()
	classifyMemoryAccesses = func(prog *ebpf.ProgramSpec) MemoryAccessSummary {
		return MemoryAccessSummary{Total: 1, ContextSafe: 1}
	}
	coreWarnings = func(progName string, prog *ebpf.ProgramSpec) []ELFWarning {
		return []ELFWarning{{Program: progName, Message: "synthetic"}}
	}
	got, err := probesFromCollectionSpec(makeFixtureSpec(), &elfProbeConfig{withCORE: true})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	if got.Programs[0].MemoryAccesses.Total != 1 {
		t.Errorf("MemoryAccesses.Total = %d, want 1", got.Programs[0].MemoryAccesses.Total)
	}
	if len(got.Warnings) == 0 {
		t.Errorf("expected synthetic warnings to be appended")
	}
}

func TestProbeNilProgram(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{"x": nil},
	}
	_, err := probesFromCollectionSpec(spec, &elfProbeConfig{})
	if err == nil {
		t.Fatal("nil program: expected error")
	}
}

func TestProbeNilMap(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{"x": nil},
	}
	_, err := probesFromCollectionSpec(spec, &elfProbeConfig{})
	if err == nil {
		t.Fatal("nil map: expected error")
	}
}

func TestTransportsFor(t *testing.T) {
	cases := []struct {
		name string
		in   []ELFMapTypeRequirement
		want []string
	}{
		{"empty", nil, nil},
		{"hash only", []ELFMapTypeRequirement{{Type: ebpf.Hash}}, nil},
		{"ringbuf", []ELFMapTypeRequirement{{Type: ebpf.RingBuf}}, []string{"event streaming via RingBuf"}},
		{"perfevent", []ELFMapTypeRequirement{{Type: ebpf.PerfEventArray}}, []string{"event streaming via PerfEventArray"}},
		{"both", []ELFMapTypeRequirement{{Type: ebpf.RingBuf}, {Type: ebpf.PerfEventArray}}, []string{"event streaming via PerfEventArray", "event streaming via RingBuf"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := transportsFor(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("transportsFor() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWithCOREChecksOption(t *testing.T) {
	cfg := &elfProbeConfig{}
	if cfg.withCORE {
		t.Fatal("expected withCORE false by default")
	}
	WithCOREChecks()(cfg)
	if !cfg.withCORE {
		t.Fatal("WithCOREChecks() did not enable withCORE")
	}
}
