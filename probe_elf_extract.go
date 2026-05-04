package kfeatures

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/leodido/kfeatures/internal/kernelversions"
)

// ELFProbeOption configures [ProbeELFWith].
type ELFProbeOption func(*elfProbeConfig)

// elfProbeConfig is the internal accumulator for ProbeELFWith options.
type elfProbeConfig struct {
	withCORE bool
}

// WithCOREChecks enables the heuristic CO-RE register-state classifier
// when probing the ELF. Without this option, [MemoryAccessSummary] is
// zero on every program and no CO-RE direct-access warnings are emitted.
//
// The classifier is heuristic: it has known false negatives on
// vmlinux.h-built programs (the warning may never fire) and rare false
// positives on hand-defined structs without
// `__attribute__((preserve_access_index))`. Treat its warnings as
// suggestions, not as hard verifier errors.
func WithCOREChecks() ELFProbeOption {
	return func(c *elfProbeConfig) { c.withCORE = true }
}

// ProbeELF returns descriptive ELF-derived signals about the program at
// path: license, BTF presence, CO-RE relocation count, computed minimum
// kernel version, transports, per-program / per-map metadata, deduplicated
// helper / program-type / map-type requirements with their introduction
// versions, and warnings (the "always-on" subset; see [ELFProbes.Warnings]
// and [ELFWarning]).
//
// ProbeELF never gates and never participates in [Check]. Use
// [(*ELFProbes).Requirements] to derive a [FeatureGroup] from the same
// parse if you also need the gate view.
func ProbeELF(path string) (*ELFProbes, error) {
	return ProbeELFWith(path)
}

// ProbeELFWith is the option-driven variant of [ProbeELF].
//
// The success path requires a real eBPF object on disk (clang +
// libbpf), which is not available in the unit-test environment. The
// per-branch behaviour is exercised by the programmatic-fixture tests
// against [probesFromCollectionSpec] (the same code paths under a
// CollectionSpec built in memory) and by the integration tests with a
// `make build`-able fixture; the disk-load wrapper itself is excluded
// from the per-file coverage gate.
//
// coverage:ignore
func ProbeELFWith(path string, opts ...ELFProbeOption) (*ELFProbes, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("probe ELF: empty path")
	}
	cfg := &elfProbeConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("probe ELF %q: load collection spec: %w", path, err)
	}
	probes, err := probesFromCollectionSpec(spec, cfg)
	if err != nil {
		return nil, fmt.Errorf("probe ELF %q: %w", path, err)
	}
	probes.Path = path
	return probes, nil
}

// probesFromCollectionSpec walks a *ebpf.CollectionSpec and populates an
// *ELFProbes value. It does not parse the ELF: it operates on an already-
// parsed CollectionSpec so that test fixtures can construct one directly
// without a .bpf.o file on disk.
func probesFromCollectionSpec(spec *ebpf.CollectionSpec, cfg *elfProbeConfig) (*ELFProbes, error) {
	if spec == nil {
		return nil, fmt.Errorf("nil collection spec")
	}
	out := &ELFProbes{
		HasBTF: spec.Types != nil,
	}

	// Walk programs in deterministic order.
	progNames := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		progNames = append(progNames, n)
	}
	slices.Sort(progNames)

	seenProgTypes := make(map[ebpf.ProgramType]struct{})
	progTypesOrder := []ebpf.ProgramType{}
	helperUnion := make(map[asm.BuiltinFunc]struct{})
	helperUnionOrder := []asm.BuiltinFunc{}
	totalCORE := 0

	for _, name := range progNames {
		prog := spec.Programs[name]
		if prog == nil {
			return nil, fmt.Errorf("program %q: nil program spec", name)
		}
		if err := validateProgramType(prog.Type); err != nil {
			return nil, fmt.Errorf("program %q: %w", name, err)
		}
		if _, ok := seenProgTypes[prog.Type]; !ok {
			seenProgTypes[prog.Type] = struct{}{}
			progTypesOrder = append(progTypesOrder, prog.Type)
		}

		// Take the first non-empty license seen across programs.
		if out.License == "" && prog.License != "" {
			out.License = prog.License
		}

		entry := ELFProgram{
			Name:        name,
			SectionName: prog.SectionName,
			Type:        prog.Type.String(),
			ProgramType: prog.Type,
			NumInsns:    len(prog.Instructions),
		}

		seenInProg := make(map[asm.BuiltinFunc]struct{})
		for i := range prog.Instructions {
			ins := &prog.Instructions[i]
			if btf.CORERelocationMetadata(ins) != nil {
				entry.CORERelocs++
				totalCORE++
			}
			if !ins.IsBuiltinCall() {
				continue
			}
			helper, err := helperFromInstruction(*ins)
			if err != nil {
				return nil, fmt.Errorf("program %q: %w", name, err)
			}
			if err := validateProgramHelper(helper); err != nil {
				return nil, fmt.Errorf("program %q: %w", name, err)
			}
			if _, ok := seenInProg[helper]; ok {
				continue
			}
			seenInProg[helper] = struct{}{}
			ver, _ := kernelversions.HelperKernelVersion(helper)
			entry.Helpers = append(entry.Helpers, ELFHelperRequirement{
				Name:    helper.String(),
				Helper:  helper,
				Version: fromInternal(ver),
			})
			if _, ok := helperUnion[helper]; !ok {
				helperUnion[helper] = struct{}{}
				helperUnionOrder = append(helperUnionOrder, helper)
			}
		}
		// Stable per-program helper order: by helper id.
		slices.SortFunc(entry.Helpers, func(a, b ELFHelperRequirement) int {
			if a.Helper < b.Helper {
				return -1
			}
			if a.Helper > b.Helper {
				return 1
			}
			return 0
		})

		if cfg.withCORE {
			entry.MemoryAccesses = classifyMemoryAccesses(prog)
			out.Warnings = append(out.Warnings, coreWarnings(name, prog)...)
		}
		out.Programs = append(out.Programs, entry)
	}
	out.CORERelocations = totalCORE

	// Maps in deterministic order.
	mapNames := make([]string, 0, len(spec.Maps))
	for n := range spec.Maps {
		mapNames = append(mapNames, n)
	}
	slices.Sort(mapNames)
	seenMapTypes := make(map[ebpf.MapType]struct{})
	mapTypesOrder := []ebpf.MapType{}
	for _, name := range mapNames {
		m := spec.Maps[name]
		if m == nil {
			return nil, fmt.Errorf("map %q: nil map spec", name)
		}
		if err := validateMapType(m.Type); err != nil {
			return nil, fmt.Errorf("map %q: %w", name, err)
		}
		if _, ok := seenMapTypes[m.Type]; !ok {
			seenMapTypes[m.Type] = struct{}{}
			mapTypesOrder = append(mapTypesOrder, m.Type)
		}
		ver, _ := kernelversions.MapTypeKernelVersion(m.Type)
		out.Maps = append(out.Maps, ELFMap{
			Name:       name,
			Type:       m.Type.String(),
			KeySize:    m.KeySize,
			ValueSize:  m.ValueSize,
			MaxEntries: m.MaxEntries,
			Version:    fromInternal(ver),
		})
	}

	// Helper / program-type / map-type union, sorted for determinism.
	slices.Sort(progTypesOrder)
	for _, pt := range progTypesOrder {
		ver, _ := kernelversions.ProgramTypeKernelVersion(pt)
		out.ProgramTypes = append(out.ProgramTypes, ELFProgramTypeRequirement{
			Name:    pt.String(),
			Type:    pt,
			Version: fromInternal(ver),
		})
	}
	slices.Sort(mapTypesOrder)
	for _, mt := range mapTypesOrder {
		ver, _ := kernelversions.MapTypeKernelVersion(mt)
		out.MapTypes = append(out.MapTypes, ELFMapTypeRequirement{
			Name:    mt.String(),
			Type:    mt,
			Version: fromInternal(ver),
		})
	}
	slices.SortFunc(helperUnionOrder, func(a, b asm.BuiltinFunc) int {
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	for _, h := range helperUnionOrder {
		ver, _ := kernelversions.HelperKernelVersion(h)
		out.Helpers = append(out.Helpers, ELFHelperRequirement{
			Name:    h.String(),
			Helper:  h,
			Version: fromInternal(ver),
		})
	}
	// Sort helpers by version desc so consumers see the gating rows first.
	slices.SortStableFunc(out.Helpers, func(a, b ELFHelperRequirement) int {
		if a.Version.less(b.Version) {
			return 1
		}
		if b.Version.less(a.Version) {
			return -1
		}
		// Same version: stable secondary key for determinism.
		if a.Helper < b.Helper {
			return -1
		}
		if a.Helper > b.Helper {
			return 1
		}
		return 0
	})

	// Min kernel = max across all per-row versions.
	for _, h := range out.Helpers {
		out.MinKernel = maxKernelVersion(out.MinKernel, h.Version)
	}
	for _, pt := range out.ProgramTypes {
		out.MinKernel = maxKernelVersion(out.MinKernel, pt.Version)
	}
	for _, mt := range out.MapTypes {
		out.MinKernel = maxKernelVersion(out.MinKernel, mt.Version)
	}

	// Transport detection: presence of RingBuf / PerfEventArray gives a
	// human-readable hint similar to bpfvet's "Transport: …" line.
	transports := transportsFor(out.MapTypes)
	if len(transports) > 0 {
		out.Transport = transports
	}

	// Always-on warning subset (superseded helpers). The CO-RE category
	// is appended above when WithCOREChecks() is set.
	out.Warnings = append(out.Warnings, supersededHelperWarnings(out)...)

	return out, nil
}

// transportsFor produces human-readable transport strings derived from the
// set of map types referenced by the ELF. Output is sorted for determinism.
func transportsFor(maps []ELFMapTypeRequirement) []string {
	seen := map[string]struct{}{}
	for _, mt := range maps {
		switch mt.Type {
		case ebpf.RingBuf:
			seen["event streaming via RingBuf"] = struct{}{}
		case ebpf.PerfEventArray:
			seen["event streaming via PerfEventArray"] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// classifyMemoryAccesses is the CO-RE register-state classifier entry
// point. The full implementation lives in probe_elf_core.go (added in a
// later step); this stub keeps the extractor compilable in isolation.
//
// When the classifier is implemented, it walks prog.Instructions once and
// returns per-program counts.
//
// coverage:ignore
var classifyMemoryAccesses = func(prog *ebpf.ProgramSpec) MemoryAccessSummary {
	return MemoryAccessSummary{}
}

// coreWarnings emits CO-RE direct-access warnings for prog. Stub-only
// until step 5; implementation lives in probe_elf_core.go.
//
// coverage:ignore
var coreWarnings = func(progName string, prog *ebpf.ProgramSpec) []ELFWarning {
	return nil
}

// supersededHelperWarnings inspects out.Helpers and emits the always-on
// "deprecated helper" warning subset. Stub-only until step 4; the rules
// live in probe_elf_warnings.go.
//
// coverage:ignore
var supersededHelperWarnings = func(out *ELFProbes) []ELFWarning {
	return nil
}
