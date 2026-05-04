package kfeatures

import (
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/leodido/kfeatures/internal/kernelversions"
)

// ELFProbes is the descriptive ELF-side counterpart of [SystemFeatures].
//
// It captures every signal that can be derived from a compiled BPF ELF
// without loading the program into the kernel: license, BTF presence and
// CO-RE relocation count, computed minimum kernel version, transports,
// per-program details, per-map metadata, deduplicated helper / program-type
// / map-type requirements with their introduction versions, and any
// warnings collected during the analysis pass.
//
// ELFProbes is descriptive only and never participates in [Check]
// evaluation. Use [(*ELFProbes).Requirements] when you want to derive a
// gating [FeatureGroup] from the same parse.
type ELFProbes struct {
	Path            string                       `json:"path"`
	License         string                       `json:"license"`
	HasBTF          bool                         `json:"hasBTF"`
	CORERelocations int                          `json:"coreRelocations"`
	MinKernel       KernelVersion                `json:"minKernel"`
	Transport       []string                     `json:"transport,omitempty"`
	Programs        []ELFProgram                 `json:"programs,omitempty"`
	Maps            []ELFMap                     `json:"maps,omitempty"`
	Helpers         []ELFHelperRequirement       `json:"helpers,omitempty"`
	ProgramTypes    []ELFProgramTypeRequirement  `json:"programTypes,omitempty"`
	MapTypes        []ELFMapTypeRequirement      `json:"mapTypes,omitempty"`
	Warnings        []ELFWarning                 `json:"warnings,omitempty"`
}

// KernelVersion is a major.minor Linux kernel version.
//
// It mirrors [kernelversions.KernelVersion] in the public API surface so
// that consumers can construct, compare and serialize values without
// importing the internal package.
type KernelVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// String renders the version as "major.minor".
func (v KernelVersion) String() string {
	return kernelversions.KernelVersion{Major: v.Major, Minor: v.Minor}.String()
}

// IsZero reports whether v is the zero value.
func (v KernelVersion) IsZero() bool {
	return v.Major == 0 && v.Minor == 0
}

// less reports whether v is older than other.
func (v KernelVersion) less(other KernelVersion) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	return v.Minor < other.Minor
}

// maxKernelVersion returns the larger of two KernelVersion values.
func maxKernelVersion(a, b KernelVersion) KernelVersion {
	if a.less(b) {
		return b
	}
	return a
}

// fromInternal converts the internal kernelversions.KernelVersion to the
// public type.
func fromInternal(v kernelversions.KernelVersion) KernelVersion {
	return KernelVersion{Major: v.Major, Minor: v.Minor}
}

// ELFProgram describes a single program inside an ELF object.
//
// MemoryAccesses is populated only when the caller passes [WithCOREChecks]
// to [ProbeELFWith]; otherwise it is the zero value.
//
// ProgramType carries the canonical cilium/ebpf constant; Type is the
// human-readable string form (the JSON shape uses Type for stable
// lower-camel output, while ProgramType drives Requirements()).
type ELFProgram struct {
	Name           string                 `json:"name"`
	SectionName    string                 `json:"sectionName"`
	Type           string                 `json:"type"`
	ProgramType    ebpf.ProgramType       `json:"-"`
	NumInsns       int                    `json:"numInsns"`
	CORERelocs     int                    `json:"coreRelocs"`
	Helpers        []ELFHelperRequirement `json:"helpers,omitempty"`
	MemoryAccesses MemoryAccessSummary    `json:"memoryAccesses,omitzero"`
}

// ELFMap describes a single map inside an ELF object.
type ELFMap struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	KeySize    uint32        `json:"keySize"`
	ValueSize  uint32        `json:"valueSize"`
	MaxEntries uint32        `json:"maxEntries"`
	Version    KernelVersion `json:"version"`
}

// ELFHelperRequirement describes a single helper invocation discovered in
// an ELF object, paired with the kernel version that introduced it.
type ELFHelperRequirement struct {
	Name    string           `json:"name"`
	Helper  asm.BuiltinFunc  `json:"-"`
	Version KernelVersion    `json:"version"`
}

// ELFProgramTypeRequirement describes a program type referenced by an ELF
// object, paired with the kernel version that introduced it.
type ELFProgramTypeRequirement struct {
	Name    string           `json:"name"`
	Type    ebpf.ProgramType `json:"-"`
	Version KernelVersion    `json:"version"`
}

// ELFMapTypeRequirement describes a map type referenced by an ELF object,
// paired with the kernel version that introduced it.
type ELFMapTypeRequirement struct {
	Name    string        `json:"name"`
	Type    ebpf.MapType  `json:"-"`
	Version KernelVersion `json:"version"`
}

// MemoryAccessSummary captures the per-program register-classifier output
// of [WithCOREChecks].
//
// All counts are zero when [WithCOREChecks] was not requested.
type MemoryAccessSummary struct {
	Total          int `json:"total"`
	COREProtected  int `json:"coreProtected"`
	ContextSafe    int `json:"contextSafe"`
	MapValueSafe   int `json:"mapValueSafe"`
	KernelDirect   int `json:"kernelDirect"`
	Uncategorized  int `json:"uncategorized"`
}

// ELFWarning is a single diagnostic raised during ELF analysis.
//
// Severity is "warning" or "error". Program is the BPF program name in
// which the issue was detected (empty for object-wide warnings). File and
// Line carry BTF source-info location when available.
type ELFWarning struct {
	Severity string `json:"severity"`
	Program  string `json:"program,omitempty"`
	File     string `json:"file,omitempty"`
	Line     uint32 `json:"line,omitempty"`
	Message  string `json:"message"`
	Detail   string `json:"detail,omitempty"`
}

// Requirements derives the same [FeatureGroup] that [FromELF] would return
// for the same input, using the data already cached on p. The two paths
// are guaranteed to produce deep-equal output.
//
// Use this when you want both the diagnostic [ELFProbes] view and the
// gating [FeatureGroup] from a single ELF parse.
func (p *ELFProbes) Requirements() FeatureGroup {
	if p == nil {
		return nil
	}
	// Re-derive the deterministic ordering FromELF guarantees: program
	// types sorted, then map types sorted, then helper-per-program pairs
	// sorted by (programType, helper). Because ELFProbes already stores
	// per-program helpers but FromELF emits the cross-program union, we
	// rebuild the union here.
	progTypes := make([]ebpf.ProgramType, 0, len(p.ProgramTypes))
	for _, pt := range p.ProgramTypes {
		progTypes = append(progTypes, pt.Type)
	}
	slices.Sort(progTypes)

	mapTypes := make([]ebpf.MapType, 0, len(p.MapTypes))
	for _, mt := range p.MapTypes {
		mapTypes = append(mapTypes, mt.Type)
	}
	slices.Sort(mapTypes)

	seenPair := make(map[ProgramHelperRequirement]struct{})
	pairs := make([]ProgramHelperRequirement, 0)
	for _, prog := range p.Programs {
		for _, h := range prog.Helpers {
			pair := ProgramHelperRequirement{
				ProgramType: prog.ProgramType,
				Helper:      h.Helper,
			}
			if _, ok := seenPair[pair]; ok {
				continue
			}
			seenPair[pair] = struct{}{}
			pairs = append(pairs, pair)
		}
	}
	slices.SortFunc(pairs, func(a, b ProgramHelperRequirement) int {
		if a.ProgramType != b.ProgramType {
			if a.ProgramType < b.ProgramType {
				return -1
			}
			return 1
		}
		if a.Helper != b.Helper {
			if a.Helper < b.Helper {
				return -1
			}
			return 1
		}
		return 0
	})

	out := make(FeatureGroup, 0, len(progTypes)+len(mapTypes)+len(pairs))
	for _, pt := range progTypes {
		out = append(out, RequireProgramType(pt))
	}
	for _, mt := range mapTypes {
		out = append(out, RequireMapType(mt))
	}
	for _, pair := range pairs {
		out = append(out, pair)
	}
	return out
}


