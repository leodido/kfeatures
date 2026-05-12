package kfeatures

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Requirement describes a pass/fail gate condition consumable by [Check].
//
// API boundary:
//   - [Requirement] values define what must pass.
//   - [ProbeOption]/WithX values define what [ProbeWith] should collect.
//   - Do not model probe-scope selection as requirements.
//
// Built-in implementations include:
//   - [Feature]
//   - [FeatureGroup]
//   - [ProgramTypeRequirement]
//   - [MapTypeRequirement]
//   - [ProgramHelperRequirement]
//   - [MountRequirement]
type Requirement interface {
	isRequirement()
}

// FeatureGroup is a reusable set of [Requirement] items.
//
// Groups can include simple [Feature] values and parameterized requirements.
// It is a preset container, not a separate gate API family.
type FeatureGroup []Requirement

// ProgramTypeRequirement requires support for a specific eBPF program type.
type ProgramTypeRequirement struct {
	Type ebpf.ProgramType
}

// MapTypeRequirement requires support for a specific eBPF map type.
type MapTypeRequirement struct {
	Type ebpf.MapType
}

// ProgramHelperRequirement requires that a helper is supported for a program type.
type ProgramHelperRequirement struct {
	ProgramType ebpf.ProgramType
	Helper      asm.BuiltinFunc
}

// MountRequirement requires that Path is mounted with a filesystem whose
// superblock magic equals Magic. Magic is the raw f_type value the kernel
// reports via Statfs (e.g. golang.org/x/sys/unix.BPF_FS_MAGIC for bpffs).
//
// Use this when [FeatureBPFFS] / [FeatureTraceFS] are too restrictive: for
// example, bpffs mounted at a non-default path, or any other pseudo-FS the
// caller depends on (cgroupv2, debugfs, securityfs, tmpfs in tests, ...).
type MountRequirement struct {
	Path  string
	Magic uint32
}

// RequireProgramType creates a requirement for a program type.
func RequireProgramType(pt ebpf.ProgramType) ProgramTypeRequirement {
	return ProgramTypeRequirement{Type: pt}
}

// RequireMapType creates a requirement for a map type.
func RequireMapType(mt ebpf.MapType) MapTypeRequirement {
	return MapTypeRequirement{Type: mt}
}

// RequireProgramHelper creates a requirement for a helper/program-type pair.
func RequireProgramHelper(pt ebpf.ProgramType, helper asm.BuiltinFunc) ProgramHelperRequirement {
	return ProgramHelperRequirement{
		ProgramType: pt,
		Helper:      helper,
	}
}

// RequireMount creates a requirement that path is mounted with a filesystem
// whose superblock magic equals magic.
//
// Magic numbers live in golang.org/x/sys/unix (e.g. unix.BPF_FS_MAGIC,
// unix.TRACEFS_MAGIC, unix.CGROUP2_SUPER_MAGIC). Pass the raw value.
//
// Panics if path is empty or magic is zero. Both indicate API misuse: an
// empty path cannot be statfs'd, and a zero magic does not correspond to any
// known filesystem and would silently mismatch every real mount.
func RequireMount(path string, magic uint32) MountRequirement {
	if path == "" {
		panic("kfeatures.RequireMount: path must not be empty")
	}
	if magic == 0 {
		panic("kfeatures.RequireMount: magic must not be zero (use a constant from golang.org/x/sys/unix, e.g. unix.BPF_FS_MAGIC)")
	}
	return MountRequirement{Path: path, Magic: magic}
}

func (Feature) isRequirement()                  {}
func (FeatureGroup) isRequirement()             {}
func (ProgramTypeRequirement) isRequirement()   {}
func (MapTypeRequirement) isRequirement()       {}
func (ProgramHelperRequirement) isRequirement() {}
func (MountRequirement) isRequirement()         {}

type requirementSet struct {
	features       []Feature
	programTypes   []ebpf.ProgramType
	mapTypes       []ebpf.MapType
	programHelpers []ProgramHelperRequirement
	mounts         []MountRequirement
	minKernels     []MinKernelRequirement

	seenFeatures       map[Feature]struct{}
	seenProgramTypes   map[ebpf.ProgramType]struct{}
	seenMapTypes       map[ebpf.MapType]struct{}
	seenProgramHelpers map[ProgramHelperRequirement]struct{}
	seenMounts         map[MountRequirement]struct{}
	seenMinKernels     map[MinKernelRequirement]struct{}
}

func normalizeRequirements(required []Requirement) requirementSet {
	rs := requirementSet{
		seenFeatures:       map[Feature]struct{}{},
		seenProgramTypes:   map[ebpf.ProgramType]struct{}{},
		seenMapTypes:       map[ebpf.MapType]struct{}{},
		seenProgramHelpers: map[ProgramHelperRequirement]struct{}{},
		seenMounts:         map[MountRequirement]struct{}{},
		seenMinKernels:     map[MinKernelRequirement]struct{}{},
	}
	for _, req := range required {
		rs.add(req)
	}
	return rs
}

func (rs *requirementSet) add(req Requirement) {
	switch r := req.(type) {
	case Feature:
		if _, ok := rs.seenFeatures[r]; ok {
			return
		}
		rs.seenFeatures[r] = struct{}{}
		rs.features = append(rs.features, r)
	case FeatureGroup:
		for _, nested := range r {
			if nested == nil {
				continue
			}
			rs.add(nested)
		}
	case ProgramTypeRequirement:
		if _, ok := rs.seenProgramTypes[r.Type]; ok {
			return
		}
		rs.seenProgramTypes[r.Type] = struct{}{}
		rs.programTypes = append(rs.programTypes, r.Type)
	case MapTypeRequirement:
		if _, ok := rs.seenMapTypes[r.Type]; ok {
			return
		}
		rs.seenMapTypes[r.Type] = struct{}{}
		rs.mapTypes = append(rs.mapTypes, r.Type)
	case ProgramHelperRequirement:
		if _, ok := rs.seenProgramHelpers[r]; ok {
			return
		}
		rs.seenProgramHelpers[r] = struct{}{}
		rs.programHelpers = append(rs.programHelpers, r)
	case MountRequirement:
		if _, ok := rs.seenMounts[r]; ok {
			return
		}
		rs.seenMounts[r] = struct{}{}
		rs.mounts = append(rs.mounts, r)
	case MinKernelRequirement:
		if _, ok := rs.seenMinKernels[r]; ok {
			return
		}
		rs.seenMinKernels[r] = struct{}{}
		rs.minKernels = append(rs.minKernels, r)
	}
}
