//go:build linux

package kfeatures

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Requirement describes a gate condition consumable by [Check].
//
// Built-in implementations include:
//   - [Feature]
//   - [FeatureGroup]
//   - [ProgramTypeRequirement]
//   - [MapTypeRequirement]
//   - [ProgramHelperRequirement]
type Requirement interface {
	isRequirement()
}

// FeatureGroup is a reusable set of [Requirement] items.
//
// Groups can include simple [Feature] values and parameterized requirements.
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

func (Feature) isRequirement()                  {}
func (FeatureGroup) isRequirement()             {}
func (ProgramTypeRequirement) isRequirement()   {}
func (MapTypeRequirement) isRequirement()       {}
func (ProgramHelperRequirement) isRequirement() {}

type requirementSet struct {
	features       []Feature
	programTypes   []ebpf.ProgramType
	mapTypes       []ebpf.MapType
	programHelpers []ProgramHelperRequirement

	seenFeatures       map[Feature]struct{}
	seenProgramTypes   map[ebpf.ProgramType]struct{}
	seenMapTypes       map[ebpf.MapType]struct{}
	seenProgramHelpers map[ProgramHelperRequirement]struct{}
}

func normalizeRequirements(required []Requirement) requirementSet {
	rs := requirementSet{
		seenFeatures:       map[Feature]struct{}{},
		seenProgramTypes:   map[ebpf.ProgramType]struct{}{},
		seenMapTypes:       map[ebpf.MapType]struct{}{},
		seenProgramHelpers: map[ProgramHelperRequirement]struct{}{},
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
	}
}
