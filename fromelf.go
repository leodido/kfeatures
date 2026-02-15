//go:build linux

package kfeatures

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
)

// FromELF derives workload requirements from an eBPF ELF object file.
//
// Contract:
//   - Signature: FromELF(path string) (FeatureGroup, error)
//   - Determinism: output is deduplicated and stably ordered
//   - v1 scope: extract only program-type and map-type requirements
//   - Unknown handling: fail closed (return error for unsupported/unknown kinds)
//
// Returned requirements are directly consumable by [Check].
func FromELF(path string) (FeatureGroup, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("from ELF: empty path")
	}

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("from ELF %q: load collection spec: %w", path, err)
	}

	reqs, err := requirementsFromCollectionSpec(spec)
	if err != nil {
		return nil, fmt.Errorf("from ELF %q: %w", path, err)
	}
	return reqs, nil
}

func requirementsFromCollectionSpec(spec *ebpf.CollectionSpec) (FeatureGroup, error) {
	if spec == nil {
		return nil, fmt.Errorf("nil collection spec")
	}

	seenProgramTypes := make(map[ebpf.ProgramType]struct{}, len(spec.Programs))
	seenMapTypes := make(map[ebpf.MapType]struct{}, len(spec.Maps))

	for name, prog := range spec.Programs {
		if prog == nil {
			return nil, fmt.Errorf("program %q: nil program spec", name)
		}
		if err := validateProgramType(prog.Type); err != nil {
			return nil, fmt.Errorf("program %q: %w", name, err)
		}
		seenProgramTypes[prog.Type] = struct{}{}
	}

	for name, m := range spec.Maps {
		if m == nil {
			return nil, fmt.Errorf("map %q: nil map spec", name)
		}
		if err := validateMapType(m.Type); err != nil {
			return nil, fmt.Errorf("map %q: %w", name, err)
		}
		seenMapTypes[m.Type] = struct{}{}
	}

	programTypes := make([]ebpf.ProgramType, 0, len(seenProgramTypes))
	for pt := range seenProgramTypes {
		programTypes = append(programTypes, pt)
	}
	slices.Sort(programTypes)

	mapTypes := make([]ebpf.MapType, 0, len(seenMapTypes))
	for mt := range seenMapTypes {
		mapTypes = append(mapTypes, mt)
	}
	slices.Sort(mapTypes)

	reqs := make(FeatureGroup, 0, len(programTypes)+len(mapTypes))
	for _, pt := range programTypes {
		reqs = append(reqs, RequireProgramType(pt))
	}
	for _, mt := range mapTypes {
		reqs = append(reqs, RequireMapType(mt))
	}

	return reqs, nil
}

func validateProgramType(pt ebpf.ProgramType) error {
	if pt == ebpf.UnspecifiedProgram {
		return fmt.Errorf("unsupported/unspecified program type")
	}
	if strings.HasPrefix(pt.String(), "ProgramType(") {
		return fmt.Errorf("unknown program type %d", pt)
	}
	return nil
}

func validateMapType(mt ebpf.MapType) error {
	if mt == ebpf.UnspecifiedMap {
		return fmt.Errorf("unsupported/unspecified map type")
	}
	if strings.HasPrefix(mt.String(), "MapType(") {
		return fmt.Errorf("unknown map type %d", mt)
	}
	return nil
}
