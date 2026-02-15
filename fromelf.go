package kfeatures

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// FromELF derives workload requirements from an eBPF ELF object file.
//
// Contract:
//   - Signature: FromELF(path string) (FeatureGroup, error)
//   - Determinism: output is deduplicated and stably ordered
//   - Scope: extract program/map requirements and helper-per-program requirements
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
	seenProgramHelpers := make(map[ProgramHelperRequirement]struct{})

	for name, prog := range spec.Programs {
		if prog == nil {
			return nil, fmt.Errorf("program %q: nil program spec", name)
		}
		if err := validateProgramType(prog.Type); err != nil {
			return nil, fmt.Errorf("program %q: %w", name, err)
		}
		seenProgramTypes[prog.Type] = struct{}{}

		for _, ins := range prog.Instructions {
			if !ins.IsBuiltinCall() {
				continue
			}
			helper, err := helperFromInstruction(ins)
			if err != nil {
				return nil, fmt.Errorf("program %q: %w", name, err)
			}
			if err := validateProgramHelper(helper); err != nil {
				return nil, fmt.Errorf("program %q: %w", name, err)
			}
			seenProgramHelpers[RequireProgramHelper(prog.Type, helper)] = struct{}{}
		}
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

	programHelpers := make([]ProgramHelperRequirement, 0, len(seenProgramHelpers))
	for req := range seenProgramHelpers {
		programHelpers = append(programHelpers, req)
	}
	slices.SortFunc(programHelpers, func(a, b ProgramHelperRequirement) int {
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

	reqs := make(FeatureGroup, 0, len(programTypes)+len(mapTypes)+len(programHelpers))
	for _, pt := range programTypes {
		reqs = append(reqs, RequireProgramType(pt))
	}
	for _, mt := range mapTypes {
		reqs = append(reqs, RequireMapType(mt))
	}
	for _, req := range programHelpers {
		reqs = append(reqs, req)
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

func helperFromInstruction(ins asm.Instruction) (asm.BuiltinFunc, error) {
	if ins.Constant < 0 || ins.Constant > int64(^uint32(0)) {
		return 0, fmt.Errorf("invalid helper ID %d", ins.Constant)
	}
	return asm.BuiltinFunc(uint32(ins.Constant)), nil
}

func validateProgramHelper(helper asm.BuiltinFunc) error {
	if helper == asm.FnUnspec {
		return fmt.Errorf("unsupported/unspecified helper")
	}
	if strings.HasPrefix(helper.String(), "BuiltinFunc(") {
		return fmt.Errorf("unknown helper %d", helper)
	}
	return nil
}
