package main

import (
	"fmt"
	"sort"
	"strings"
)

// validate asserts that every UAPI helper / program-type / map-type enum
// value present in the kernel header has a matching row in the BCC table.
//
// Missing entries fail generation with a clear list so that maintainers
// notice when upstream adds a new enum value before BCC documents it.
//
// Extra entries in BCC (with no matching UAPI symbol) are silently
// tolerated: BCC sometimes documents in-kernel-only types or aliases that
// never made it to UAPI. Those rows do not break a build, only the missing
// direction does.
func validate(bcc *bccTables, uapi *uapiSets) error {
	var problems []string

	// Helpers: BCC keys are lowercase suffixes (without BPF_FUNC_).
	missingHelpers := []string{}
	for fn := range uapi.Helpers {
		if _, ok := bcc.Helpers[fn]; !ok {
			if _, allowed := allowedMissingHelpers[fn]; allowed {
				continue
			}
			missingHelpers = append(missingHelpers, fn)
		}
	}
	if len(missingHelpers) > 0 {
		sort.Strings(missingHelpers)
		problems = append(problems,
			fmt.Sprintf("UAPI helpers absent from BCC table:\n  - BPF_FUNC_%s",
				strings.Join(missingHelpers, "\n  - BPF_FUNC_")))
	}

	missingProgTypes := []string{}
	for pt := range uapi.ProgramTypes {
		if _, ok := bcc.ProgramTypes[pt]; !ok {
			if _, allowed := allowedMissingProgTypes[pt]; allowed {
				continue
			}
			missingProgTypes = append(missingProgTypes, pt)
		}
	}
	if len(missingProgTypes) > 0 {
		sort.Strings(missingProgTypes)
		problems = append(problems,
			fmt.Sprintf("UAPI program types absent from BCC table:\n  - %s",
				strings.Join(missingProgTypes, "\n  - ")))
	}

	missingMapTypes := []string{}
	for mt := range uapi.MapTypes {
		if _, ok := bcc.MapTypes[mt]; !ok {
			if _, allowed := allowedMissingMapTypes[mt]; allowed {
				continue
			}
			missingMapTypes = append(missingMapTypes, mt)
		}
	}
	if len(missingMapTypes) > 0 {
		sort.Strings(missingMapTypes)
		problems = append(problems,
			fmt.Sprintf("UAPI map types absent from BCC table:\n  - %s",
				strings.Join(missingMapTypes, "\n  - ")))
	}

	if len(problems) > 0 {
		return fmt.Errorf("cross-validation failed:\n\n%s", strings.Join(problems, "\n\n"))
	}
	return nil
}
