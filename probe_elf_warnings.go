package kfeatures

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// supersededHelperRule names a deprecated/superseded helper and the
// preferred replacements with the kernel version those replacements
// landed in.
type supersededHelperRule struct {
	deprecated   asm.BuiltinFunc
	replacements []string
	since        string // human-readable kernel version where replacements landed
	rationale    string // one-line motivation
}

// supersededHelperRules enumerates the deprecated helpers we surface as
// always-on warnings. The list is intentionally small; new entries
// require an upstream citation in the PR description so reviewers can
// audit the rationale.
var supersededHelperRules = []supersededHelperRule{
	{
		deprecated:   asm.FnProbeRead,
		replacements: []string{"FnProbeReadKernel", "FnProbeReadUser"},
		since:        "5.5",
		rationale:    "bpf_probe_read does not distinguish kernel vs user address space; use the explicit per-space variants",
	},
	{
		deprecated:   asm.FnProbeReadStr,
		replacements: []string{"FnProbeReadKernelStr", "FnProbeReadUserStr"},
		since:        "5.5",
		rationale:    "bpf_probe_read_str does not distinguish kernel vs user address space; use the explicit per-space variants",
	},
	{
		deprecated:   asm.FnGetCurrentTask,
		replacements: []string{"FnGetCurrentTaskBtf"},
		since:        "5.11",
		rationale:    "bpf_get_current_task returns an opaque pointer; the BTF variant returns a typed struct task_struct",
	},
}

func init() {
	// Bind the always-on warning generator now that the rules are
	// declared. Keeping this as a var assignment in init() (rather than
	// at package scope) lets tests stub supersededHelperWarnings without
	// import-cycle gymnastics.
	supersededHelperWarnings = generateSupersededHelperWarnings
}

// generateSupersededHelperWarnings returns one ELFWarning per deprecated
// helper detected in out.Programs, scoped per-program so that the user
// sees which call site needs attention.
func generateSupersededHelperWarnings(out *ELFProbes) []ELFWarning {
	if out == nil || len(out.Programs) == 0 {
		return nil
	}
	var warnings []ELFWarning
	for _, prog := range out.Programs {
		for _, h := range prog.Helpers {
			rule, ok := lookupSupersededHelper(h.Helper)
			if !ok {
				continue
			}
			warnings = append(warnings, ELFWarning{
				Severity: "warning",
				Program:  prog.Name,
				Message:  fmt.Sprintf("uses deprecated helper %s", h.Name),
				Detail:   fmt.Sprintf("prefer %s (since %s); %s", joinReplacements(rule.replacements), rule.since, rule.rationale),
			})
		}
	}
	return warnings
}

func lookupSupersededHelper(fn asm.BuiltinFunc) (supersededHelperRule, bool) {
	for _, r := range supersededHelperRules {
		if r.deprecated == fn {
			return r, true
		}
	}
	return supersededHelperRule{}, false
}

func joinReplacements(rs []string) string {
	switch len(rs) {
	case 0:
		return ""
	case 1:
		return rs[0]
	case 2:
		return rs[0] + " or " + rs[1]
	}
	out := rs[0]
	for i := 1; i < len(rs)-1; i++ {
		out += ", " + rs[i]
	}
	return out + " or " + rs[len(rs)-1]
}
