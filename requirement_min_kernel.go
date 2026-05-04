package kfeatures

import (
	"fmt"
	"strconv"
	"strings"
)

// MinKernelRequirement requires the running kernel to be at least
// Major.Minor.
//
// MinKernelRequirement is the gating counterpart of [ELFProbes.MinKernel]:
// callers that already derived a minimum kernel version from an ELF (or
// from any other source) can drop the value into [Check] without manually
// translating it into a helper / program-type / map-type set.
//
// Patch level is intentionally absent: BPF feature introductions are
// always pinned at major.minor in upstream documentation.
type MinKernelRequirement struct {
	Major int
	Minor int
}

// RequireMinKernel creates a MinKernelRequirement gating on the supplied
// major.minor pair.
//
// Panics if either operand is negative; both indicate API misuse.
func RequireMinKernel(major, minor int) MinKernelRequirement {
	if major < 0 || minor < 0 {
		panic("kfeatures.RequireMinKernel: major and minor must be non-negative")
	}
	return MinKernelRequirement{Major: major, Minor: minor}
}

// String renders the requirement as "kernel >= major.minor".
func (r MinKernelRequirement) String() string {
	return fmt.Sprintf("kernel >= %d.%d", r.Major, r.Minor)
}

func (MinKernelRequirement) isRequirement() {}

// satisfiedBy reports whether release (a uname -r string) is >= the
// requirement's major.minor. Releases that fail to parse are reported as
// unsatisfied with an explanatory error.
func (r MinKernelRequirement) satisfiedBy(release string) error {
	gotMajor, gotMinor, err := parseKernelRelease(release)
	if err != nil {
		return fmt.Errorf("could not parse running kernel release %q: %w", release, err)
	}
	if gotMajor > r.Major {
		return nil
	}
	if gotMajor == r.Major && gotMinor >= r.Minor {
		return nil
	}
	return fmt.Errorf("running kernel %d.%d is older than required %d.%d", gotMajor, gotMinor, r.Major, r.Minor)
}

// parseKernelRelease extracts the leading major.minor from a uname -r
// string. Accepts "6.1", "6.1.0", "6.1.0-generic", "6.1.0-1.el9.x86_64".
func parseKernelRelease(release string) (int, int, error) {
	release = strings.TrimSpace(release)
	if release == "" {
		return 0, 0, fmt.Errorf("empty release string")
	}
	// Trim trailing build qualifiers after a '-' so "6.1.0-generic" parses.
	if i := strings.IndexByte(release, '-'); i >= 0 {
		release = release[:i]
	}
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("missing minor version separator")
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major: %w", err)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor: %w", err)
	}
	if maj < 0 || min < 0 {
		return 0, 0, fmt.Errorf("negative version components")
	}
	return maj, min, nil
}
