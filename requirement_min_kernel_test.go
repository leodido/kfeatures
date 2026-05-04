package kfeatures

import (
	"strings"
	"testing"
)

func TestRequireMinKernel(t *testing.T) {
	r := RequireMinKernel(5, 8)
	if r != (MinKernelRequirement{Major: 5, Minor: 8}) {
		t.Errorf("RequireMinKernel = %+v", r)
	}
	if r.String() != "kernel >= 5.8" {
		t.Errorf("String() = %q", r.String())
	}
}

func TestRequireMinKernelNegativePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on negative major")
		}
	}()
	RequireMinKernel(-1, 0)
}

func TestRequireMinKernelNegativeMinorPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on negative minor")
		}
	}()
	RequireMinKernel(5, -1)
}

func TestMinKernelSatisfiedBy(t *testing.T) {
	r := MinKernelRequirement{Major: 5, Minor: 8}
	cases := []struct {
		release string
		ok      bool
	}{
		{"6.1.0-generic", true},
		{"5.8.0", true},
		{"5.8", true},
		{"5.10.0", true},
		{"5.7.0", false},
		{"4.19.300-1.el7", false},
		{"6.0.0-1.el9.x86_64", true},
	}
	for _, tc := range cases {
		err := r.satisfiedBy(tc.release)
		if tc.ok && err != nil {
			t.Errorf("satisfiedBy(%q) returned err: %v", tc.release, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("satisfiedBy(%q) returned nil, want err", tc.release)
		}
	}
}

func TestMinKernelSatisfiedByParseErrors(t *testing.T) {
	r := MinKernelRequirement{Major: 5, Minor: 8}
	cases := []string{
		"",
		"   ",
		"abc",
		"5",
		"5.x",
		"x.5",
	}
	for _, in := range cases {
		err := r.satisfiedBy(in)
		if err == nil {
			t.Errorf("satisfiedBy(%q) expected error, got nil", in)
			continue
		}
		if !strings.Contains(err.Error(), "could not parse running kernel release") {
			t.Errorf("satisfiedBy(%q) error = %v, want parse-error wrapper", in, err)
		}
	}
}

func TestParseKernelRelease(t *testing.T) {
	cases := []struct {
		in        string
		major     int
		minor     int
		ok        bool
	}{
		{"6.1.0", 6, 1, true},
		{"6.1", 6, 1, true},
		{"6.1.0-generic", 6, 1, true},
		{"6.1.0-1.el9.x86_64", 6, 1, true},
		{"6.1-rc1", 6, 1, true},
		{"  5.10.0  ", 5, 10, true},
		{"", 0, 0, false},
		{"abc", 0, 0, false},
		{"5", 0, 0, false},
		{"5.x", 0, 0, false},
		{"x.5", 0, 0, false},
	}
	for _, tc := range cases {
		major, minor, err := parseKernelRelease(tc.in)
		if tc.ok {
			if err != nil {
				t.Errorf("parseKernelRelease(%q) err: %v", tc.in, err)
				continue
			}
			if major != tc.major || minor != tc.minor {
				t.Errorf("parseKernelRelease(%q) = (%d, %d), want (%d, %d)", tc.in, major, minor, tc.major, tc.minor)
			}
		} else if err == nil {
			t.Errorf("parseKernelRelease(%q) expected err", tc.in)
		}
	}
}

func TestMinKernelRequirementImplementsRequirement(t *testing.T) {
	var _ Requirement = MinKernelRequirement{}
	var _ Requirement = RequireMinKernel(5, 8)
}

func TestMinKernelDedupedInRequirementSet(t *testing.T) {
	rs := normalizeRequirements([]Requirement{
		RequireMinKernel(5, 8),
		RequireMinKernel(5, 8), // dup
		RequireMinKernel(6, 0),
	})
	if len(rs.minKernels) != 2 {
		t.Errorf("expected 2 minKernels after dedup, got %d", len(rs.minKernels))
	}
}
