package kfeatures

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestSupersededHelperWarningsNil(t *testing.T) {
	if got := generateSupersededHelperWarnings(nil); got != nil {
		t.Errorf("nil receiver = %+v, want nil", got)
	}
	if got := generateSupersededHelperWarnings(&ELFProbes{}); got != nil {
		t.Errorf("empty programs = %+v, want nil", got)
	}
}

func TestSupersededHelperWarningsBindsViaInit(t *testing.T) {
	if supersededHelperWarnings == nil {
		t.Fatal("supersededHelperWarnings should be bound by init()")
	}
}

func TestSupersededHelperWarningsAllRules(t *testing.T) {
	probes := &ELFProbes{
		Programs: []ELFProgram{
			{
				Name:        "p1",
				Type:        ebpf.Kprobe.String(),
				ProgramType: ebpf.Kprobe,
				Helpers: []ELFHelperRequirement{
					{Name: asm.FnProbeRead.String(), Helper: asm.FnProbeRead},
					{Name: asm.FnProbeReadStr.String(), Helper: asm.FnProbeReadStr},
					{Name: asm.FnGetCurrentTask.String(), Helper: asm.FnGetCurrentTask},
					// A non-deprecated helper to confirm we don't warn on it.
					{Name: asm.FnMapLookupElem.String(), Helper: asm.FnMapLookupElem},
				},
			},
		},
	}
	got := generateSupersededHelperWarnings(probes)
	if len(got) != 3 {
		t.Fatalf("expected 3 warnings, got %d: %+v", len(got), got)
	}
	for _, w := range got {
		if w.Severity != "warning" {
			t.Errorf("severity = %q, want warning", w.Severity)
		}
		if w.Program != "p1" {
			t.Errorf("program = %q, want p1", w.Program)
		}
		if !strings.HasPrefix(w.Message, "uses deprecated helper ") {
			t.Errorf("message = %q", w.Message)
		}
		if w.Detail == "" {
			t.Error("detail should be set")
		}
	}
}

func TestLookupSupersededHelperUnknown(t *testing.T) {
	if _, ok := lookupSupersededHelper(asm.FnMapLookupElem); ok {
		t.Errorf("FnMapLookupElem should not match a superseded rule")
	}
}

func TestJoinReplacements(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"FnA"}, "FnA"},
		{[]string{"FnA", "FnB"}, "FnA or FnB"},
		{[]string{"FnA", "FnB", "FnC"}, "FnA, FnB or FnC"},
		{[]string{"FnA", "FnB", "FnC", "FnD"}, "FnA, FnB, FnC or FnD"},
	}
	for _, tc := range cases {
		if got := joinReplacements(tc.in); got != tc.want {
			t.Errorf("joinReplacements(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSupersededWarningIntegration(t *testing.T) {
	// A program that calls bpf_probe_read should produce a warning when
	// the full ELFProbes view is built.
	insns := asm.Instructions{
		asm.LoadImm(asm.R1, 0, asm.DWord),
		asm.FnProbeRead.Call(),
		asm.Return(),
	}
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"oldprog": {
				Name:         "oldprog",
				Type:         ebpf.Kprobe,
				License:      "GPL",
				Instructions: insns,
			},
		},
	}
	got, err := probesFromCollectionSpec(spec, &elfProbeConfig{})
	if err != nil {
		t.Fatalf("probesFromCollectionSpec: %v", err)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %+v", len(got.Warnings), got.Warnings)
	}
	w := got.Warnings[0]
	if !strings.Contains(w.Message, "bpf_probe_read") && !strings.Contains(w.Message, "FnProbeRead") {
		t.Errorf("warning message = %q", w.Message)
	}
}
