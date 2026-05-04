package main

import (
	"strings"
	"testing"

	"github.com/leodido/kfeatures"
)

func TestAssembleCheckRequirementsEmpty(t *testing.T) {
	_, err := assembleCheckRequirements(&CheckOptions{})
	if err == nil {
		t.Fatal("expected error when neither --require nor --from-elf is set")
	}
	if !strings.Contains(err.Error(), "no features specified") {
		t.Errorf("error = %v", err)
	}
}

func TestAssembleCheckRequirementsRequireOnly(t *testing.T) {
	got, err := assembleCheckRequirements(&CheckOptions{
		Require: featureRequirements{kfeatures.FeatureBPFSyscall},
	})
	if err != nil {
		t.Fatalf("assembleCheckRequirements: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

func TestAssembleCheckRequirementsFromELFParseError(t *testing.T) {
	_, err := assembleCheckRequirements(&CheckOptions{
		FromELF: "/nonexistent/path/missing.bpf.o",
	})
	if err == nil {
		t.Fatal("expected error on missing ELF")
	}
	if !strings.Contains(err.Error(), "from-elf") {
		t.Errorf("error = %v, want from-elf wrapper", err)
	}
}
