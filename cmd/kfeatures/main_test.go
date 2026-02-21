package main

import (
	"strings"
	"testing"

	"github.com/leodido/kfeatures"
)

func TestParseFeatureRequirements_CaseInsensitive(t *testing.T) {
	got, err := parseFeatureRequirements(" BPF-SYSCALL, ima, Trace-FS ")
	if err != nil {
		t.Fatalf("parseFeatureRequirements() error = %v", err)
	}

	want := featureRequirements{
		kfeatures.FeatureBPFSyscall,
		kfeatures.FeatureIMA,
		kfeatures.FeatureTraceFS,
	}

	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseFeatureRequirements_UnknownFeature(t *testing.T) {
	_, err := parseFeatureRequirements("ciao")
	if err == nil {
		t.Fatal("parseFeatureRequirements(ciao) expected error")
	}

	msg := err.Error()
	if !strings.Contains(msg, `unknown feature: "ciao"`) {
		t.Fatalf("error %q missing unknown feature context", msg)
	}
	if !strings.Contains(msg, "available:") {
		t.Fatalf("error %q missing available features", msg)
	}
}

func TestFeatureRequirementsString(t *testing.T) {
	r := featureRequirements{
		kfeatures.FeatureIMA,
		kfeatures.FeatureBPFSyscall,
	}
	if got, want := r.String(), "ima,bpf-syscall"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestCheckLongDescription_UsesEnumNames(t *testing.T) {
	desc := checkLongDescription()
	if !strings.Contains(desc, "Available features:") {
		t.Fatalf("checkLongDescription() missing header: %q", desc)
	}

	for _, name := range kfeatures.FeatureNames() {
		if !strings.Contains(desc, name) {
			t.Fatalf("checkLongDescription() missing feature %q", name)
		}
	}
}
