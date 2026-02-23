package main

import (
	"strings"
	"testing"

	"github.com/leodido/kfeatures"
	"github.com/spf13/cobra"
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

func TestCheckOptionsCompleteRequire(t *testing.T) {
	opts := &CheckOptions{}

	t.Run("empty input returns feature candidates", func(t *testing.T) {
		got, directive := opts.CompleteRequire(nil, nil, "")
		if len(got) == 0 {
			t.Fatal("expected non-empty candidates")
		}
		if got[0] != kfeatures.FeatureNames()[0] {
			t.Fatalf("first candidate = %q, want %q", got[0], kfeatures.FeatureNames()[0])
		}
		if directive != cobra.ShellCompDirectiveNoFileComp|cobra.ShellCompDirectiveNoSpace {
			t.Fatalf("directive = %v, want %v", directive, cobra.ShellCompDirectiveNoFileComp|cobra.ShellCompDirectiveNoSpace)
		}
	})

	t.Run("prefix filter is case-insensitive", func(t *testing.T) {
		got, _ := opts.CompleteRequire(nil, nil, "BPF-S")
		if len(got) == 0 {
			t.Fatal("expected filtered candidates")
		}
		for _, c := range got {
			if !strings.HasPrefix(c, "bpf-s") {
				t.Fatalf("candidate %q does not match expected prefix", c)
			}
		}
	})

	t.Run("comma-separated completion prefixes and avoids duplicates", func(t *testing.T) {
		got, _ := opts.CompleteRequire(nil, nil, "BPF-SYSCALL,tr")
		if len(got) == 0 {
			t.Fatal("expected comma-separated candidates")
		}
		for _, c := range got {
			if !strings.HasPrefix(c, "BPF-SYSCALL,") {
				t.Fatalf("candidate %q missing expected prefix", c)
			}
			if strings.EqualFold(c, "BPF-SYSCALL,bpf-syscall") {
				t.Fatalf("duplicate selected feature suggested: %q", c)
			}
		}
	})
}
