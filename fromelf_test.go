package kfeatures

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestRequirementsFromCollectionSpec_DedupAndStableOrder(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"p2": {Type: ebpf.XDP},
			"p1": {Type: ebpf.Kprobe},
			"p3": {Type: ebpf.Kprobe}, // duplicate
		},
		Maps: map[string]*ebpf.MapSpec{
			"m2": {Type: ebpf.Array},
			"m1": {Type: ebpf.Hash},
			"m3": {Type: ebpf.Array}, // duplicate
		},
	}

	got, err := requirementsFromCollectionSpec(spec)
	if err != nil {
		t.Fatalf("requirementsFromCollectionSpec() error = %v", err)
	}

	want := FeatureGroup{
		RequireProgramType(ebpf.Kprobe),
		RequireProgramType(ebpf.XDP),
		RequireMapType(ebpf.Hash),
		RequireMapType(ebpf.Array),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requirementsFromCollectionSpec() = %#v, want %#v", got, want)
	}
}

func TestRequirementsFromCollectionSpec_FailClosedUnknownKinds(t *testing.T) {
	t.Run("unspecified program type", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"bad-prog": {Type: ebpf.UnspecifiedProgram},
			},
		}
		_, err := requirementsFromCollectionSpec(spec)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), `program "bad-prog": unsupported/unspecified program type`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unknown map type", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{
				"bad-map": {Type: ebpf.MapType(999999)},
			},
		}
		_, err := requirementsFromCollectionSpec(spec)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), `map "bad-map": unknown map type`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unknown program type", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"bad-prog": {Type: ebpf.ProgramType(999999)},
			},
		}
		_, err := requirementsFromCollectionSpec(spec)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), `program "bad-prog": unknown program type`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRequirementsFromCollectionSpec_NilEntities(t *testing.T) {
	t.Run("nil collection spec", func(t *testing.T) {
		_, err := requirementsFromCollectionSpec(nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "nil collection spec") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil program spec", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"nil-prog": nil,
			},
		}
		_, err := requirementsFromCollectionSpec(spec)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), `program "nil-prog": nil program spec`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil map spec", func(t *testing.T) {
		spec := &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{
				"nil-map": nil,
			},
		}
		_, err := requirementsFromCollectionSpec(spec)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), `map "nil-map": nil map spec`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestFromELF_PathValidationAndParseErrors(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		_, err := FromELF("   ")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "empty path") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := FromELF(filepath.Join(t.TempDir(), "missing.o"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "load collection spec") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid ELF", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "invalid.o")
		if err := os.WriteFile(path, []byte("not an ELF"), 0644); err != nil {
			t.Fatalf("write invalid file: %v", err)
		}
		_, err := FromELF(path)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "load collection spec") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
