package kernelversions

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestKernelVersion(t *testing.T) {
	a := KernelVersion{Major: 5, Minor: 8}
	b := KernelVersion{Major: 5, Minor: 10}
	c := KernelVersion{Major: 6, Minor: 0}
	if !a.Less(b) {
		t.Errorf("5.8 should be less than 5.10")
	}
	if !b.Less(c) {
		t.Errorf("5.10 should be less than 6.0")
	}
	if a.Less(a) {
		t.Errorf("5.8 should not be less than itself")
	}
	if c.Less(b) {
		t.Errorf("6.0 should not be less than 5.10")
	}
	if !(KernelVersion{}).IsZero() {
		t.Errorf("zero value should be IsZero")
	}
	if a.IsZero() {
		t.Errorf("5.8 should not be IsZero")
	}
	if got := a.String(); got != "5.8" {
		t.Errorf("String() = %q, want %q", got, "5.8")
	}
	if got := (KernelVersion{Major: 5, Minor: 19}).String(); got != "5.19" {
		t.Errorf("String() = %q, want %q", got, "5.19")
	}
	if got := (KernelVersion{}).String(); got != "0.0" {
		t.Errorf("zero String() = %q, want %q", got, "0.0")
	}
}

func TestMax(t *testing.T) {
	a := KernelVersion{Major: 5, Minor: 8}
	b := KernelVersion{Major: 4, Minor: 10}
	if got := Max(a, b); got != a {
		t.Errorf("Max(5.8, 4.10) = %v, want %v", got, a)
	}
	if got := Max(b, a); got != a {
		t.Errorf("Max(4.10, 5.8) = %v, want %v", got, a)
	}
	if got := Max(a, a); got != a {
		t.Errorf("Max(a, a) = %v, want %v", got, a)
	}
}

func TestHelperKernelVersion(t *testing.T) {
	// Bind helper introduced in 4.17 per the snapshot.
	v, ok := HelperKernelVersion(asm.FnBind)
	if !ok {
		t.Fatalf("FnBind not in HelperVersion table")
	}
	if v != (KernelVersion{Major: 4, Minor: 17}) {
		t.Errorf("FnBind version = %v, want 4.17", v)
	}
}

func TestMapTypeKernelVersion(t *testing.T) {
	v, ok := MapTypeKernelVersion(ebpf.RingBuf)
	if !ok {
		t.Fatalf("RingBuf not in MapTypeVersion table")
	}
	if v != (KernelVersion{Major: 5, Minor: 8}) {
		t.Errorf("RingBuf version = %v, want 5.8", v)
	}
}

func TestProgramTypeKernelVersion(t *testing.T) {
	v, ok := ProgramTypeKernelVersion(ebpf.Kprobe)
	if !ok {
		t.Fatalf("Kprobe not in ProgTypeVersion table")
	}
	if v != (KernelVersion{Major: 4, Minor: 1}) {
		t.Errorf("Kprobe version = %v, want 4.1", v)
	}
}
