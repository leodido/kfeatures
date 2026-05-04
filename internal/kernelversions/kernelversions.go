// Package kernelversions exposes the minimum kernel version at which each
// eBPF helper, program type and map type was introduced.
//
// The lookup tables in this package are generated from the BCC project's
// kernel-versions.md document at a pinned commit, cross-validated against
// the libbpf UAPI enum in include/uapi/linux/bpf.h at a pinned commit. The
// generator lives in cmd/kvgen.
//
// Consumers must treat the data as a snapshot, not as a real-time source of
// truth. The repository's scheduled CI workflow refreshes the snapshot by
// opening a PR when upstream changes.
package kernelversions

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// KernelVersion is a major.minor Linux kernel version.
//
// Patch level is intentionally omitted: BPF feature introductions are
// always pinned at major.minor in BCC's table and in the kernel commit
// log, and surfacing patch-level would imply false precision.
type KernelVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// Less reports whether v is older than other.
func (v KernelVersion) Less(other KernelVersion) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	return v.Minor < other.Minor
}

// IsZero reports whether v is the zero value.
func (v KernelVersion) IsZero() bool {
	return v.Major == 0 && v.Minor == 0
}

// String renders v as "major.minor".
func (v KernelVersion) String() string {
	return itoa(v.Major) + "." + itoa(v.Minor)
}

// Max returns the maximum of two KernelVersion values.
func Max(a, b KernelVersion) KernelVersion {
	if a.Less(b) {
		return b
	}
	return a
}

// HelperKernelVersion returns the kernel version that introduced the
// helper, and a boolean reporting whether the lookup succeeded.
func HelperKernelVersion(fn asm.BuiltinFunc) (KernelVersion, bool) {
	v, ok := HelperVersion[fn]
	return v, ok
}

// MapTypeKernelVersion returns the kernel version that introduced the
// map type, and a boolean reporting whether the lookup succeeded.
func MapTypeKernelVersion(mt ebpf.MapType) (KernelVersion, bool) {
	v, ok := MapTypeVersion[mt]
	return v, ok
}

// ProgramTypeKernelVersion returns the kernel version that introduced
// the program type, and a boolean reporting whether the lookup succeeded.
func ProgramTypeKernelVersion(pt ebpf.ProgramType) (KernelVersion, bool) {
	v, ok := ProgTypeVersion[pt]
	return v, ok
}

// itoa is a tiny strconv.Itoa replacement to keep this file dependency-free
// at package load time. Inputs are always small non-negative integers.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
