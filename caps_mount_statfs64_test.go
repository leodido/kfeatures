//go:build linux && (amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le || riscv64 || s390x || loong64)

package kfeatures

import "golang.org/x/sys/unix"

// setStatfsType assigns magic to st.Type on architectures where the kernel
// exposes f_type as a 64-bit signed integer.
func setStatfsType(st *unix.Statfs_t, magic uint32) {
	st.Type = int64(magic)
}
