//go:build linux && (386 || arm || mips || mipsle)

package kfeatures

import "golang.org/x/sys/unix"

// setStatfsType assigns magic to st.Type on architectures where the kernel
// exposes f_type as a 32-bit signed integer.
func setStatfsType(st *unix.Statfs_t, magic uint32) {
	st.Type = int32(magic)
}
