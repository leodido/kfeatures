//go:build !linux

package kfeatures

// ErrNoKernelConfig is returned when no kernel config source is available.
// On non-Linux platforms, kernel config is never available.
var ErrNoKernelConfig = ErrUnsupportedPlatform
