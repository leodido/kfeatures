//go:build !linux

package kfeatures

import "github.com/cilium/ebpf"

// probeConfig holds the configuration for a probe operation.
// On non-Linux platforms this is a no-op placeholder.
type probeConfig struct{}

// ProbeOption configures what [ProbeWith] collects for diagnostics/reporting.
type ProbeOption func(*probeConfig)

func ProbeWith(_ ...ProbeOption) (*SystemFeatures, error) {
	return nil, ErrUnsupportedPlatform
}

func Probe() (*SystemFeatures, error) {
	return nil, ErrUnsupportedPlatform
}

func ProbeNoCache() (*SystemFeatures, error) {
	return nil, ErrUnsupportedPlatform
}

func ResetCache() {}

func WithProgramTypes(_ ...ebpf.ProgramType) ProbeOption { return func(*probeConfig) {} }
func WithSecuritySubsystems() ProbeOption                { return func(*probeConfig) {} }
func WithKernelConfig() ProbeOption                      { return func(*probeConfig) {} }
func WithCapabilities() ProbeOption                      { return func(*probeConfig) {} }
func WithJIT() ProbeOption                               { return func(*probeConfig) {} }
func WithSyscalls() ProbeOption                          { return func(*probeConfig) {} }
func WithNamespaces() ProbeOption                        { return func(*probeConfig) {} }
func WithMitigations() ProbeOption                       { return func(*probeConfig) {} }
func WithFilesystems() ProbeOption                       { return func(*probeConfig) {} }
func WithLSMPath(_ string) ProbeOption                   { return func(*probeConfig) {} }
func WithAll() ProbeOption                               { return func(*probeConfig) {} }
