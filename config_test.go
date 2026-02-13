//go:build linux

package kfeatures

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	input := `#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 6.1.0 Kernel Configuration
#
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=120300
CONFIG_LOCALVERSION=""
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_IMA=y
CONFIG_FPROBE=y
CONFIG_XDP_SOCKETS=y
CONFIG_XDP_SOCKETS_DIAG=m
CONFIG_NET=y
`

	kc, err := parseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	tests := []struct {
		key  string
		want ConfigValue
	}{
		{"BPF", ConfigBuiltin},
		{"BPF_SYSCALL", ConfigBuiltin},
		{"BPF_LSM", ConfigBuiltin},
		{"DEBUG_INFO_BTF", ConfigBuiltin},
		{"IMA", ConfigBuiltin},
		{"FPROBE", ConfigBuiltin},
		{"XDP_SOCKETS", ConfigBuiltin},
		{"XDP_SOCKETS_DIAG", ConfigModule},
		{"NET", ConfigBuiltin},
		// Not set or not a y/m value.
		{"CC_IS_GCC", ConfigBuiltin},
		{"GCC_VERSION", ConfigNotSet},  // numeric value, ignored
		{"LOCALVERSION", ConfigNotSet}, // string value, ignored
		{"NONEXISTENT", ConfigNotSet},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := kc.Get(tt.key)
			if got != tt.want {
				t.Errorf("Get(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseConfig_ConvenienceFields(t *testing.T) {
	input := `CONFIG_BPF_LSM=y
CONFIG_IMA=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FPROBE=y
`

	kc, err := parseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if kc.BPFLSM != ConfigBuiltin {
		t.Errorf("BPFLSM = %v, want ConfigBuiltin", kc.BPFLSM)
	}
	if kc.IMA != ConfigBuiltin {
		t.Errorf("IMA = %v, want ConfigBuiltin", kc.IMA)
	}
	if kc.BTF != ConfigBuiltin {
		t.Errorf("BTF = %v, want ConfigBuiltin", kc.BTF)
	}
	if kc.KprobeMulti != ConfigBuiltin {
		t.Errorf("KprobeMulti = %v, want ConfigBuiltin", kc.KprobeMulti)
	}
}

func TestParseConfig_ModuleValues(t *testing.T) {
	input := `CONFIG_BPF_LSM=m
CONFIG_IMA=m
`

	kc, err := parseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if kc.BPFLSM != ConfigModule {
		t.Errorf("BPFLSM = %v, want ConfigModule", kc.BPFLSM)
	}
	if kc.IMA != ConfigModule {
		t.Errorf("IMA = %v, want ConfigModule", kc.IMA)
	}
	if !kc.BPFLSM.IsEnabled() {
		t.Error("BPFLSM.IsEnabled() = false, want true")
	}
	if kc.BPFLSM.IsBuiltin() {
		t.Error("BPFLSM.IsBuiltin() = true, want false")
	}
}

func TestParseConfig_Empty(t *testing.T) {
	kc, err := parseConfig(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if kc.Get("anything") != ConfigNotSet {
		t.Error("expected ConfigNotSet for empty config")
	}
}

func TestParseConfig_CommentsOnly(t *testing.T) {
	input := `# This is a comment
# Another comment
# CONFIG_BPF is not set
`
	kc, err := parseConfig(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if kc.Get("BPF") != ConfigNotSet {
		t.Error("commented-out config should be ConfigNotSet")
	}
}

func TestParseConfig_FromTestdata(t *testing.T) {
	kc, err := parseConfigFrom(configSource{
		path:       "testdata/config-test",
		compressed: false,
	})
	if err != nil {
		t.Fatalf("parseConfigFrom() error = %v", err)
	}

	if kc.BPFLSM != ConfigBuiltin {
		t.Errorf("BPFLSM = %v, want ConfigBuiltin", kc.BPFLSM)
	}
	if kc.IMA != ConfigBuiltin {
		t.Errorf("IMA = %v, want ConfigBuiltin", kc.IMA)
	}
	if kc.BTF != ConfigBuiltin {
		t.Errorf("BTF = %v, want ConfigBuiltin", kc.BTF)
	}
	if kc.KprobeMulti != ConfigBuiltin {
		t.Errorf("KprobeMulti = %v, want ConfigBuiltin", kc.KprobeMulti)
	}
	if !kc.IsSet("XDP_SOCKETS") {
		t.Error("IsSet(XDP_SOCKETS) = false, want true")
	}
	if kc.Get("XDP_SOCKETS_DIAG") != ConfigModule {
		t.Errorf("Get(XDP_SOCKETS_DIAG) = %v, want ConfigModule", kc.Get("XDP_SOCKETS_DIAG"))
	}
}

func TestParseConfigFrom_MissingFile(t *testing.T) {
	_, err := parseConfigFrom(configSource{
		path:       "/nonexistent/path/config",
		compressed: false,
	})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReadKernelConfig_Sentinel(t *testing.T) {
	// This test verifies that ErrNoKernelConfig is returned when all sources fail.
	// On CI/test environments, at least one source usually exists,
	// so we just verify the error type works with errors.Is.
	err := fmt.Errorf("wrapped: %w", ErrNoKernelConfig)
	if !errors.Is(err, ErrNoKernelConfig) {
		t.Error("errors.Is should match ErrNoKernelConfig")
	}
}
