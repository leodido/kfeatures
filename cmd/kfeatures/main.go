//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/leodido/kfeatures"
	"github.com/leodido/structcli"
	"github.com/spf13/cobra"
)

// Build metadata injected via ldflags (see .goreleaser.yaml).
// When built without ldflags (e.g., plain `go build`), these remain
// at their zero values and the version command omits them gracefully.
var (
	version = ""
	commit  = ""
	date    = ""
)

func main() {
	root := &cobra.Command{
		Use:   "kfeatures",
		Short: "Kernel feature detection for eBPF programs",
		Long: `kfeatures probes kernel capabilities relevant to eBPF programs.

It detects program type support, BTF availability, security subsystems (LSM, IMA),
kernel configuration, and process capabilities. Use it for operator diagnostics,
CI/CD gating, or container runtime validation.`,
	}

	root.AddCommand(probeCmd())
	root.AddCommand(checkCmd())
	root.AddCommand(configCmd())
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ProbeOptions defines flags for the probe subcommand.
type ProbeOptions struct {
	JSON bool `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

func (o *ProbeOptions) Attach(c *cobra.Command) error {
	return structcli.Define(c, o)
}

func probeCmd() *cobra.Command {
	opts := &ProbeOptions{}

	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe all kernel features and display results",
		PreRunE: func(c *cobra.Command, args []string) error {
			return structcli.Unmarshal(c, opts)
		},
		RunE: func(c *cobra.Command, args []string) error {
			sf, err := kfeatures.ProbeNoCache()
			if err != nil {
				return fmt.Errorf("probe failed: %w", err)
			}

			if opts.JSON {
				return printJSON(sf)
			}

			fmt.Print(sf)
			return nil
		},
	}

	if err := opts.Attach(cmd); err != nil {
		panic(err)
	}
	return cmd
}

// CheckOptions defines flags for the check subcommand.
type CheckOptions struct {
	Require []string `flag:"require" flagshort:"r" flagdescr:"Required features (comma-separated: bpf-syscall,perf-event-open,bpf-lsm,btf,ima,kprobe,kprobe-multi,fentry,tracepoint,cap-bpf,cap-sys-admin,cap-perfmon,jit,jit-hardened,sleepable-bpf,tracefs,bpffs,init-user-ns,unprivileged-bpf-disabled,bpf-stats-enabled)" flagrequired:"true"`
	JSON    bool     `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

func (o *CheckOptions) Attach(c *cobra.Command) error {
	return structcli.Define(c, o)
}

// featureFromName maps CLI feature names to Feature constants.
var featureFromName = map[string]kfeatures.Feature{
	"bpf-lsm":                   kfeatures.FeatureBPFLSM,
	"btf":                       kfeatures.FeatureBTF,
	"ima":                       kfeatures.FeatureIMA,
	"kprobe":                    kfeatures.FeatureKprobe,
	"kprobe-multi":              kfeatures.FeatureKprobeMulti,
	"fentry":                    kfeatures.FeatureFentry,
	"tracepoint":                kfeatures.FeatureTracepoint,
	"cap-bpf":                   kfeatures.FeatureCapBPF,
	"cap-sys-admin":             kfeatures.FeatureCapSysAdmin,
	"cap-perfmon":               kfeatures.FeatureCapPerfmon,
	"jit":                       kfeatures.FeatureJITEnabled,
	"jit-hardened":              kfeatures.FeatureJITHardened,
	"bpf-syscall":               kfeatures.FeatureBPFSyscall,
	"perf-event-open":           kfeatures.FeaturePerfEventOpen,
	"sleepable-bpf":             kfeatures.FeatureSleepableBPF,
	"tracefs":                   kfeatures.FeatureTraceFS,
	"bpffs":                     kfeatures.FeatureBPFFS,
	"init-user-ns":              kfeatures.FeatureInitUserNS,
	"unprivileged-bpf-disabled": kfeatures.FeatureUnprivilegedBPFDisabled,
	"bpf-stats-enabled":         kfeatures.FeatureBPFStatsEnabled,
}

func checkCmd() *cobra.Command {
	opts := &CheckOptions{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check specific kernel feature requirements",
		Long: `Check that the kernel supports all required features.
Exits with code 0 if all requirements are met, 1 if any are missing.

Available features:
  bpf-syscall, perf-event-open, bpf-lsm, btf, ima, kprobe, kprobe-multi,
  fentry, tracepoint, cap-bpf, cap-sys-admin, cap-perfmon, jit, jit-hardened,
  sleepable-bpf, tracefs, bpffs, init-user-ns, unprivileged-bpf-disabled,
  bpf-stats-enabled`,
		PreRunE: func(c *cobra.Command, args []string) error {
			return structcli.Unmarshal(c, opts)
		},
		RunE: func(c *cobra.Command, args []string) error {
			var features []kfeatures.Feature
			for _, name := range opts.Require {
				// Handle comma-separated values within a single flag value.
				for _, n := range strings.Split(name, ",") {
					n = strings.TrimSpace(n)
					if n == "" {
						continue
					}
					f, ok := featureFromName[n]
					if !ok {
						return fmt.Errorf("unknown feature: %q (available: %s)", n, availableFeatures())
					}
					features = append(features, f)
				}
			}

			if len(features) == 0 {
				return fmt.Errorf("no features specified")
			}

			requirements := make([]kfeatures.Requirement, 0, len(features))
			for _, f := range features {
				requirements = append(requirements, f)
			}

			err := kfeatures.Check(requirements...)
			if err != nil {
				var fe *kfeatures.FeatureError
				if errors.As(err, &fe) {
					if opts.JSON {
						return printJSON(map[string]any{
							"ok":      false,
							"feature": fe.Feature,
							"reason":  fe.Reason,
						})
					}
					fmt.Fprintf(os.Stderr, "FAIL: %s — %s\n", fe.Feature, fe.Reason)
					os.Exit(1)
				}
				return err
			}

			if opts.JSON {
				return printJSON(map[string]any{"ok": true})
			}
			fmt.Println("OK: all requirements satisfied")
			return nil
		},
	}

	if err := opts.Attach(cmd); err != nil {
		panic(err)
	}
	return cmd
}

// ConfigOptions defines flags for the config subcommand.
type ConfigOptions struct {
	JSON bool `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

func (o *ConfigOptions) Attach(c *cobra.Command) error {
	return structcli.Define(c, o)
}

func configCmd() *cobra.Command {
	opts := &ConfigOptions{}

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Display parsed kernel configuration",
		PreRunE: func(c *cobra.Command, args []string) error {
			return structcli.Unmarshal(c, opts)
		},
		RunE: func(c *cobra.Command, args []string) error {
			sf, err := kfeatures.ProbeWith(kfeatures.WithKernelConfig())
			if err != nil {
				return fmt.Errorf("probe failed: %w", err)
			}

			if sf.KernelConfig == nil {
				fmt.Fprintln(os.Stderr, "kernel config not available")
				os.Exit(1)
			}

			if opts.JSON {
				return printJSON(map[string]any{
					"CONFIG_BPF_LSM":        sf.KernelConfig.BPFLSM.String(),
					"CONFIG_IMA":            sf.KernelConfig.IMA.String(),
					"CONFIG_DEBUG_INFO_BTF": sf.KernelConfig.BTF.String(),
					"CONFIG_FPROBE":         sf.KernelConfig.KprobeMulti.String(),
				})
			}

			fmt.Printf("CONFIG_BPF_LSM:        %s\n", sf.KernelConfig.BPFLSM)
			fmt.Printf("CONFIG_IMA:            %s\n", sf.KernelConfig.IMA)
			fmt.Printf("CONFIG_DEBUG_INFO_BTF: %s\n", sf.KernelConfig.BTF)
			fmt.Printf("CONFIG_FPROBE:         %s\n", sf.KernelConfig.KprobeMulti)
			return nil
		},
	}

	if err := opts.Attach(cmd); err != nil {
		panic(err)
	}
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show kernel and tool version",
		RunE: func(c *cobra.Command, args []string) error {
			if version != "" {
				fmt.Printf("kfeatures %s", version)
				if commit != "" {
					fmt.Printf(" (%s)", commit)
				}
				if date != "" {
					fmt.Printf(" built %s", date)
				}
				fmt.Println()
			} else {
				fmt.Println("kfeatures (dev)")
			}

			sf, err := kfeatures.ProbeWith()
			if err != nil {
				return fmt.Errorf("probe failed: %w", err)
			}
			fmt.Printf("Kernel: %s\n", sf.KernelVersion)
			return nil
		},
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func availableFeatures() string {
	names := make([]string, 0, len(featureFromName))
	for k := range featureFromName {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}
