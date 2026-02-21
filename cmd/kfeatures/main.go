package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/leodido/kfeatures"
	"github.com/leodido/structcli"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/thediveo/enumflag/v2"
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
		SilenceUsage: true,
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
				return err
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
	Require featureRequirements `flag:"require" flagshort:"r" flagdescr:"Required features (see available features above)" flagrequired:"true" flagcustom:"true"`
	JSON    bool                `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

func (o *CheckOptions) Attach(c *cobra.Command) error {
	return structcli.Define(c, o)
}

func (o *CheckOptions) DefineRequire(name, short, descr string, structField reflect.StructField, fieldValue reflect.Value) (pflag.Value, string) {
	fieldPtr := fieldValue.Addr().Interface().(*featureRequirements)
	*fieldPtr = nil
	return fieldPtr, descr
}

func (o *CheckOptions) DecodeRequire(input any) (any, error) {
	s, ok := input.(string)
	if !ok {
		return input, nil
	}

	return parseFeatureRequirements(s)
}

func checkCmd() *cobra.Command {
	opts := &CheckOptions{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check specific kernel feature requirements",
		Long:  checkLongDescription(),
		PreRunE: func(c *cobra.Command, args []string) error {
			return structcli.Unmarshal(c, opts)
		},
		RunE: func(c *cobra.Command, args []string) error {
			if len(opts.Require) == 0 {
				return fmt.Errorf("no features specified")
			}

			requirements := make([]kfeatures.Requirement, 0, len(opts.Require))
			for _, f := range opts.Require {
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
				return err
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
				return err
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
	return strings.Join(kfeatures.FeatureNames(), ", ")
}

func checkLongDescription() string {
	return fmt.Sprintf(`Check that the kernel supports all required features.
Exits with code 0 if all requirements are met, 1 if any are missing.

Available features:
%s`, formatWrappedList(kfeatures.FeatureNames(), "  ", 80))
}

func formatWrappedList(items []string, indent string, maxWidth int) string {
	if len(items) == 0 {
		return indent + "(none)"
	}

	lines := make([]string, 0, len(items))
	line := indent
	for i, item := range items {
		token := item
		if i < len(items)-1 {
			token += ", "
		}

		if len(line)+len(token) > maxWidth && line != indent {
			lines = append(lines, strings.TrimRight(line, " "))
			line = indent + token
			continue
		}

		line += token
	}

	lines = append(lines, strings.TrimRight(line, " "))
	return strings.Join(lines, "\n")
}

type featureRequirements []kfeatures.Feature

var featureIdentifierMap = func() map[kfeatures.Feature][]string {
	ids := make(map[kfeatures.Feature][]string, len(kfeatures.FeatureValues()))
	for _, f := range kfeatures.FeatureValues() {
		ids[f] = []string{f.String()}
	}
	return ids
}()

func (r *featureRequirements) String() string {
	names := make([]string, 0, len(*r))
	for _, f := range *r {
		names = append(names, f.String())
	}

	return strings.Join(names, ",")
}

func (r *featureRequirements) Set(input string) error {
	features, err := parseFeatureRequirements(input)
	if err != nil {
		return err
	}

	*r = append(*r, features...)
	return nil
}

func (r *featureRequirements) Type() string {
	return "feature"
}

func parseFeatureRequirements(input string) (featureRequirements, error) {
	if strings.TrimSpace(input) == "" {
		return featureRequirements{}, nil
	}

	parts := strings.Split(input, ",")
	features := make(featureRequirements, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}

		var feature kfeatures.Feature
		enumValue := enumflag.New(&feature, "kfeatures.Feature", featureIdentifierMap, enumflag.EnumCaseInsensitive)
		if err := enumValue.Set(name); err != nil {
			return nil, fmt.Errorf("unknown feature: %q (available: %s)", name, availableFeatures())
		}

		features = append(features, feature)
	}

	return features, nil
}
