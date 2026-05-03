package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/leodido/kfeatures"
	"github.com/leodido/structcli"
	"github.com/leodido/structcli/jsonschema"
	structclimcp "github.com/leodido/structcli/mcp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
		// Root needs RunE so structcli can wrap it for --jsonschema=tree
		// interception. Without RunE, cobra treats root as non-runnable and
		// short-circuits to Help() before PreRunE fires, preventing the
		// schema interceptor from running on root invocations.
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	root.AddCommand(probeCmd())
	root.AddCommand(checkCmd())
	root.AddCommand(configCmd())
	root.AddCommand(versionCmd())

	// Setup orchestrates the optional structcli capabilities:
	//   * WithJSONSchema: `--jsonschema` discovery surface.
	//   * WithFlagErrors: typed FlagError values so HandleError classifies
	//                     cobra/pflag misuse with semantic exit codes
	//                     (10/11/12/15) instead of the Error=1 fallback.
	//   * WithMCP:        `--mcp` flag exposes every runnable leaf command
	//                     as an MCP tool over stdio. Each subcommand
	//                     becomes a callable tool whose schema mirrors the
	//                     cobra flag set; agents introspect via tools/list
	//                     and invoke via tools/call without scraping
	//                     --help. Tool name uses the command path with `-`
	//                     as separator (only relevant once we have nested
	//                     subcommands; today the names are just `probe`,
	//                     `check`, `config`, `version`).
	//                     `version` and `completion` are excluded: the
	//                     former is build-metadata best surfaced as a
	//                     server-info field, and the latter is a shell
	//                     integration with no agent value.
	// Setup must run after AddCommand so subcommands are wrapped.
	if err := structcli.Setup(root,
		structcli.WithJSONSchema(jsonschema.Options{}),
		structcli.WithFlagErrors(),
		structcli.WithMCP(structclimcp.Options{
			Version: mcpServerVersion(),
			// Exclude entries match exact tool names OR exact full
			// command paths. Cobra auto-generates `completion <shell>`
			// leaves (one per supported shell), so we exclude both the
			// parent path and each leaf tool name; structcli's MCP
			// registry never sees the parent because it only exposes
			// runnable leaves, but listing the leaves explicitly is
			// future-proof if cobra adds a new shell.
			Exclude: []string{
				"version",
				"completion-bash",
				"completion-zsh",
				"completion-fish",
				"completion-powershell",
			},
		}),
	); err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		os.Exit(1)
	}

	// ExecuteOrExit drives the auto-bind pipeline (config → unmarshal →
	// validate) for every command registered through structcli.Bind, then
	// either exits 0 or writes a structured-error JSON to stderr and exits
	// with a semantic exit code from the exitcode package (input errors
	// 10–19, config/env 20–29, runtime 1–9). Replaces the pre-refactor
	// "Error: …" + os.Exit(1) bridge.
	structcli.ExecuteOrExit(root)
}

// ProbeOptions defines flags for the probe subcommand.
type ProbeOptions struct {
	JSON bool `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

func probeCmd() *cobra.Command {
	opts := &ProbeOptions{}

	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe all kernel features and display results",
		RunE: func(c *cobra.Command, args []string) error {
			sf, err := kfeatures.ProbeNoCache()
			if err != nil {
				return err
			}

			if opts.JSON {
				return printJSON(c.OutOrStdout(), sf)
			}

			fmt.Fprint(c.OutOrStdout(), sf)
			return nil
		},
	}

	if err := structcli.Bind(cmd, opts); err != nil {
		panic(err)
	}
	return cmd
}

// CheckOptions defines flags for the check subcommand.
type CheckOptions struct {
	Require featureRequirements `flag:"require" flagshort:"r" flagdescr:"Required features (see available features above)" flagrequired:"true" flagcustom:"true"`
	JSON    bool                `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

// DefineRequire / DecodeRequire / CompleteRequire are the structcli custom-flag
// triad. structcli.Bind discovers them by reflection on *CheckOptions; no
// explicit Attach method is needed.

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

func (o *CheckOptions) CompleteRequire(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	prefix := ""
	current := toComplete
	selected := map[string]struct{}{}

	if comma := strings.LastIndex(toComplete, ","); comma >= 0 {
		prefix = toComplete[:comma+1]
		current = toComplete[comma+1:]

		for _, raw := range strings.Split(toComplete[:comma], ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}

			var f kfeatures.Feature
			if err := f.UnmarshalText([]byte(raw)); err == nil {
				selected[f.String()] = struct{}{}
			}
		}
	}

	current = strings.ToLower(strings.TrimSpace(current))
	candidates := make([]string, 0, len(kfeatures.FeatureNames()))
	for _, name := range kfeatures.FeatureNames() {
		if _, ok := selected[name]; ok {
			continue
		}
		if current != "" && !strings.HasPrefix(strings.ToLower(name), current) {
			continue
		}
		candidates = append(candidates, prefix+name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

func checkCmd() *cobra.Command {
	opts := &CheckOptions{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check specific kernel feature requirements",
		Long:  checkLongDescription(),
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
				// FeatureError is a business outcome, not an invocation
				// error: --json emits the documented {ok,feature,reason}
				// shape on stdout; the human path emits FAIL on stderr.
				// Both exit 1 directly so structcli.ExecuteOrExit does not
				// overwrite the verdict with a generic structured-error
				// JSON. Other errors (probing, parsing) fall through to
				// structcli for classification.
				//
				// Streams go through cmd.OutOrStdout / cmd.ErrOrStderr so
				// MCP mode (which redirects them into per-call buffers
				// captured into the JSON-RPC response) sees the verdict
				// instead of having it leak to the host stdio.
				var fe *kfeatures.FeatureError
				if errors.As(err, &fe) {
					if inMCPMode(c) {
						// Under MCP the host receives the structcli error
						// envelope (HandleError writes it; the MCP layer
						// wraps it as content with isError=true) and any
						// stdout/stderr we write here is discarded. Skip
						// the CLI-only formatting and return the typed
						// error so the message reaches the agent verbatim.
						// os.Exit would terminate the MCP server for the
						// host and break subsequent tools/call requests.
						return fe
					}
					if opts.JSON {
						_ = printJSON(c.OutOrStdout(), map[string]any{
							"ok":      false,
							"feature": fe.Feature,
							"reason":  fe.Reason,
						})
					} else {
						fmt.Fprintf(c.ErrOrStderr(), "FAIL: %s - %s\n", fe.Feature, fe.Reason)
					}
					os.Exit(1)
				}
				return err
			}

			if opts.JSON {
				return printJSON(c.OutOrStdout(), map[string]any{"ok": true})
			}
			fmt.Fprintln(c.OutOrStdout(), "OK: all requirements satisfied")
			return nil
		},
	}

	if err := structcli.Bind(cmd, opts); err != nil {
		panic(err)
	}
	return cmd
}

// ConfigOptions defines flags for the config subcommand.
type ConfigOptions struct {
	JSON bool `flag:"json" flagshort:"j" flagdescr:"Output in JSON format"`
}

func configCmd() *cobra.Command {
	opts := &ConfigOptions{}

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Display parsed kernel configuration",
		RunE: func(c *cobra.Command, args []string) error {
			sf, err := kfeatures.ProbeWith(kfeatures.WithKernelConfig())
			if err != nil {
				return err
			}

			if sf.KernelConfig == nil {
				fmt.Fprintln(c.ErrOrStderr(), "kernel config not available")
				if inMCPMode(c) {
					return errors.New("kernel config not available")
				}
				os.Exit(1)
			}

			out := c.OutOrStdout()
			if opts.JSON {
				return printJSON(out, map[string]any{
					"CONFIG_BPF_LSM":        sf.KernelConfig.BPFLSM.String(),
					"CONFIG_IMA":            sf.KernelConfig.IMA.String(),
					"CONFIG_DEBUG_INFO_BTF": sf.KernelConfig.BTF.String(),
					"CONFIG_FPROBE":         sf.KernelConfig.KprobeMulti.String(),
				})
			}

			fmt.Fprintf(out, "CONFIG_BPF_LSM:        %s\n", sf.KernelConfig.BPFLSM)
			fmt.Fprintf(out, "CONFIG_IMA:            %s\n", sf.KernelConfig.IMA)
			fmt.Fprintf(out, "CONFIG_DEBUG_INFO_BTF: %s\n", sf.KernelConfig.BTF)
			fmt.Fprintf(out, "CONFIG_FPROBE:         %s\n", sf.KernelConfig.KprobeMulti)
			return nil
		},
	}

	if err := structcli.Bind(cmd, opts); err != nil {
		panic(err)
	}
	return cmd
}

// mcpServerVersion returns just the version string for MCP serverInfo
// (whose `name` field already carries "kfeatures"). Falls back to "dev"
// when built without ldflags, matching the human-facing version path's
// fallback. The CLI `version` subcommand renders a richer line
// ("kfeatures <ver> (<commit>) built <date>") for human consumption;
// MCP clients should use `tools/call` on a future `version` tool (today
// excluded) or read `serverInfo.version` directly.
func mcpServerVersion() string {
	if version != "" {
		return version
	}
	return "dev"
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show kernel and tool version",
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			if version != "" {
				fmt.Fprintf(out, "kfeatures %s", version)
				if commit != "" {
					fmt.Fprintf(out, " (%s)", commit)
				}
				if date != "" {
					fmt.Fprintf(out, " built %s", date)
				}
				fmt.Fprintln(out)
			} else {
				fmt.Fprintln(out, "kfeatures (dev)")
			}

			sf, err := kfeatures.ProbeWith()
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Kernel: %s\n", sf.KernelVersion)
			return nil
		},
	}
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// inMCPMode reports whether the command is being executed inside an MCP
// tools/call request. The structcli MCP wrapper swaps the executed
// command's Out/Err for per-call buffers (cobra's OutOrStdout walks up
// the parent chain, so reading it on a leaf reflects the swap performed
// by the wrapper on root or on a factory-built command), so a custom
// Out distinct from the process os.Stdout signals MCP mode. We use it
// to swap process-wide os.Exit calls for plain error returns: exiting
// the host would kill the MCP server mid-session and break subsequent
// tools/call requests.
//
// Coupling note: the proxy assumes the only code path that calls
// SetOut on our cobra tree is structcli's MCP wrapper. As of structcli
// v0.17.0 this holds (only mcp.go calls SetOut in non-test code). If a
// future structcli capability calls SetOut for another reason, this
// detection must be replaced with an explicit signal (e.g. a context
// value or annotation set by the MCP wrapper).
//
// Caller note: do not introduce `defer` statements in any RunE that
// reaches `os.Exit(1)` through this gate; os.Exit skips deferreds.
// Today no such RunE has a defer; this comment exists to keep it that
// way.
func inMCPMode(c *cobra.Command) bool {
	if c == nil {
		return false
	}
	out := c.OutOrStdout()
	return out != nil && out != os.Stdout
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

func (r *featureRequirements) String() string {
	if len(*r) == 0 {
		return ""
	}

	out := make([]byte, 0, len(*r)*12)
	for _, f := range *r {
		if len(out) > 0 {
			out = append(out, ',')
		}
		var err error
		out, err = f.AppendText(out)
		if err != nil {
			return ""
		}
	}

	return string(out)
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
		if err := feature.UnmarshalText([]byte(name)); err != nil {
			return nil, fmt.Errorf("unknown feature: %q (available: %s)", name, availableFeatures())
		}

		features = append(features, feature)
	}

	return features, nil
}
