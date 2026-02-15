// Package kfeatures provides kernel feature detection for eBPF programs.
//
// This package probes kernel capabilities at runtime, enabling early failure
// with clear, actionable error messages when requirements aren't met.
// It complements github.com/cilium/ebpf/features by adding BTF availability
// detection, security subsystem probing (LSM, IMA), kernel config parsing,
// capability checking, and composite feature validation with operator-facing
// diagnostics.
//
// # API Model
//
// kfeatures intentionally exposes two API families:
//   - [Check] for pass/fail readiness validation using [Requirement] items
//   - [Probe]/[ProbeWith] for diagnostics data collection using WithX options
//
// Keep these families separate:
//   - model stable boolean gates as [Feature]
//   - model parameterized gates as [Requirement] item types
//   - keep context-only/descriptive signals probe-only unless a concrete
//     deterministic gating policy is defined.
//
// FromELF API contract (frozen):
//   - [FromELF] returns [FeatureGroup] requirement items consumable by [Check]
//   - output is deterministic (deduplicated, stable order)
//   - extraction scope includes program/map types and helper-per-program requirements
//   - unknown/unsupported ELF kinds fail closed with an error
//
// # Quick Check
//
// Validate that required kernel features are available:
//
//	if err := kfeatures.Check(kfeatures.FeatureBPFLSM, kfeatures.FeatureBTF); err != nil {
//	    var fe *kfeatures.FeatureError
//	    if errors.As(err, &fe) {
//	        log.Fatalf("kernel not ready: %s — %s", fe.Feature, fe.Reason)
//	    }
//	    log.Fatal(err)
//	}
//
// # Full Probe
//
// Probe all features for diagnostics:
//
//	sf, err := kfeatures.Probe()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("BPF LSM program type: %v\n", sf.LSMProgramType.Supported)
//	fmt.Printf("BPF LSM enabled: %v\n", sf.BPFLSMEnabled.Supported)
//	fmt.Printf("BTF available: %v\n", sf.BTF.Supported)
//	fmt.Printf("Kernel: %s\n", sf.KernelVersion)
//	fmt.Println(sf) // human-readable summary
//
// # Selective Probing
//
// Probe only specific features to minimize overhead:
//
//	sf, err := kfeatures.ProbeWith(
//	    kfeatures.WithProgramTypes(ebpf.LSM, ebpf.Kprobe),
//	    kfeatures.WithSecuritySubsystems(),
//	    kfeatures.WithCapabilities(),
//	)
//
// # Types
//
// [ProbeResult] represents the outcome of probing a single feature:
//   - Supported: true if the feature is available
//   - Error: non-nil if the probe itself failed (not just unsupported)
//
// [SystemFeatures] aggregates all probe results into a single struct.
//
// [KernelConfig] holds parsed kernel configuration values with support
// for distinguishing between =m (module) and =y (built-in) settings.
//
// [Feature] represents a kernel capability that can be checked via [Check].
//
// [FeatureError] provides actionable diagnostics when a required feature
// is unavailable, including the feature name, a human-readable reason with
// remediation steps, and the underlying probe error if any.
package kfeatures
