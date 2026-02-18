//go:build !linux

package kfeatures

// Check validates the specified requirements and returns a *[FeatureError]
// for the first unsatisfied requirement, or nil if all are met.
// On non-Linux platforms, Check always returns an unsupported-platform error.
func Check(_ ...Requirement) error {
	return ErrUnsupportedPlatform
}

// Result maps a [Feature] to its corresponding [ProbeResult].
// On non-Linux platforms, every feature is unknown.
func (sf *SystemFeatures) Result(_ Feature) (ProbeResult, bool) {
	return ProbeResult{}, false
}

// Diagnose returns an enriched reason string explaining why a feature
// is not supported and what the operator can do to fix it.
// On non-Linux platforms, the answer is always the same.
func (sf *SystemFeatures) Diagnose(_ Feature) string {
	return "not supported (requires Linux)"
}
