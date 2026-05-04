package main

// Known gaps where the upstream UAPI header documents an enum value that
// BCC's kernel-versions.md hasn't picked up yet (or the BCC document has
// chosen not to list — e.g. the synthetic *_UNSPEC entries). Each entry
// suppresses a single cross-validation diagnostic.
//
// New entries here require a maintainer review note explaining why the
// value is allowed to be absent. The intent is to keep the audit trail
// inside the generator rather than letting unknown values silently slip
// through.
//
// When BCC catches up, the entry can be removed; the generator will
// then have a row in its emitted table for the symbol, gated by what
// cilium/ebpf actually exposes.

// allowedMissingHelpers lists BPF_FUNC_<lowercase> identifiers the BCC
// table is allowed to omit.
var allowedMissingHelpers = map[string]string{
	// BCC table snapshot lags upstream; helper introduced in v6.x.
	"skc_to_mptcp_sock": "BCC table not yet refreshed past v6.x; helper exists in UAPI",
}

// allowedMissingProgTypes lists BPF_PROG_TYPE_<NAME> identifiers the BCC
// table is allowed to omit.
var allowedMissingProgTypes = map[string]string{
	"BPF_PROG_TYPE_UNSPEC":    "synthetic enum sentinel; never appears in BCC table",
	"BPF_PROG_TYPE_NETFILTER": "BCC table not yet refreshed past v6.x; type exists in UAPI",
}

// allowedMissingMapTypes lists BPF_MAP_TYPE_<NAME> identifiers the BCC
// table is allowed to omit.
var allowedMissingMapTypes = map[string]string{
	"BPF_MAP_TYPE_UNSPEC":       "synthetic enum sentinel; never appears in BCC table",
	"BPF_MAP_TYPE_CGRP_STORAGE": "BCC table not yet refreshed past v6.x; type exists in UAPI",
	"BPF_MAP_TYPE_ARENA":        "BCC table not yet refreshed past v6.x; type exists in UAPI",
	"BPF_MAP_TYPE_INSN_ARRAY":   "BCC table not yet refreshed past v6.x; type exists in UAPI",
}
