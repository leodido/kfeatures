package main

import (
	"strings"
	"testing"
)

func TestParseBCC(t *testing.T) {
	md := `# header

## Helpers

Helper | Kernel version | License | Commit |
-------|----------------|---------|--------|
` + "`BPF_FUNC_bind()`" + ` | 4.17 |  | [` + "`d74bad4e74ee`" + `]
` + "`BPF_FUNC_ktime_get_ns()`" + ` | 3.18 |  | [` + "`abc`" + `]

## Maps

### Map types

 Map type | Kernel version | Commit | Enum
----------|----------------|--------|------
Hash                            | 3.19 | [` + "`xx`" + `] | BPF_MAP_TYPE_HASH
Array                           | 3.19 | [` + "`yy`" + `] | BPF_MAP_TYPE_ARRAY

## Main features

### Program types

Program type | Kernel version | Commit | Enum
-------------|----------------|--------|-----
Kprobe                         | 4.1  | [` + "`zz`" + `] | BPF_PROG_TYPE_KPROBE
XDP                            | 4.8  | [` + "`zz`" + `] | BPF_PROG_TYPE_XDP
`
	got, err := parseBCC([]byte(md))
	if err != nil {
		t.Fatalf("parseBCC: %v", err)
	}
	if v, ok := got.Helpers["bind"]; !ok || v != (kernelVersion{4, 17}) {
		t.Fatalf("Helpers[bind]=%v ok=%v want {4 17}", v, ok)
	}
	if v, ok := got.Helpers["ktime_get_ns"]; !ok || v != (kernelVersion{3, 18}) {
		t.Fatalf("Helpers[ktime_get_ns]=%v ok=%v want {3 18}", v, ok)
	}
	if v, ok := got.MapTypes["BPF_MAP_TYPE_HASH"]; !ok || v != (kernelVersion{3, 19}) {
		t.Fatalf("MapTypes[BPF_MAP_TYPE_HASH]=%v ok=%v want {3 19}", v, ok)
	}
	if v, ok := got.ProgramTypes["BPF_PROG_TYPE_KPROBE"]; !ok || v != (kernelVersion{4, 1}) {
		t.Fatalf("ProgramTypes[BPF_PROG_TYPE_KPROBE]=%v ok=%v want {4 1}", v, ok)
	}
	if len(got.MapTypes) != 2 || len(got.ProgramTypes) != 2 || len(got.Helpers) != 2 {
		t.Fatalf("counts wrong: helpers=%d progs=%d maps=%d", len(got.Helpers), len(got.ProgramTypes), len(got.MapTypes))
	}
}

func TestParseBCC_LayoutChange(t *testing.T) {
	// Empty input should fail loudly.
	_, err := parseBCC([]byte("# nothing\n"))
	if err == nil {
		t.Fatal("parseBCC: expected error on empty input")
	}
	if !strings.Contains(err.Error(), "no helpers parsed") {
		t.Fatalf("parseBCC: error %q does not mention helpers", err)
	}
}

func TestParseUAPI(t *testing.T) {
	header := `
#define ___BPF_FUNC_MAPPER(FN, ctx...)\
	FN(unspec, 0, ##ctx)				\
	FN(map_lookup_elem, 1, ##ctx)			\
	FN(bind, 2, ##ctx)				\
	FN(x, 1000, ##ctx)

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	__MAX_BPF_MAP_TYPE
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_KPROBE,
	__MAX_BPF_PROG_TYPE
};
`
	got, err := parseUAPI([]byte(header))
	if err != nil {
		t.Fatalf("parseUAPI: %v", err)
	}
	for _, want := range []string{"map_lookup_elem", "bind"} {
		if _, ok := got.Helpers[want]; !ok {
			t.Errorf("Helpers missing %q", want)
		}
	}
	if _, ok := got.Helpers["x"]; ok {
		t.Errorf("Helpers should not contain sentinel 'x'")
	}
	if _, ok := got.Helpers["unspec"]; ok {
		t.Errorf("Helpers should not contain 'unspec'")
	}
	for _, want := range []string{"BPF_MAP_TYPE_HASH", "BPF_MAP_TYPE_ARRAY", "BPF_MAP_TYPE_CGROUP_STORAGE", "BPF_MAP_TYPE_UNSPEC"} {
		if _, ok := got.MapTypes[want]; !ok {
			t.Errorf("MapTypes missing %q", want)
		}
	}
	if _, ok := got.MapTypes["BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED"]; ok {
		t.Errorf("MapTypes should drop _DEPRECATED entries")
	}
	if _, ok := got.MapTypes["__MAX_BPF_MAP_TYPE"]; ok {
		t.Errorf("MapTypes should drop __MAX sentinel")
	}
	for _, want := range []string{"BPF_PROG_TYPE_UNSPEC", "BPF_PROG_TYPE_KPROBE"} {
		if _, ok := got.ProgramTypes[want]; !ok {
			t.Errorf("ProgramTypes missing %q", want)
		}
	}
}

func TestValidateMissing(t *testing.T) {
	bcc := &bccTables{
		Helpers:      map[string]kernelVersion{"bind": {4, 17}},
		ProgramTypes: map[string]kernelVersion{"BPF_PROG_TYPE_KPROBE": {4, 1}},
		MapTypes:     map[string]kernelVersion{"BPF_MAP_TYPE_HASH": {3, 19}},
	}
	uapi := &uapiSets{
		Helpers:      map[string]struct{}{"bind": {}, "new_helper": {}},
		ProgramTypes: map[string]struct{}{"BPF_PROG_TYPE_KPROBE": {}, "BPF_PROG_TYPE_NEW": {}},
		MapTypes:     map[string]struct{}{"BPF_MAP_TYPE_HASH": {}, "BPF_MAP_TYPE_NEW": {}},
	}
	err := validate(bcc, uapi)
	if err == nil {
		t.Fatal("validate: expected error")
	}
	for _, want := range []string{"BPF_FUNC_new_helper", "BPF_PROG_TYPE_NEW", "BPF_MAP_TYPE_NEW"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validate error missing %q; got: %s", want, err)
		}
	}
}

func TestValidateAllowedMissing(t *testing.T) {
	bcc := &bccTables{
		Helpers:      map[string]kernelVersion{},
		ProgramTypes: map[string]kernelVersion{},
		MapTypes:     map[string]kernelVersion{},
	}
	uapi := &uapiSets{
		Helpers:      map[string]struct{}{"skc_to_mptcp_sock": {}},
		ProgramTypes: map[string]struct{}{"BPF_PROG_TYPE_UNSPEC": {}, "BPF_PROG_TYPE_NETFILTER": {}},
		MapTypes:     map[string]struct{}{"BPF_MAP_TYPE_UNSPEC": {}, "BPF_MAP_TYPE_ARENA": {}},
	}
	if err := validate(bcc, uapi); err != nil {
		t.Fatalf("validate: known gaps should pass, got: %v", err)
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want kernelVersion
		ok   bool
	}{
		{"5.8", kernelVersion{5, 8}, true},
		{"6.1", kernelVersion{6, 1}, true},
		{"3.19", kernelVersion{3, 19}, true},
		{"bad", kernelVersion{}, false},
		{"5", kernelVersion{}, false},
		{"a.b", kernelVersion{}, false},
	}
	for _, tc := range cases {
		got, err := parseVersion(tc.in)
		if tc.ok && err != nil {
			t.Errorf("parseVersion(%q) unexpected err: %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseVersion(%q) expected err, got %v", tc.in, got)
		}
		if tc.ok && got != tc.want {
			t.Errorf("parseVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLeadingEnumIdent(t *testing.T) {
	cases := map[string]string{
		"BPF_MAP_TYPE_HASH,":                            "BPF_MAP_TYPE_HASH",
		"BPF_MAP_TYPE_HASH = BPF_MAP_TYPE_OTHER":        "BPF_MAP_TYPE_HASH",
		"\tBPF_MAP_TYPE_HASH,":                          "",
		"// a comment":                                  "",
		"":                                              "",
		"};":                                            "",
		"BPF_MAP_TYPE_INSN_ARRAY,":                      "BPF_MAP_TYPE_INSN_ARRAY",
	}
	for in, want := range cases {
		if got := leadingEnumIdent(in); got != want {
			t.Errorf("leadingEnumIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCamelize(t *testing.T) {
	cases := map[string]string{
		"map_lookup_elem":         "MapLookupElem",
		"ktime_get_ns":            "KtimeGetNs",
		"x":                       "X",
		"":                        "",
		"already_caps":            "AlreadyCaps",
	}
	for in, want := range cases {
		if got := camelize(in); got != want {
			t.Errorf("camelize(%q) = %q, want %q", in, got, want)
		}
	}
}
