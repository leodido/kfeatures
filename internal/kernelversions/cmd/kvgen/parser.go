package main

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// kernelVersion mirrors kernelversions.KernelVersion. It is duplicated here
// to keep the generator self-contained (the generator emits the package's
// types.go; importing it would create a chicken-and-egg coupling on every
// rebuild).
type kernelVersion struct {
	Major int
	Minor int
}

// bccTables holds the parsed contents of BCC's kernel-versions.md, keyed
// by the upstream identifier the markdown table provides.
type bccTables struct {
	// Helpers maps the BCC helper enum name (e.g. "BPF_FUNC_bind") to the
	// kernel version that introduced the helper.
	Helpers map[string]kernelVersion
	// ProgramTypes maps the BCC program-type enum (e.g. "BPF_PROG_TYPE_KPROBE")
	// to the kernel version that introduced the program type.
	ProgramTypes map[string]kernelVersion
	// MapTypes maps the BCC map-type enum (e.g. "BPF_MAP_TYPE_HASH") to the
	// kernel version that introduced the map type.
	MapTypes map[string]kernelVersion
}

// uapiSets holds the enum value sets discovered in include/uapi/linux/bpf.h.
type uapiSets struct {
	// Helpers is the set of BPF_FUNC_<name> identifiers. Entries are stored
	// in lowercase form (without the BPF_FUNC_ prefix) to match BCC's table
	// rows after normalization.
	Helpers map[string]struct{}
	// ProgramTypes is the set of BPF_PROG_TYPE_<NAME> identifiers.
	ProgramTypes map[string]struct{}
	// MapTypes is the set of BPF_MAP_TYPE_<NAME> identifiers.
	MapTypes map[string]struct{}
}

var (
	// reHelperRow matches a row in BCC's "Helpers" markdown table. Each row
	// looks like: `BPF_FUNC_bind()` | 4.17 | … | …
	reHelperRow = regexp.MustCompile("`BPF_FUNC_([A-Za-z0-9_]+)\\(\\)`\\s*\\|\\s*([0-9]+\\.[0-9]+)")

	// reEnumRow matches a row in BCC's program-type / map-type tables. The
	// trailing | <kernel> | <commit> | <enum> column carries the canonical
	// identifier we care about.
	reEnumRow = regexp.MustCompile(`\|\s*([0-9]+\.[0-9]+)\s*\|.*\|\s*(BPF_(?:PROG|MAP)_TYPE_[A-Z0-9_]+)\s*$`)

	// reUAPIFn matches FN(<name>, <id>, …) macro invocations inside the
	// FN-list block.
	reUAPIFn = regexp.MustCompile(`^\s+FN\(([a-z0-9_]+),`)
)

// parseBCC walks BCC's kernel-versions.md and extracts the helper /
// program-type / map-type tables.
func parseBCC(body []byte) (*bccTables, error) {
	t := &bccTables{
		Helpers:      map[string]kernelVersion{},
		ProgramTypes: map[string]kernelVersion{},
		MapTypes:     map[string]kernelVersion{},
	}
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### "):
			section = strings.TrimSpace(strings.TrimLeft(line, "# "))
			continue
		}
		switch section {
		case "Helpers":
			if m := reHelperRow.FindStringSubmatch(line); m != nil {
				v, err := parseVersion(m[2])
				if err != nil {
					return nil, fmt.Errorf("helper %q: %w", m[1], err)
				}
				t.Helpers[m[1]] = v
			}
		case "Program types":
			if m := reEnumRow.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[2], "BPF_PROG_TYPE_") {
				v, err := parseVersion(m[1])
				if err != nil {
					return nil, fmt.Errorf("program type %q: %w", m[2], err)
				}
				t.ProgramTypes[m[2]] = v
			}
		case "Map types":
			if m := reEnumRow.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[2], "BPF_MAP_TYPE_") {
				v, err := parseVersion(m[1])
				if err != nil {
					return nil, fmt.Errorf("map type %q: %w", m[2], err)
				}
				t.MapTypes[m[2]] = v
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(t.Helpers) == 0 {
		return nil, fmt.Errorf("no helpers parsed (markdown layout changed?)")
	}
	if len(t.ProgramTypes) == 0 {
		return nil, fmt.Errorf("no program types parsed (markdown layout changed?)")
	}
	if len(t.MapTypes) == 0 {
		return nil, fmt.Errorf("no map types parsed (markdown layout changed?)")
	}
	return t, nil
}

// parseUAPI walks include/uapi/linux/bpf.h and harvests the helper FN-list
// plus the bpf_prog_type and bpf_map_type enum bodies.
func parseUAPI(body []byte) (*uapiSets, error) {
	u := &uapiSets{
		Helpers:      map[string]struct{}{},
		ProgramTypes: map[string]struct{}{},
		MapTypes:     map[string]struct{}{},
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	enumState := "" // "", "prog", "map"
	for scanner.Scan() {
		line := scanner.Text()
		// FN(<name>, <id>, …) macros for helpers. The sentinel `FN(x, ...)`
		// inside the macro template is the only single-character entry; we
		// drop it.
		if m := reUAPIFn.FindStringSubmatch(line); m != nil {
			name := m[1]
			if name == "x" || name == "unspec" {
				continue
			}
			u.Helpers[name] = struct{}{}
			continue
		}
		switch {
		case strings.HasPrefix(line, "enum bpf_prog_type"):
			enumState = "prog"
			continue
		case strings.HasPrefix(line, "enum bpf_map_type"):
			enumState = "map"
			continue
		}
		if enumState != "" {
			trimmed := strings.TrimSpace(line)
			if trimmed == "};" {
				enumState = ""
				continue
			}
			// Match a leading identifier ending with `,` or `=` so we don't
			// confuse comments / blank lines.
			id := leadingEnumIdent(trimmed)
			if id == "" {
				continue
			}
			switch enumState {
			case "prog":
				if strings.HasPrefix(id, "BPF_PROG_TYPE_") && !strings.HasSuffix(id, "_DEPRECATED") && id != "__MAX_BPF_PROG_TYPE" {
					u.ProgramTypes[id] = struct{}{}
				}
			case "map":
				if strings.HasPrefix(id, "BPF_MAP_TYPE_") && !strings.HasSuffix(id, "_DEPRECATED") && id != "__MAX_BPF_MAP_TYPE" {
					u.MapTypes[id] = struct{}{}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(u.Helpers) == 0 {
		return nil, fmt.Errorf("no helpers parsed (UAPI header layout changed?)")
	}
	if len(u.ProgramTypes) == 0 {
		return nil, fmt.Errorf("no program types parsed (UAPI header layout changed?)")
	}
	if len(u.MapTypes) == 0 {
		return nil, fmt.Errorf("no map types parsed (UAPI header layout changed?)")
	}
	return u, nil
}

// leadingEnumIdent extracts the C identifier that starts an enum value
// declaration. Returns "" if the line doesn't look like an enum value.
func leadingEnumIdent(s string) string {
	end := 0
	for end < len(s) {
		c := s[end]
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return ""
	}
	id := s[:end]
	rest := strings.TrimSpace(s[end:])
	if rest == "" {
		return ""
	}
	switch rest[0] {
	case ',', '=':
		return id
	}
	return ""
}

func parseVersion(s string) (kernelVersion, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return kernelVersion{}, fmt.Errorf("invalid version %q", s)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return kernelVersion{}, fmt.Errorf("invalid major in %q: %w", s, err)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return kernelVersion{}, fmt.Errorf("invalid minor in %q: %w", s, err)
	}
	return kernelVersion{Major: maj, Minor: min}, nil
}
