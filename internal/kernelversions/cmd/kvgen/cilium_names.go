package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
)

// The generator emits Go references like `asm.FnBind` and `ebpf.Hash`.
// Not every identifier present in the BCC table or UAPI header has a
// matching constant in cilium/ebpf — sometimes cilium hasn't caught up
// yet, sometimes the cilium constant is shaped differently (e.g.
// UnspecifiedMap vs BPF_MAP_TYPE_UNSPEC). We discover the actual cilium
// constants by reading the cilium source files in the module cache, so
// that the snapshot only references symbols that exist.
//
// We deliberately avoid a Go AST walk: a regex over the raw source is
// sufficient because cilium/ebpf's helper / map-type / program-type
// declarations are all single-line constant definitions in well-known
// files.

var (
	ciliumLoadOnce  sync.Once
	ciliumHelpers   map[string]struct{}
	ciliumProgTypes map[string]struct{}
	ciliumMapTypes  map[string]struct{}
	ciliumLoadErr   error
)

func loadCiliumNames() {
	ciliumLoadOnce.Do(func() {
		dir, err := ciliumModuleDir()
		if err != nil {
			ciliumLoadErr = err
			return
		}
		ciliumHelpers, err = harvestIdents(filepath.Join(dir, "asm", "func_lin.go"),
			regexp.MustCompile(`(?m)^\s+(Fn[A-Z][A-Za-z0-9]*)\s*=`))
		if err != nil {
			ciliumLoadErr = fmt.Errorf("harvest helpers: %w", err)
			return
		}
		ciliumMapTypes, err = harvestMapTypes(filepath.Join(dir, "types.go"))
		if err != nil {
			ciliumLoadErr = fmt.Errorf("harvest map types: %w", err)
			return
		}
		ciliumProgTypes, err = harvestProgTypes(filepath.Join(dir, "types.go"))
		if err != nil {
			ciliumLoadErr = fmt.Errorf("harvest program types: %w", err)
			return
		}
	})
}

func ciliumModuleDir() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/cilium/ebpf")
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list cilium/ebpf: %w", err)
	}
	dir := string(bytes.TrimSpace(out))
	if dir == "" {
		return "", fmt.Errorf("cilium/ebpf module dir not found")
	}
	return dir, nil
}

func harvestIdents(path string, re *regexp.Regexp) (map[string]struct{}, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, m := range re.FindAllSubmatch(body, -1) {
		out[string(m[1])] = struct{}{}
	}
	return out, nil
}

// harvestMapTypes finds the iota-driven const block in cilium/ebpf/types.go
// that starts with `UnspecifiedMap MapType = MapType(platform.LinuxTag | iota)`
// and returns every bare identifier inside it.
func harvestMapTypes(path string) (map[string]struct{}, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	idx := bytes.Index(body, []byte("UnspecifiedMap MapType"))
	if idx < 0 {
		return nil, fmt.Errorf("UnspecifiedMap declaration not found in %s", path)
	}
	end := bytes.Index(body[idx:], []byte("\n)"))
	if end < 0 {
		return nil, fmt.Errorf("closing paren after UnspecifiedMap not found in %s", path)
	}
	block := body[idx : idx+end]
	identRE := regexp.MustCompile(`(?m)^\s*([A-Z][A-Za-z0-9_]*)\s*$`)
	out := map[string]struct{}{
		"UnspecifiedMap": {},
	}
	for _, m := range identRE.FindAllSubmatch(block, -1) {
		out[string(m[1])] = struct{}{}
	}
	return out, nil
}

// harvestProgTypes finds the explicit `<Ident> = ProgramType(sys.BPF_PROG_TYPE_*)`
// block in cilium/ebpf/types.go and returns every left-hand identifier.
func harvestProgTypes(path string) (map[string]struct{}, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s+([A-Z][A-Za-z0-9_]*)\s*=\s*ProgramType\(`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllSubmatch(body, -1) {
		out[string(m[1])] = struct{}{}
	}
	return out, nil
}

func ciliumHasHelper(goConst string) bool {
	loadCiliumNames()
	if ciliumLoadErr != nil {
		fmt.Fprintln(os.Stderr, "kvgen warning: cilium name lookup failed:", ciliumLoadErr)
		return false
	}
	_, ok := ciliumHelpers[goConst]
	return ok
}

func ciliumHasProgType(goConst string) bool {
	loadCiliumNames()
	if ciliumLoadErr != nil {
		return false
	}
	_, ok := ciliumProgTypes[goConst]
	return ok
}

func ciliumHasMapType(goConst string) bool {
	loadCiliumNames()
	if ciliumLoadErr != nil {
		return false
	}
	_, ok := ciliumMapTypes[goConst]
	return ok
}
