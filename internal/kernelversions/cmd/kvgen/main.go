// kvgen regenerates the kernel-version snapshot consumed by package
// kernelversions.
//
// It fetches the BCC kernel-versions.md document and the libbpf UAPI bpf.h
// header at pinned commits, parses the helper / program-type / map-type
// tables, cross-validates that every BPF_FUNC_* / BPF_PROG_TYPE_* /
// BPF_MAP_TYPE_* enum value present in the UAPI header has a corresponding
// row in the BCC table, then emits source.json and tables.go in the parent
// package directory.
//
// Usage:
//
//	go run ./internal/kernelversions/cmd/kvgen \
//	    --bcc-commit=<sha> --kernel-commit=<sha> \
//	    --output-dir=internal/kernelversions
//
// Defaults are the pinned commits embedded at the top of this file. Run
// without flags to refresh against those pins; override flags only when
// preparing a snapshot bump.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Default pins. Bumped by the scheduled refresh workflow when upstream
// changes; do not edit by hand.
const (
	defaultBCCCommit    = "91c1e8ee5f5a5b85d3bfe8e35d11fa0a6d3b5e52"
	defaultKernelCommit = "c7e4e4d5f7dc2daa439303d1b5bf6bdfaa249f49"
)

// main is the CLI entrypoint. Network-bound; not exercised by unit tests.
// coverage:ignore
func main() {
	bccCommit := flag.String("bcc-commit", defaultBCCCommit, "iovisor/bcc commit SHA to fetch kernel-versions.md from")
	kernelCommit := flag.String("kernel-commit", defaultKernelCommit, "torvalds/linux commit SHA to fetch include/uapi/linux/bpf.h from")
	outputDir := flag.String("output-dir", "internal/kernelversions", "directory to write source.json and tables.go into")
	flag.Parse()

	if err := run(*bccCommit, *kernelCommit, *outputDir); err != nil {
		fmt.Fprintln(os.Stderr, "kvgen:", err)
		os.Exit(1)
	}
}

// run drives the generator end to end. The two HTTP fetches make this
// network-bound, so it is excluded from per-file coverage gating; the
// individual parser/validator/emitter steps are exercised separately.
// coverage:ignore
func run(bccCommit, kernelCommit, outputDir string) error {
	bccURL := fmt.Sprintf("https://raw.githubusercontent.com/iovisor/bcc/%s/docs/kernel-versions.md", bccCommit)
	bccBody, err := fetch(bccURL)
	if err != nil {
		return fmt.Errorf("fetch BCC kernel-versions.md: %w", err)
	}
	kernelURL := fmt.Sprintf("https://raw.githubusercontent.com/torvalds/linux/%s/include/uapi/linux/bpf.h", kernelCommit)
	kernelBody, err := fetch(kernelURL)
	if err != nil {
		return fmt.Errorf("fetch UAPI bpf.h: %w", err)
	}

	bcc, err := parseBCC(bccBody)
	if err != nil {
		return fmt.Errorf("parse BCC markdown: %w", err)
	}
	uapi, err := parseUAPI(kernelBody)
	if err != nil {
		return fmt.Errorf("parse UAPI header: %w", err)
	}
	if err := validate(bcc, uapi); err != nil {
		return fmt.Errorf("cross-validate UAPI vs BCC: %w", err)
	}

	src := buildSource(bcc, bccCommit, kernelCommit)
	if err := writeSourceJSON(filepath.Join(outputDir, "source.json"), src); err != nil {
		return fmt.Errorf("write source.json: %w", err)
	}
	if err := writeTablesGo(filepath.Join(outputDir, "tables.go"), src); err != nil {
		return fmt.Errorf("write tables.go: %w", err)
	}
	return nil
}

// fetch performs an HTTP GET. Network-bound; coverage gated by run.
// coverage:ignore
func fetch(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
