// covercheck enforces a minimum per-file statement-coverage threshold
// on the files added (or otherwise gated) by a feature branch.
//
// It reads a Go coverage profile, scans the corresponding source files
// for `// coverage:ignore` markers attached to function declarations,
// excludes those functions from the denominator, and fails (exit 1) if
// any gated file's adjusted coverage is below the threshold.
//
// Usage:
//
//	covercheck --profile=<file> --threshold=<float> [--file=<glob>...]
//
// `--file` may be repeated. Each value is a path glob matching the file
// portion of a coverage entry (e.g. `probe_elf*.go`). When no `--file`
// is supplied, every file in the profile is gated.
//
// The marker syntax is a single-line comment `// coverage:ignore`
// placed on its own line in the doc comment immediately above a
// `func` declaration. The marker excludes the entire function body
// (every statement attributed to the matching covered range) from
// both the numerator and the denominator.
//
// This tool is intended to be invoked from `make cover-check`. It is
// network-free and has no external dependencies beyond the Go
// standard library and `golang.org/x/tools/cover`.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

func main() {
	profile := flag.String("profile", "", "path to the Go coverage profile (required)")
	threshold := flag.Float64("threshold", 90.0, "minimum per-file coverage percentage")
	var files multiFlag
	flag.Var(&files, "file", "glob to gate (matches the file portion of a profile entry; may be repeated)")
	flag.Parse()

	if *profile == "" {
		fmt.Fprintln(os.Stderr, "covercheck: --profile is required")
		os.Exit(2)
	}

	profiles, err := cover.ParseProfiles(*profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "covercheck: parse profile: %v\n", err)
		os.Exit(2)
	}

	type fileResult struct {
		Name      string
		Covered   int
		Total     int
		Ignored   int
		Threshold float64
	}
	var results []fileResult
	failures := 0

	for _, p := range profiles {
		if !matchesAny(p.FileName, files) {
			continue
		}
		srcPath, err := resolveSource(p.FileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "covercheck: %s: %v\n", p.FileName, err)
			os.Exit(2)
		}
		ignoredRanges, err := collectIgnoredRanges(srcPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "covercheck: %s: %v\n", p.FileName, err)
			os.Exit(2)
		}

		var covered, total, ignored int
		for _, b := range p.Blocks {
			if rangesContain(ignoredRanges, b.StartLine) {
				ignored += b.NumStmt
				continue
			}
			total += b.NumStmt
			if b.Count > 0 {
				covered += b.NumStmt
			}
		}

		results = append(results, fileResult{
			Name:      p.FileName,
			Covered:   covered,
			Total:     total,
			Ignored:   ignored,
			Threshold: *threshold,
		})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	fmt.Println("File                                                         Covered  Total  Ignored  %")
	fmt.Println("-----------------------------------------------------------  -------  -----  -------  -----")
	for _, r := range results {
		pct := 100.0
		if r.Total > 0 {
			pct = 100.0 * float64(r.Covered) / float64(r.Total)
		}
		flag := " "
		if r.Total > 0 && pct < r.Threshold {
			flag = "x"
			failures++
		}
		fmt.Printf("%s %-58s  %7d  %5d  %7d  %5.1f\n", flag, shorten(r.Name), r.Covered, r.Total, r.Ignored, pct)
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "covercheck: no files matched the supplied --file globs")
		os.Exit(2)
	}

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "\ncovercheck: %d file(s) below %.1f%% threshold\n", failures, *threshold)
		os.Exit(1)
	}
	fmt.Printf("\ncovercheck: all %d gated file(s) at or above %.1f%% threshold\n", len(results), *threshold)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// matchesAny reports whether profileFile matches any of the supplied
// globs. An empty patterns list matches everything (so a bare
// `--profile` invocation is a full sweep).
func matchesAny(profileFile string, patterns multiFlag) bool {
	if len(patterns) == 0 {
		return true
	}
	base := filepath.Base(profileFile)
	for _, pat := range patterns {
		// Match against (a) the full profile path, (b) the bare
		// basename for the `probe_elf*.go` shorthand, and (c) any
		// path suffix so `internal/kernelversions/kernelversions.go`
		// matches the module-prefixed profile entry without forcing
		// callers to spell out the module path.
		if ok, _ := filepath.Match(pat, profileFile); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
		if strings.HasSuffix(profileFile, "/"+pat) {
			return true
		}
	}
	return false
}

// resolveSource turns a coverage profile's file label (always a Go
// import path joined with the file basename) into an absolute path
// rooted at the current working directory's module.
func resolveSource(profileFile string) (string, error) {
	// The profile labels look like "github.com/leodido/kfeatures/foo.go".
	// We want "./foo.go" (or "./internal/.../foo.go") relative to the
	// module root, which is the working directory of `go test`.
	// Strip the module path prefix; if it doesn't match, fall back to
	// the basename (kvgen-style internal packages already include the
	// subdir suffix).
	mod, err := moduleImportPath()
	if err != nil {
		return "", err
	}
	rel := strings.TrimPrefix(profileFile, mod+"/")
	if rel == profileFile {
		return "", fmt.Errorf("profile entry %q does not start with module path %q", profileFile, mod)
	}
	if _, err := os.Stat(rel); err != nil {
		return "", fmt.Errorf("source not found at %s: %w", rel, err)
	}
	return rel, nil
}

// moduleImportPath reads go.mod and returns the declared module path.
func moduleImportPath() (string, error) {
	body, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module")), nil
		}
	}
	return "", fmt.Errorf("module directive not found in go.mod")
}

// lineRange describes an inclusive [start, end] line range in a Go file.
type lineRange struct{ start, end int }

// collectIgnoredRanges parses src and returns the line ranges of every
// function whose doc comment (or a free-floating comment immediately
// above the func keyword) contains a line equal to `// coverage:ignore`.
func collectIgnoredRanges(src string) ([]lineRange, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", src, err)
	}

	// Index every comment group by the line *immediately following* its
	// last line. This lets us look up "is there an ignore-marker
	// comment directly above this function?" in O(1) per func.
	commentsByNextLine := make(map[int]*ast.CommentGroup, len(f.Comments))
	for _, cg := range f.Comments {
		nextLine := fset.Position(cg.End()).Line + 1
		commentsByNextLine[nextLine] = cg
	}

	var out []lineRange
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			line := fset.Position(d.Pos()).Line
			group := d.Doc
			if group == nil {
				group = commentsByNextLine[line]
			}
			if group == nil || !hasIgnoreMarker(group) {
				continue
			}
			out = append(out, lineRange{
				start: line,
				end:   fset.Position(d.End()).Line,
			})
		case *ast.GenDecl:
			// Cover `var foo = func(...) { ... }` (and the `const`
			// equivalent) so test-time stubbed function variables can
			// be opted out the same way as named functions.
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			line := fset.Position(d.Pos()).Line
			group := d.Doc
			if group == nil {
				group = commentsByNextLine[line]
			}
			if group == nil || !hasIgnoreMarker(group) {
				continue
			}
			for _, sp := range d.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, val := range vs.Values {
					fn, ok := val.(*ast.FuncLit)
					if !ok {
						continue
					}
					out = append(out, lineRange{
						start: fset.Position(fn.Pos()).Line,
						end:   fset.Position(fn.End()).Line,
					})
				}
			}
		}
	}
	return out, nil
}

func hasIgnoreMarker(g *ast.CommentGroup) bool {
	for _, c := range g.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if text == "coverage:ignore" {
			return true
		}
	}
	return false
}

func rangesContain(rs []lineRange, line int) bool {
	for _, r := range rs {
		if line >= r.start && line <= r.end {
			return true
		}
	}
	return false
}

func shorten(name string) string {
	const maxLen = 58
	if len(name) <= maxLen {
		return name
	}
	return "..." + name[len(name)-maxLen+3:]
}
