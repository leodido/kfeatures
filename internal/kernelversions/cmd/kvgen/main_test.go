package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEmitsOnlyTablesGo(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body string
		switch {
		case strings.Contains(req.URL.Path, "/iovisor/bcc/"):
			body = minimalBCCMarkdown()
		case strings.Contains(req.URL.Path, "/torvalds/linux/"):
			body = minimalUAPIHeader()
		default:
			t.Fatalf("unexpected fetch URL: %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
	})

	resetCiliumNameCache(t)
	ciliumLoadOnce.Do(func() {
		ciliumHelpers = map[string]struct{}{"FnBind": {}}
		ciliumProgTypes = map[string]struct{}{"Kprobe": {}}
		ciliumMapTypes = map[string]struct{}{"Hash": {}}
	})

	dir := t.TempDir()
	if err := run("bcc-sha", "kernel-sha", dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tables.go")); err != nil {
		t.Fatalf("tables.go not emitted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "source.json")); !os.IsNotExist(err) {
		t.Fatalf("source.json should not be emitted, stat err = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func minimalBCCMarkdown() string {
	return `# header

## Helpers

Helper | Kernel version | License | Commit |
-------|----------------|---------|--------|
` + "`BPF_FUNC_bind()`" + ` | 4.17 |  | [` + "`d74bad4e74ee`" + `]

## Maps

### Map types

 Map type | Kernel version | Commit | Enum
----------|----------------|--------|------
Hash                            | 3.19 | [` + "`xx`" + `] | BPF_MAP_TYPE_HASH

## Main features

### Program types

Program type | Kernel version | Commit | Enum
-------------|----------------|--------|-----
Kprobe                         | 4.1  | [` + "`zz`" + `] | BPF_PROG_TYPE_KPROBE
`
}

func minimalUAPIHeader() string {
	return `
#define ___BPF_FUNC_MAPPER(FN, ctx...)\
	FN(unspec, 0, ##ctx)				\
	FN(bind, 2, ##ctx)

enum bpf_map_type {
	BPF_MAP_TYPE_HASH,
	__MAX_BPF_MAP_TYPE
};

enum bpf_prog_type {
	BPF_PROG_TYPE_KPROBE,
	__MAX_BPF_PROG_TYPE
};
`
}
