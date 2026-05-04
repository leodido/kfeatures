package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSource(t *testing.T) {
	bcc := &bccTables{
		Helpers:      map[string]kernelVersion{"bind": {4, 17}, "ktime_get_ns": {3, 18}},
		ProgramTypes: map[string]kernelVersion{"BPF_PROG_TYPE_KPROBE": {4, 1}, "BPF_PROG_TYPE_XDP": {4, 8}},
		MapTypes:     map[string]kernelVersion{"BPF_MAP_TYPE_HASH": {3, 19}, "BPF_MAP_TYPE_RINGBUF": {5, 8}},
	}
	src := buildSource(bcc, "bcc-sha", "kernel-sha")
	if src.BCCCommit != "bcc-sha" || src.KernelCommit != "kernel-sha" {
		t.Fatalf("commits not propagated: %+v", src)
	}
	// Helpers must be sorted by UAPI name.
	if len(src.Helpers) != 2 || src.Helpers[0].UAPI != "BPF_FUNC_bind" || src.Helpers[1].UAPI != "BPF_FUNC_ktime_get_ns" {
		t.Fatalf("helpers not sorted: %+v", src.Helpers)
	}
	if src.Helpers[0].GoConst != "FnBind" {
		t.Errorf("helper Go const = %q, want FnBind", src.Helpers[0].GoConst)
	}
	if src.Helpers[1].GoConst != "FnKtimeGetNs" {
		t.Errorf("helper Go const = %q, want FnKtimeGetNs", src.Helpers[1].GoConst)
	}
	// ProgramTypes sorted by UAPI; mapping uses ciliumProgTypeName.
	if src.ProgramTypes[0].GoConst != "Kprobe" || src.ProgramTypes[1].GoConst != "XDP" {
		t.Errorf("prog type names = %+v", src.ProgramTypes)
	}
	if src.MapTypes[0].GoConst != "Hash" || src.MapTypes[1].GoConst != "RingBuf" {
		t.Errorf("map type names = %+v", src.MapTypes)
	}
}

func TestWriteSourceJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.json")
	src := &source{BCCCommit: "x", KernelCommit: "y"}
	if err := writeSourceJSON(path, src); err != nil {
		t.Fatalf("writeSourceJSON: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var roundtrip source
	if err := json.Unmarshal(body, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundtrip.BCCCommit != "x" {
		t.Errorf("roundtrip BCC commit = %q", roundtrip.BCCCommit)
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Errorf("expected trailing newline")
	}
}

func TestWriteTablesGoFormatsAndCompiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tables.go")
	src := &source{
		BCCCommit:    "abc",
		KernelCommit: "def",
		Helpers:      []helperRow{{UAPI: "BPF_FUNC_bind", GoConst: "FnBind", Version: kernelVersion{4, 17}}},
		ProgramTypes: []enumRow{{UAPI: "BPF_PROG_TYPE_KPROBE", GoConst: "Kprobe", Version: kernelVersion{4, 1}}},
		MapTypes:     []enumRow{{UAPI: "BPF_MAP_TYPE_HASH", GoConst: "Hash", Version: kernelVersion{3, 19}}},
	}
	if err := writeTablesGo(path, src); err != nil {
		t.Fatalf("writeTablesGo: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(body)
	for _, want := range []string{"package kernelversions", "asm.FnBind", "ebpf.Kprobe", "ebpf.Hash", "BCC commit:    abc", "Kernel commit: def"} {
		if !strings.Contains(got, want) {
			t.Errorf("tables.go missing %q\n%s", want, got)
		}
	}
}

func TestCiliumProgTypeNameAllCases(t *testing.T) {
	cases := map[string]string{
		"BPF_PROG_TYPE_SOCKET_FILTER":           "SocketFilter",
		"BPF_PROG_TYPE_KPROBE":                  "Kprobe",
		"BPF_PROG_TYPE_SCHED_CLS":               "SchedCLS",
		"BPF_PROG_TYPE_SCHED_ACT":               "SchedACT",
		"BPF_PROG_TYPE_TRACEPOINT":              "TracePoint",
		"BPF_PROG_TYPE_XDP":                     "XDP",
		"BPF_PROG_TYPE_PERF_EVENT":              "PerfEvent",
		"BPF_PROG_TYPE_CGROUP_SKB":              "CGroupSKB",
		"BPF_PROG_TYPE_CGROUP_SOCK":             "CGroupSock",
		"BPF_PROG_TYPE_LWT_IN":                  "LWTIn",
		"BPF_PROG_TYPE_LWT_OUT":                 "LWTOut",
		"BPF_PROG_TYPE_LWT_XMIT":                "LWTXmit",
		"BPF_PROG_TYPE_SOCK_OPS":                "SockOps",
		"BPF_PROG_TYPE_SK_SKB":                  "SkSKB",
		"BPF_PROG_TYPE_CGROUP_DEVICE":           "CGroupDevice",
		"BPF_PROG_TYPE_SK_MSG":                  "SkMsg",
		"BPF_PROG_TYPE_RAW_TRACEPOINT":          "RawTracepoint",
		"BPF_PROG_TYPE_CGROUP_SOCK_ADDR":        "CGroupSockAddr",
		"BPF_PROG_TYPE_LWT_SEG6LOCAL":           "LWTSeg6Local",
		"BPF_PROG_TYPE_LIRC_MODE2":              "LircMode2",
		"BPF_PROG_TYPE_SK_REUSEPORT":            "SkReuseport",
		"BPF_PROG_TYPE_FLOW_DISSECTOR":          "FlowDissector",
		"BPF_PROG_TYPE_CGROUP_SYSCTL":           "CGroupSysctl",
		"BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE": "RawTracepointWritable",
		"BPF_PROG_TYPE_CGROUP_SOCKOPT":          "CGroupSockopt",
		"BPF_PROG_TYPE_TRACING":                 "Tracing",
		"BPF_PROG_TYPE_STRUCT_OPS":              "StructOps",
		"BPF_PROG_TYPE_EXT":                     "Extension",
		"BPF_PROG_TYPE_LSM":                     "LSM",
		"BPF_PROG_TYPE_SK_LOOKUP":               "SkLookup",
		"BPF_PROG_TYPE_SYSCALL":                 "Syscall",
		"BPF_PROG_TYPE_NETFILTER":               "Netfilter",
		"BPF_PROG_TYPE_DOES_NOT_EXIST":          "",
	}
	for in, want := range cases {
		if got := ciliumProgTypeName(in); got != want {
			t.Errorf("ciliumProgTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCiliumMapTypeNameAllCases(t *testing.T) {
	cases := map[string]string{
		"BPF_MAP_TYPE_HASH":                  "Hash",
		"BPF_MAP_TYPE_ARRAY":                 "Array",
		"BPF_MAP_TYPE_PROG_ARRAY":            "ProgramArray",
		"BPF_MAP_TYPE_PERF_EVENT_ARRAY":      "PerfEventArray",
		"BPF_MAP_TYPE_PERCPU_HASH":           "PerCPUHash",
		"BPF_MAP_TYPE_PERCPU_ARRAY":          "PerCPUArray",
		"BPF_MAP_TYPE_STACK_TRACE":           "StackTrace",
		"BPF_MAP_TYPE_CGROUP_ARRAY":          "CGroupArray",
		"BPF_MAP_TYPE_LRU_HASH":              "LRUHash",
		"BPF_MAP_TYPE_LRU_PERCPU_HASH":       "LRUCPUHash",
		"BPF_MAP_TYPE_LPM_TRIE":              "LPMTrie",
		"BPF_MAP_TYPE_ARRAY_OF_MAPS":         "ArrayOfMaps",
		"BPF_MAP_TYPE_HASH_OF_MAPS":          "HashOfMaps",
		"BPF_MAP_TYPE_DEVMAP":                "DevMap",
		"BPF_MAP_TYPE_SOCKMAP":               "SockMap",
		"BPF_MAP_TYPE_CPUMAP":                "CPUMap",
		"BPF_MAP_TYPE_XSKMAP":                "XSKMap",
		"BPF_MAP_TYPE_SOCKHASH":              "SockHash",
		"BPF_MAP_TYPE_CGROUP_STORAGE":        "CGroupStorage",
		"BPF_MAP_TYPE_REUSEPORT_SOCKARRAY":   "ReusePortSockArray",
		"BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE": "PerCPUCGroupStorage",
		"BPF_MAP_TYPE_QUEUE":                 "Queue",
		"BPF_MAP_TYPE_STACK":                 "Stack",
		"BPF_MAP_TYPE_SK_STORAGE":            "SkStorage",
		"BPF_MAP_TYPE_DEVMAP_HASH":           "DevMapHash",
		"BPF_MAP_TYPE_STRUCT_OPS":            "StructOpsMap",
		"BPF_MAP_TYPE_RINGBUF":               "RingBuf",
		"BPF_MAP_TYPE_INODE_STORAGE":         "InodeStorage",
		"BPF_MAP_TYPE_TASK_STORAGE":          "TaskStorage",
		"BPF_MAP_TYPE_BLOOM_FILTER":          "BloomFilter",
		"BPF_MAP_TYPE_USER_RINGBUF":          "UserRingbuf",
		"BPF_MAP_TYPE_CGRP_STORAGE":          "CgroupStorage",
		"BPF_MAP_TYPE_ARENA":                 "Arena",
		"BPF_MAP_TYPE_DOES_NOT_EXIST":        "",
	}
	for in, want := range cases {
		if got := ciliumMapTypeName(in); got != want {
			t.Errorf("ciliumMapTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}
