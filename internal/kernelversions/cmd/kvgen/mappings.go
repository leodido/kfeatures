package main

// ciliumProgTypeName maps a UAPI BPF_PROG_TYPE_* identifier to the
// corresponding exported constant in package github.com/cilium/ebpf.
//
// cilium/ebpf uses domain-friendly names (e.g. Kprobe, SchedCLS) instead
// of the verbose BPF_PROG_TYPE_KPROBE form. The mapping is intentionally
// explicit: a mechanical transformation would silently miscompile when
// cilium chooses a non-canonical Go name for a new type.
//
// Entries are added when a new program type lands in cilium/ebpf. Until
// then the snapshot omits the row (the lookup returns false).
func ciliumProgTypeName(uapi string) string {
	switch uapi {
	case "BPF_PROG_TYPE_SOCKET_FILTER":
		return "SocketFilter"
	case "BPF_PROG_TYPE_KPROBE":
		return "Kprobe"
	case "BPF_PROG_TYPE_SCHED_CLS":
		return "SchedCLS"
	case "BPF_PROG_TYPE_SCHED_ACT":
		return "SchedACT"
	case "BPF_PROG_TYPE_TRACEPOINT":
		return "TracePoint"
	case "BPF_PROG_TYPE_XDP":
		return "XDP"
	case "BPF_PROG_TYPE_PERF_EVENT":
		return "PerfEvent"
	case "BPF_PROG_TYPE_CGROUP_SKB":
		return "CGroupSKB"
	case "BPF_PROG_TYPE_CGROUP_SOCK":
		return "CGroupSock"
	case "BPF_PROG_TYPE_LWT_IN":
		return "LWTIn"
	case "BPF_PROG_TYPE_LWT_OUT":
		return "LWTOut"
	case "BPF_PROG_TYPE_LWT_XMIT":
		return "LWTXmit"
	case "BPF_PROG_TYPE_SOCK_OPS":
		return "SockOps"
	case "BPF_PROG_TYPE_SK_SKB":
		return "SkSKB"
	case "BPF_PROG_TYPE_CGROUP_DEVICE":
		return "CGroupDevice"
	case "BPF_PROG_TYPE_SK_MSG":
		return "SkMsg"
	case "BPF_PROG_TYPE_RAW_TRACEPOINT":
		return "RawTracepoint"
	case "BPF_PROG_TYPE_CGROUP_SOCK_ADDR":
		return "CGroupSockAddr"
	case "BPF_PROG_TYPE_LWT_SEG6LOCAL":
		return "LWTSeg6Local"
	case "BPF_PROG_TYPE_LIRC_MODE2":
		return "LircMode2"
	case "BPF_PROG_TYPE_SK_REUSEPORT":
		return "SkReuseport"
	case "BPF_PROG_TYPE_FLOW_DISSECTOR":
		return "FlowDissector"
	case "BPF_PROG_TYPE_CGROUP_SYSCTL":
		return "CGroupSysctl"
	case "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE":
		return "RawTracepointWritable"
	case "BPF_PROG_TYPE_CGROUP_SOCKOPT":
		return "CGroupSockopt"
	case "BPF_PROG_TYPE_TRACING":
		return "Tracing"
	case "BPF_PROG_TYPE_STRUCT_OPS":
		return "StructOps"
	case "BPF_PROG_TYPE_EXT":
		return "Extension"
	case "BPF_PROG_TYPE_LSM":
		return "LSM"
	case "BPF_PROG_TYPE_SK_LOOKUP":
		return "SkLookup"
	case "BPF_PROG_TYPE_SYSCALL":
		return "Syscall"
	case "BPF_PROG_TYPE_NETFILTER":
		return "Netfilter"
	}
	return ""
}

// ciliumMapTypeName maps a UAPI BPF_MAP_TYPE_* identifier to the
// corresponding exported constant in package github.com/cilium/ebpf.
func ciliumMapTypeName(uapi string) string {
	switch uapi {
	case "BPF_MAP_TYPE_HASH":
		return "Hash"
	case "BPF_MAP_TYPE_ARRAY":
		return "Array"
	case "BPF_MAP_TYPE_PROG_ARRAY":
		return "ProgramArray"
	case "BPF_MAP_TYPE_PERF_EVENT_ARRAY":
		return "PerfEventArray"
	case "BPF_MAP_TYPE_PERCPU_HASH":
		return "PerCPUHash"
	case "BPF_MAP_TYPE_PERCPU_ARRAY":
		return "PerCPUArray"
	case "BPF_MAP_TYPE_STACK_TRACE":
		return "StackTrace"
	case "BPF_MAP_TYPE_CGROUP_ARRAY":
		return "CGroupArray"
	case "BPF_MAP_TYPE_LRU_HASH":
		return "LRUHash"
	case "BPF_MAP_TYPE_LRU_PERCPU_HASH":
		return "LRUCPUHash"
	case "BPF_MAP_TYPE_LPM_TRIE":
		return "LPMTrie"
	case "BPF_MAP_TYPE_ARRAY_OF_MAPS":
		return "ArrayOfMaps"
	case "BPF_MAP_TYPE_HASH_OF_MAPS":
		return "HashOfMaps"
	case "BPF_MAP_TYPE_DEVMAP":
		return "DevMap"
	case "BPF_MAP_TYPE_SOCKMAP":
		return "SockMap"
	case "BPF_MAP_TYPE_CPUMAP":
		return "CPUMap"
	case "BPF_MAP_TYPE_XSKMAP":
		return "XSKMap"
	case "BPF_MAP_TYPE_SOCKHASH":
		return "SockHash"
	case "BPF_MAP_TYPE_CGROUP_STORAGE":
		return "CGroupStorage"
	case "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY":
		return "ReusePortSockArray"
	case "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE":
		return "PerCPUCGroupStorage"
	case "BPF_MAP_TYPE_QUEUE":
		return "Queue"
	case "BPF_MAP_TYPE_STACK":
		return "Stack"
	case "BPF_MAP_TYPE_SK_STORAGE":
		return "SkStorage"
	case "BPF_MAP_TYPE_DEVMAP_HASH":
		return "DevMapHash"
	case "BPF_MAP_TYPE_STRUCT_OPS":
		return "StructOpsMap"
	case "BPF_MAP_TYPE_RINGBUF":
		return "RingBuf"
	case "BPF_MAP_TYPE_INODE_STORAGE":
		return "InodeStorage"
	case "BPF_MAP_TYPE_TASK_STORAGE":
		return "TaskStorage"
	case "BPF_MAP_TYPE_BLOOM_FILTER":
		return "BloomFilter"
	case "BPF_MAP_TYPE_USER_RINGBUF":
		return "UserRingbuf"
	case "BPF_MAP_TYPE_CGRP_STORAGE":
		return "CgroupStorage"
	case "BPF_MAP_TYPE_ARENA":
		return "Arena"
	}
	return ""
}
