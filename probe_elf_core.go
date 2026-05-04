package kfeatures

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Compile-time assertions: keep the unused import for btf clearly used
// (for CORERelocationMetadata). See lineInfo for why btf.LineInfoMetadata
// is not currently called.
var _ = btf.CORERelocationMetadata

// regProvenance is the inferred origin of the value currently held by a
// register. The classifier tracks per-register provenance through a
// linear single-pass walk of the instruction stream.
//
// This is heuristic, not a verifier: branches and loops are conservatively
// flattened, and provenance inferred from a memory load whose source
// register is itself uncategorized propagates as uncategorized. The aim is
// to surface obvious "you forgot BPF_CORE_READ" mistakes, not to
// reproduce the in-kernel verifier's reachability analysis.
type regProvenance int

const (
	provUnknown regProvenance = iota
	provContext               // R1 at function entry; pointer to ctx
	provMapValue              // pointer returned by bpf_map_lookup_elem and friends
	provKernelDirect          // pointer returned by helpers like bpf_get_current_task
	provCOREProtected         // pointer carried via a CORE-relocated load
)

// memoryAccessKind labels what the classifier inferred about a single
// pointer dereference. accessNotLoad is the zero value and means the
// instruction at this position is not a memory load (the slot is skipped
// when summing per-program counters).
type memoryAccessKind int

const (
	accessNotLoad memoryAccessKind = iota
	accessUncategorized
	accessContextSafe
	accessMapValueSafe
	accessKernelDirect
	accessCOREProtected
)

func init() {
	classifyMemoryAccesses = computeMemoryAccessSummary
	coreWarnings = computeCOREWarnings
}

// computeMemoryAccessSummary walks the program once and returns the
// per-program counters surfaced via [MemoryAccessSummary].
func computeMemoryAccessSummary(prog *ebpf.ProgramSpec) MemoryAccessSummary {
	if prog == nil {
		return MemoryAccessSummary{}
	}
	classes := classifyProgram(prog)
	summary := MemoryAccessSummary{}
	for _, k := range classes {
		switch k {
		case accessNotLoad:
			continue
		case accessContextSafe:
			summary.ContextSafe++
		case accessMapValueSafe:
			summary.MapValueSafe++
		case accessKernelDirect:
			summary.KernelDirect++
		case accessCOREProtected:
			summary.COREProtected++
		default:
			summary.Uncategorized++
		}
		summary.Total++
	}
	return summary
}

// computeCOREWarnings emits one warning per kernel-direct load that the
// classifier flagged. The intent is to nudge the user toward CO-RE.
func computeCOREWarnings(progName string, prog *ebpf.ProgramSpec) []ELFWarning {
	if prog == nil {
		return nil
	}
	classes := classifyProgram(prog)
	var out []ELFWarning
	for i, k := range classes {
		if k != accessKernelDirect {
			continue
		}
		// Look up source-info if the program carries it. cilium's
		// LineInfo.Source() returns "" when no info attached, which is
		// fine — we drop file/line in that case.
		ins := prog.Instructions[i]
		file, line := lineInfo(ins)
		out = append(out, ELFWarning{
			Severity: "warning",
			Program:  progName,
			File:     file,
			Line:     line,
			Message:  fmt.Sprintf("kernel pointer dereferenced without CO-RE protection at instruction %d", i),
			Detail:   "consider using BPF_CORE_READ() / bpf_probe_read_kernel() to protect against kernel struct layout changes",
		})
	}
	return out
}

// classifyProgram walks prog.Instructions once and returns a per-instruction
// classification slice. Non-load instructions classify as accessUncategorized
// (the value is meaningful only for memory-load opcodes; consumers iterate
// alongside the original instructions).
func classifyProgram(prog *ebpf.ProgramSpec) []memoryAccessKind {
	insns := prog.Instructions
	classes := make([]memoryAccessKind, len(insns))
	regs := make(map[asm.Register]regProvenance, 16)
	regs[asm.R1] = provContext // BPF ABI: R1 holds *ctx at entry

	for i := range insns {
		ins := insns[i]
		op := ins.OpCode
		// CO-RE-relocated load: mark dest as CORE-protected and
		// classify this access as CORE-protected too.
		if btf.CORERelocationMetadata(&insns[i]) != nil {
			classes[i] = accessCOREProtected
			regs[ins.Dst] = provCOREProtected
			continue
		}
		// Memory load (LdXClass + MemMode). Classify by source-register
		// provenance; propagate to dst.
		if op.Class() == asm.LdXClass && op.Mode() == asm.MemMode {
			classes[i] = classifyAccess(regs[ins.Src])
			regs[ins.Dst] = inheritFromSource(regs[ins.Src])
			continue
		}
		// Helper call: R0 receives helper return value; classify R0.
		if ins.IsBuiltinCall() {
			helper := asm.BuiltinFunc(ins.Constant)
			regs[asm.R0] = provenanceForHelper(helper)
			// R1-R5 are clobbered by the call (BPF ABI).
			delete(regs, asm.R1)
			delete(regs, asm.R2)
			delete(regs, asm.R3)
			delete(regs, asm.R4)
			delete(regs, asm.R5)
			continue
		}
		// Plain register-to-register move: propagate provenance.
		if op.Class() == asm.ALU64Class && op.ALUOp() == asm.Mov {
			regs[ins.Dst] = regs[ins.Src]
			continue
		}
	}
	return classes
}

// classifyAccess maps a source-register provenance to a memory-access
// classification. Always returns one of the load classifications (never
// accessNotLoad), since the caller has already determined this is a load
// instruction.
func classifyAccess(p regProvenance) memoryAccessKind {
	switch p {
	case provContext:
		return accessContextSafe
	case provMapValue:
		return accessMapValueSafe
	case provKernelDirect:
		return accessKernelDirect
	case provCOREProtected:
		return accessCOREProtected
	default:
		return accessUncategorized
	}
}

// inheritFromSource decides what provenance to propagate to the
// destination register when loading from a typed source. The default is
// to keep the source classification, on the assumption that loading
// "ctx->skb->data" still yields a context-derived pointer; the kernel-
// direct chain remains kernel-direct so that follow-up loads continue
// to warn.
func inheritFromSource(p regProvenance) regProvenance {
	switch p {
	case provContext, provCOREProtected, provKernelDirect, provMapValue:
		return p
	default:
		return provUnknown
	}
}

// provenanceForHelper assigns R0's provenance after a helper call. The
// table is intentionally small: the classifier degrades to provUnknown
// for any helper not enumerated here.
func provenanceForHelper(fn asm.BuiltinFunc) regProvenance {
	switch fn {
	case asm.FnMapLookupElem:
		return provMapValue
	case asm.FnGetCurrentTask, asm.FnGetCurrentTaskBtf:
		return provKernelDirect
	}
	return provUnknown
}

// lineInfo extracts file/line from BTF source-info metadata attached to
// ins. cilium/ebpf v0.20 does not yet expose per-instruction line info as
// public Metadata, so this returns empty values; once exposed, callers
// will get file:line in [ELFWarning] without further changes.
func lineInfo(ins asm.Instruction) (string, uint32) {
	_ = ins
	return "", 0
}
