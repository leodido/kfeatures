package main

import "testing"

func TestCiliumHasHelper(t *testing.T) {
	if !ciliumHasHelper("FnBind") {
		t.Errorf("FnBind should be present in cilium/ebpf")
	}
	if ciliumHasHelper("FnDoesNotExist") {
		t.Errorf("FnDoesNotExist should not be present")
	}
}

func TestCiliumHasProgType(t *testing.T) {
	if !ciliumHasProgType("Kprobe") {
		t.Errorf("Kprobe should be present in cilium/ebpf")
	}
	if !ciliumHasProgType("XDP") {
		t.Errorf("XDP should be present in cilium/ebpf")
	}
	if ciliumHasProgType("DoesNotExist") {
		t.Errorf("DoesNotExist should not be present")
	}
}

func TestCiliumHasMapType(t *testing.T) {
	if !ciliumHasMapType("Hash") {
		t.Errorf("Hash should be present in cilium/ebpf")
	}
	if !ciliumHasMapType("RingBuf") {
		t.Errorf("RingBuf should be present in cilium/ebpf")
	}
	if ciliumHasMapType("DoesNotExist") {
		t.Errorf("DoesNotExist should not be present")
	}
}
