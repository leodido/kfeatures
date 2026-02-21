#!/usr/bin/env bats
# Linux-only CLI tests — require a real kernel.

load helper

setup_file() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        skip "requires Linux"
    fi
    build_kfeatures
}

# --- version ---

@test "version: shows tool identity and kernel" {
    run "$KFEATURES_BIN" version
    assert_success
    assert_output --partial "kfeatures (dev)"
    assert_output --partial "Kernel:"
}

# --- probe ---

@test "probe: returns kernel data" {
    run "$KFEATURES_BIN" probe
    assert_success
    assert_output --partial "Kernel:"
    assert_output --partial "bpf():"
}

@test "probe --json: returns valid JSON" {
    run "$KFEATURES_BIN" probe --json
    assert_success
    echo "$output" | python3 -c "import sys,json; json.load(sys.stdin)"
}

# --- check ---

@test "check: bpf-syscall is satisfied" {
    run "$KFEATURES_BIN" check --require bpf-syscall
    assert_success
}

@test "check --json: bpf-syscall ok is true" {
    run "$KFEATURES_BIN" check --require bpf-syscall --json
    assert_success
    echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True"
}

@test "check: require parsing is case-insensitive" {
    run "$KFEATURES_BIN" check --require BPF-SYSCALL
    assert_success
}

@test "check: unknown feature is rejected" {
    run "$KFEATURES_BIN" check --require nonexistent
    assert_failure
    assert_output --partial "unknown feature"
}

# --- config ---

@test "config: does not crash" {
    # config may exit 1 if /proc/config.gz is unavailable;
    # we only verify the binary does not segfault / panic.
    run "$KFEATURES_BIN" config
    [[ "$status" -eq 0 || "$status" -eq 1 ]]
}
