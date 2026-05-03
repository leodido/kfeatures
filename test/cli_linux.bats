#!/usr/bin/env bats
# Linux-only CLI tests: require a real kernel.

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

@test "config: missing kernel config emits structcli envelope on stderr" {
    # Only meaningful when the runner cannot read kernel config
    # from any of the sources readKernelConfig probes (config.go):
    # /proc/config.gz, /boot/config-$(uname -r),
    # /lib/modules/$(uname -r)/config. On hosts where one IS
    # readable this path simply isn't exercised.
    local rel
    rel="$(uname -r)"
    if [[ -r /proc/config.gz ]] \
        || [[ -r "/boot/config-${rel}" ]] \
        || [[ -r "/lib/modules/${rel}/config" ]]; then
        skip "kernel config is readable on this host"
    fi
    run "$KFEATURES_BIN" config
    assert_failure
    # Stderr is the structcli envelope, not a bare line. We check
    # the stable surface: a JSON object whose message starts with
    # the canonical "kernel config not available" prefix and which
    # carries the command name. The remediation suffix
    # ("tried /proc/config.gz, ...") is intentionally NOT asserted
    # so the wording can be improved without churning the test.
    assert_output --partial '"message":"kernel config not available'
    assert_output --partial '"command":"kfeatures config"'
}

@test "config --json: missing kernel config keeps stdout clean" {
    local rel
    rel="$(uname -r)"
    if [[ -r /proc/config.gz ]] \
        || [[ -r "/boot/config-${rel}" ]] \
        || [[ -r "/lib/modules/${rel}/config" ]]; then
        skip "kernel config is readable on this host"
    fi
    # Capture stdout and stderr separately so we can prove --json
    # no longer drops a half-baked payload on stdout: the failure
    # is reported only via the structcli envelope on stderr.
    local out_file err_file rc
    out_file="$(mktemp)"
    err_file="$(mktemp)"
    set +e
    "$KFEATURES_BIN" config --json >"$out_file" 2>"$err_file"
    rc=$?
    set -e
    [[ "$rc" -eq 1 ]]
    [[ ! -s "$out_file" ]]
    grep -q '"message":"kernel config not available' "$err_file"
    rm -f "$out_file" "$err_file"
}
