#!/usr/bin/env bats
# Non-Linux CLI tests — verify graceful degradation.

load helper

setup_file() {
    if [[ "$(uname -s)" == "Linux" ]]; then
        skip "these tests target non-Linux platforms"
    fi
    build_kfeatures
}

# --- graceful failures ---

@test "version: fails with platform error" {
    run "$KFEATURES_BIN" version
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "version: prints tool identity before failing" {
    run "$KFEATURES_BIN" version
    assert_failure
    assert_output --partial "kfeatures (dev)"
}

@test "probe: fails with platform error" {
    run "$KFEATURES_BIN" probe
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "probe --json: fails with platform error" {
    run "$KFEATURES_BIN" probe --json
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "config: fails with platform error" {
    run "$KFEATURES_BIN" config
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "config --json: fails with platform error" {
    run "$KFEATURES_BIN" config --json
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "check: fails with platform error" {
    run "$KFEATURES_BIN" check --require bpf-syscall
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "check --json: fails with platform error" {
    run "$KFEATURES_BIN" check --require bpf-syscall --json
    assert_failure
    assert_output --partial "probing requires Linux"
}

@test "check: mixed-case require parses before platform error" {
    run "$KFEATURES_BIN" check --require BPF-SYSCALL
    assert_failure
    assert_output --partial "probing requires Linux"
    refute_output --partial "invalid argument"
}
