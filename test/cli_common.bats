#!/usr/bin/env bats
# Cross-platform CLI tests (Linux + macOS).

load helper

setup_file() {
    build_kfeatures
}

# --- help ---

@test "help: root describes the tool" {
    run "$KFEATURES_BIN" --help
    assert_success
    assert_output --partial "kfeatures probes kernel capabilities"
}

@test "help: probe subcommand" {
    run "$KFEATURES_BIN" probe --help
    assert_success
    assert_output --partial "Probe all kernel features"
}

@test "help: check subcommand" {
    run "$KFEATURES_BIN" check --help
    assert_success
    assert_output --partial "Check that the kernel supports all required features"
}

@test "help: config subcommand" {
    run "$KFEATURES_BIN" config --help
    assert_success
    assert_output --partial "Display parsed kernel configuration"
}

@test "help: version subcommand" {
    run "$KFEATURES_BIN" version --help
    assert_success
    assert_output --partial "Show kernel and tool version"
}

# --- error UX ---

@test "errors do not print usage" {
    run "$KFEATURES_BIN" probe 2>&1
    # Whether it succeeds (Linux) or fails (macOS), usage must not appear.
    refute_output --partial "Usage:"
}
