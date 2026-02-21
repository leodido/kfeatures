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

@test "help: check require flag points to available features without duplication" {
    run "$KFEATURES_BIN" check --help
    assert_success
    assert_output --partial "Available features:"
    assert_output --partial "Required features (see available features above)"

    available_count="$(printf "%s\n" "$output" | grep -c '^Available features:$')"
    [[ "$available_count" -eq 1 ]]

    require_line="$(printf "%s\n" "$output" | grep -E '^[[:space:]]*-r, --require[[:space:]]+feature')"
    [[ -n "$require_line" ]]
    [[ "$require_line" != *"{"* ]]
    [[ "$require_line" != *"bpf-lsm"* ]]

    feature_token_count="$(printf "%s\n" "$output" | grep -o 'bpf-lsm' | wc -l | tr -d ' ')"
    [[ "$feature_token_count" -eq 1 ]]
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

@test "check: legacy alias is rejected" {
    run "$KFEATURES_BIN" check --require bpffs
    assert_failure
    assert_output --partial 'unknown feature: "bpffs"'
}
