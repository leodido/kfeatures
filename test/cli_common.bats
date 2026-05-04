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
    assert_output --partial "probe host"
    assert_output --partial "probe bpf"
}

@test "help: probe host leaf" {
    run "$KFEATURES_BIN" probe host --help
    assert_success
    assert_output --partial "Probe the running kernel"
}

@test "help: probe bpf leaf" {
    run "$KFEATURES_BIN" probe bpf --help
    assert_success
    assert_output --partial "Probe a compiled eBPF ELF object"
    assert_output --partial "--with-core"
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
    # Assert against the structured envelope's `got` field rather than a
    # JSON-escaped substring of `message`: `got` is the documented
    # contract, while `message` is structcli prose that may be reworded
    # without breaking semantics.
    echo "$output" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['error'] == 'invalid_flag_value', d
assert d['got'] == 'bpffs', d
assert d['flag'] == 'require', d
"
}

# --- structured errors (structcli WithFlagErrors + ExecuteOrExit) ---
#
# Invocation errors (bad/missing/unknown flags, unknown subcommands) are
# emitted as a single JSON line on stderr with a semantic exit code from
# the structcli exitcode package. These assertions lock the contract so
# downstream agents can rely on it.

@test "errors: missing required flag emits structured JSON with exit code 10" {
    run "$KFEATURES_BIN" check
    [[ "$status" -eq 10 ]]
    echo "$output" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['error'] == 'missing_required_flag', d
assert d['exit_code'] == 10, d
assert d['flag'] == 'require', d
assert d['command'] == 'kfeatures check', d
"
}

@test "errors: unknown flag emits structured JSON with exit code 12" {
    run "$KFEATURES_BIN" probe --bogus
    [[ "$status" -eq 12 ]]
    echo "$output" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['error'] == 'unknown_flag', d
assert d['exit_code'] == 12, d
assert d['flag'] == 'bogus', d
"
}

@test "errors: invalid flag value emits structured JSON with exit code 11" {
    run "$KFEATURES_BIN" check --require bpffs
    [[ "$status" -eq 11 ]]
    echo "$output" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['error'] == 'invalid_flag_value', d
assert d['exit_code'] == 11, d
assert d['flag'] == 'require', d
assert d['got'] == 'bpffs', d
"
}

@test "errors: unknown subcommand emits structured JSON with exit code 14" {
    run "$KFEATURES_BIN" wat
    [[ "$status" -eq 14 ]]
    echo "$output" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['error'] == 'unknown_command', d
assert d['exit_code'] == 14, d
assert d['got'] == 'wat', d
assert 'check' in d['available'], d
assert 'probe' in d['available'], d
"
}

@test "completion: check require suggests feature values" {
    run "$KFEATURES_BIN" __complete check --require ""
    assert_success
    assert_output --partial "bpf-lsm"
}

@test "completion: check require supports comma-separated values" {
    run "$KFEATURES_BIN" __complete check --require "BPF-SYSCALL,tr"
    assert_success
    assert_output --partial "BPF-SYSCALL,tracepoint"
    assert_output --partial "BPF-SYSCALL,trace-fs"
    refute_output --partial "BPF-SYSCALL,bpf-syscall"
}

# --- --jsonschema discovery ---

@test "jsonschema: root command emits valid schema" {
    run "$KFEATURES_BIN" --jsonschema
    assert_success
    assert_output --partial '"title": "kfeatures"'
    echo "$output" | python3 -c "import sys,json; json.load(sys.stdin)"
}

@test "jsonschema: subcommand emits per-command schema" {
    run "$KFEATURES_BIN" check --jsonschema
    assert_success
    assert_output --partial '"title": "kfeatures check"'
    assert_output --partial '"require"'
    echo "$output" | python3 -c "import sys,json; json.load(sys.stdin)"
}

@test "jsonschema=tree: root emits array covering subcommands" {
    run "$KFEATURES_BIN" --jsonschema=tree
    assert_success
    assert_output --partial '"title": "kfeatures"'
    assert_output --partial '"title": "kfeatures probe"'
    assert_output --partial '"title": "kfeatures check"'
    echo "$output" | python3 -c "import sys,json; assert isinstance(json.load(sys.stdin), list)"
}

@test "jsonschema: unknown value is rejected" {
    run "$KFEATURES_BIN" --jsonschema=xml
    assert_failure
    assert_output --partial "unknown --jsonschema value"
}
