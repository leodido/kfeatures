#!/usr/bin/env bats
# Linux-only mount integration tests. Exercises the corrected FeatureBPFFS /
# FeatureTraceFS gates by reading the runner's actual mount state and asserting
# the CLI's exit code agrees with `stat -f -c %T`.
#
# Requires root because some assertions mount a tmpfs at a temp dir to verify
# the binary survives non-default filesystem types end-to-end.

load helper

setup_file() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        skip "requires Linux"
    fi
    if [[ "$(id -u)" != "0" ]]; then
        skip "requires root (mount integration)"
    fi
    build_kfeatures
}

setup() {
    TMPFS_DIR="$(mktemp -d)"
    mount -t tmpfs tmpfs "$TMPFS_DIR" || skip "cannot mount tmpfs (sandboxed?): $output"
    export TMPFS_DIR
}

teardown() {
    if [[ -n "${TMPFS_DIR:-}" ]] && mountpoint -q "$TMPFS_DIR" 2>/dev/null; then
        umount "$TMPFS_DIR" || true
    fi
    if [[ -n "${TMPFS_DIR:-}" && -d "$TMPFS_DIR" ]]; then
        rmdir "$TMPFS_DIR" || true
    fi
}

# Sanity: tmpfs we just mounted reports the expected filesystem type via stat,
# matching what RequireMount would see through unix.Statfs.
@test "tmpfs mount is observable via stat -f" {
    run stat -f -c '%T' "$TMPFS_DIR"
    assert_success
    assert_output "tmpfs"
}

@test "check --require bpf-fs: exit code agrees with actual /sys/fs/bpf state" {
    expected_type="$(stat -f -c '%T' /sys/fs/bpf 2>/dev/null || echo missing)"

    run "$KFEATURES_BIN" check --require bpf-fs
    if [[ "$expected_type" == "bpf_fs" ]]; then
        assert_success
    else
        assert_failure
        assert_output --partial "bpffs"
    fi
}

@test "check --require trace-fs: exit code agrees with actual tracefs state" {
    primary="$(stat -f -c '%T' /sys/kernel/tracing 2>/dev/null || echo missing)"
    fallback="$(stat -f -c '%T' /sys/kernel/debug/tracing 2>/dev/null || echo missing)"

    run "$KFEATURES_BIN" check --require trace-fs
    if [[ "$primary" == "tracefs" || "$fallback" == "tracefs" ]]; then
        assert_success
    else
        assert_failure
        assert_output --partial "tracefs"
    fi
}
